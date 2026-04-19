# HTTPSmuggler Ultimate v1.0.0

> **HTTP Request Smuggling Detection & Verification Framework**
>
> A high-fidelity automated tool for identifying HTTP Request Smuggling vulnerabilities across frontend-backend architectures. Detects CL.TE, TE.CL, TE.TE, and CL.0 smuggling vectors using timing and differential response analysis.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Bash](https://img.shields.io/badge/Bash-5.0+-green)
![Platform](https://img.shields.io/badge/Platform-Linux%20|%20macOS%20|%20WSL-blue)

---

## 🎯 Overview

HTTPSmuggler Ultimate is an advanced reconnaissance tool designed to **automatically detect and verify HTTP Request Smuggling vulnerabilities** in web applications. It bridges the gap between vulnerability discovery and confirmation by:

- **Automating payload delivery** across 18+ smuggling attack vectors
- **Eliminating false positives** through multi-round verification (80% confidence threshold)
- **Measuring timing deltas** to detect backend hangs and desynchronization
- **Analyzing differential responses** to confirm successful header injection
- **Generating manual verification guides** for Burp Suite and manual testing
- **Bulk scanning** with parallel thread support

### What is HTTP Request Smuggling?

HTTP Request Smuggling (HRS) exploits ambiguity in how frontend proxies and backend servers parse HTTP requests—particularly the `Content-Length` and `Transfer-Encoding` headers. By crafting requests that different layers interpret differently, attackers can:

- **Bypass security controls** (firewalls, WAFs, authentication)
- **Poison shared connection pools** (affecting other users' requests)
- **Cache manipulation** (poisoning web caches with malicious content)
- **Credential theft** (capturing other users' cookies/tokens)

**Learn more:** [PortSwigger HTTP Request Smuggling Research](https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn)

---

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/mohidqx/HTTPsmuggle.git
cd HTTPsmuggle

# Make executable
chmod +x smuggler.sh

# Run a single scan
./smuggler.sh target.com

# Or use directly
bash smuggler.sh https://api.target.com:8443
```

### Prerequisites

- **Bash** 4.0+
- **OpenSSL** (for TLS connections)
- **curl** (optional, for auto-update checks)
- **netcat** or `/dev/tcp` (for non-TLS connections)

**Ubuntu/Debian:**
```bash
sudo apt update && sudo apt install -y openssl curl
```

**macOS:**
```bash
brew install openssl
```

---

## 📖 Usage

### Single Target Scan

```bash
# Default: HTTPS on port 443
./smuggler.sh target.com

# Explicit port
./smuggler.sh target.com:8080

# Full URL
./smuggler.sh https://api.example.com/v1
./smuggler.sh http://internal-app.local:80

# Custom path
./smuggler.sh -p /api/upload target.com

# With verbose output
./smuggler.sh -v target.com

# Generate manual verification guide
./smuggler.sh -g target.com

# JSON output
./smuggler.sh -j target.com

# All of the above
./smuggler.sh -v -g -j target.com
```

### Bulk Scanning

```bash
# Create targets file (one per line, # for comments)
cat > targets.txt << EOF
# Internal APIs
api.internal.com:8443
admin-panel.local

# External targets
target.example.com
api.partner.com:443
EOF

# Scan all targets
./smuggler.sh -f targets.txt

# Bulk scan with 5 parallel threads and JSON output
./smuggler.sh -f targets.txt -T 5 -j

# Quick mode (less thorough, faster)
./smuggler.sh -f targets.txt --quick -j
```

### Advanced Options

```bash
# List all 18 payloads and categories
./smuggler.sh --payloads

# Skip auto-update check
./smuggler.sh -u target.com

# Custom timing timeout (default: 13 seconds)
./smuggler.sh -t 20 target.com

# HTTP proxy for requests
./smuggler.sh --proxy 127.0.0.1:8080 target.com

# All options combined
./smuggler.sh \
  -f targets.txt \
  -p /api/upload \
  -t 15 \
  -T 10 \
  -v -j -g --proxy 127.0.0.1:8080
```

### Command-Line Reference

| Option | Argument | Default | Description |
|--------|----------|---------|-------------|
| `-h, --help` | — | — | Show help and exit |
| `--payloads` | — | — | List all available payloads |
| `-f` | `<file>` | — | Bulk mode: scan targets from file |
| `-p` | `<path>` | `/` | Custom request path |
| `-t` | `<seconds>` | `13` | Timing test timeout |
| `-T` | `<threads>` | `1` | Parallel threads for bulk mode |
| `--proxy` | `<host:port>` | — | HTTP proxy endpoint |
| `--quick` | — | `false` | Fast mode (2 rounds, 50% threshold) |
| `-v` | — | `false` | Verbose debug output |
| `-j` | — | `false` | Write JSON results to `smuggler_results.json` |
| `-g` | — | `false` | Generate manual verification guide |
| `-u` | — | `false` | Skip auto-update check |

---

## 🎯 Attack Vectors & Payloads

HTTPSmuggler tests **18 distinct attack vectors** across 4 primary categories:

### Category: CL.TE (Content-Length vs Transfer-Encoding)

Frontend interprets `Content-Length`, backend processes `Transfer-Encoding: chunked`.

| Payload | Strategy | Description |
|---------|----------|-------------|
| `CLTE-BASIC` | TIMING | Backend hangs waiting for chunked terminator that never arrives |
| `CLTE-GPOST` | DIFF | Prepends `G` to poison next request on shared connection |

**Remediation:** Ensure frontend and backend agree on header precedence; prefer Transfer-Encoding.

---

### Category: TE.CL (Transfer-Encoding vs Content-Length)

Frontend processes `Transfer-Encoding: chunked`, backend uses `Content-Length`.

| Payload | Strategy | Description |
|---------|----------|-------------|
| `TECL-BASIC` | TIMING | Backend waits for 100 bytes but only receives chunked terminator |
| `TECL-LARGE-CL` | TIMING | Larger CL (65535) creates longer hang window |
| `TECL-GPOST` | DIFF | Smuggles full `GPOST` request prefix |

**Remediation:** Validate that Content-Length matches actual body size; reject ambiguous headers.

---

### Category: TE.TE (Transfer-Encoding Obfuscation)

Both layers support TE, but differ in parsing of obfuscated variants:

| Payload | Strategy | Description |
|---------|----------|-------------|
| `TETE-IDENTITY` | TIMING | Duplicate TE headers with conflicting values |
| `TETE-XCHUNKED` | TIMING | Non-standard `xchunked` accepted by one layer |
| `TETE-SPACE-PREFIX` | TIMING | Leading space before `chunked` (RFC violation) |
| `TETE-TAB` | TIMING | Tab separator in TE header |
| `TETE-UPPERCASE` | TIMING | `CHUNKED` in uppercase (case-sensitive parsing) |
| `TETE-COLON-SPACE` | TIMING | Malformed header: space before colon |
| `TETE-COMMA-IDENTITY` | TIMING | List of TE values: `chunked,identity` |
| `TETE-INVALID-EXT` | TIMING | Extension parameter on TE: `chunked;ext=smuggler` |
| `TETE-FOLD` | TIMING | RFC 7230 header folding (deprecated, but parsed) |
| `TETE-METHOD-OVERRIDE` | TIMING | Combined with `X-HTTP-Method-Override` |
| `TETE-X-TE` | TIMING | Non-standard `X-Transfer-Encoding` header |

**Remediation:** Implement strict header parsing; reject invalid/obfuscated Transfer-Encoding variants.

---

### Category: CL.0 (Content-Length Zero)

Backend ignores request body for certain endpoint types (static files, GET requests):

| Payload | Strategy | Description |
|---------|----------|-------------|
| `CL0-POST` | DIFF | Backend treats POST body as ignored, smuggles next request |
| `CL0-GET` | DIFF | Some backends ignore body on GET requests |

**Remediation:** Never ignore request bodies; ensure body length matches Content-Length.

---

## 🔬 Detection Strategies

### TIMING Detection

Measures response time to identify backend hangs. A vulnerable backend waits indefinitely for data that never arrives (e.g., chunked terminator, additional bytes).

```
Normal request:     ~200-500 ms
Vulnerable (hangs): Timeout (13s) OR >7000ms delay
```

**Threshold:** If elapsed time exceeds baseline + 5 seconds OR > 7 seconds, backend is hanging.

### DIFFERENTIAL Detection

Sends a "poison" request to inject data into the connection pool, then immediately sends a "canary" request to detect if the injection succeeded.

```
[Poison Request]  → Smuggled bytes sit in connection buffer
                 ↓
[Canary Request]  → Receives response with garbled method/path
                 ↓
Result: 400 Bad Request OR 405 Method Not Allowed = VULNERABLE
```

---

## 📊 Output Formats

### Text Results (`smuggler_results.txt`)

```
# HTTPSmuggler Ultimate v1.0.0 Results
# Scan started: 2025-04-19T14:32:15Z
# Path tested: /
# Format: target | payload | category | strategy | timestamp
# ──────────────────────────────────────────────────────────
target.com:443 | CLTE-BASIC | CL.TE | TIMING | 2025-04-19T14:32:18Z
target.com:443 | TECL-GPOST | TE.CL | DIFF | 2025-04-19T14:32:45Z
api.target.com:8443 | TETE-SPACE-PREFIX | TE.TE | TIMING | 2025-04-19T14:33:02Z
```

### JSON Results (`smuggler_results.json`)

```json
{
  "tool": "HTTPSmuggler Ultimate v1.0.0",
  "github": "https://github.com/mohidqx/HTTPsmuggle",
  "scan_date": "2025-04-19T14:32:15Z",
  "elapsed_seconds": 147,
  "total_targets_scanned": 3,
  "total_vulnerabilities": 3,
  "path_tested": "/",
  "results": [
    {
      "target": "target.com:443",
      "payload_name": "CLTE-BASIC",
      "category": "CL.TE",
      "strategy": "TIMING",
      "description": "Classic CL.TE: frontend reads CL, backend expects more chunks"
    },
    {
      "target": "target.com:443",
      "payload_name": "TECL-GPOST",
      "category": "TE.CL",
      "strategy": "DIFF",
      "description": "TE.CL differential: smuggle GPOST prefix to poison next request"
    }
  ]
}
```

### Manual Verification Guide (`smuggler_manual_guide.md`)

Automatically generated Markdown with step-by-step instructions for reproducing findings in Burp Suite, including raw HTTP examples and Python Turbo Intruder scripts.

---

## 🛠️ Manual Verification Workflow

After HTTPSmuggler identifies a vulnerability, confirm it manually:

### In Burp Suite Repeater:

1. **Send POISON request** → Injected request sits in connection buffer
2. **Immediately send CANARY request** on new tab (separate connection)
3. **Inspect CANARY response** for unexpected behavior:
   - **400 Bad Request** → Smuggled data prepended to canary
   - **405 Method Not Allowed** → Injected method recognized
   - **Response mismatch** → Canary got different content than expected

### Example: CL.TE Differential

**Poison (Tab 1):**
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 6
Transfer-Encoding: chunked

0

G
```

**Canary (Tab 2, immediately after):**
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 12

x=value&y=test
```

**Vulnerable Response:** Canary receives `400 Bad Request` or sees its method mangled as `GPOST`.

---

## 📈 Confidence Scoring

HTTPSmuggler uses **multi-round verification** to eliminate false positives:

| Mode | Rounds | Threshold | Use Case |
|------|--------|-----------|----------|
| Default | 5 | 4/5 (80%) | Thorough, production scans |
| Quick | 2 | 1/2 (50%) | Initial reconnaissance |

**Verification rounds test the same payload multiple times.** If 4+ out of 5 rounds trigger the vulnerability, it's confirmed.

---

## ⚙️ Configuration & Tuning

### Timeout Parameters (in script header):

```bash
TIMEOUT_BASELINE=8       # Initial connectivity test
TIMEOUT_TIMING=13        # Timing attack window (must > normal response)
TIMEOUT_DIFF=7           # Differential canary test
VERIFY_ROUNDS=5          # Multi-round verification iterations
VERIFY_THRESHOLD=4       # Required positives for confirmation
```

### Adjust for slow networks:

```bash
# Edit script or pass via environment:
TIMEOUT_TIMING=30 ./smuggler.sh target.com
```

---

## 🔐 Security & Disclaimer

### ⚠️ AUTHORIZATION REQUIRED

**This tool is for authorized security testing ONLY.** Unauthorized scanning is illegal.

```
By using this tool, you:
- Confirm you have EXPLICIT written permission to scan each target
- Assume all liability for misuse, data loss, or unauthorized access
- Agree to comply with applicable laws (CFAA, GDPR, etc.)
```

### Best Practices:

1. **Get written authorization** before any scan
2. **Run on isolated/test environments** first
3. **Notify the target organization** of findings
4. **Use responsibly** to improve security, not exploit vulnerabilities
5. **Store results securely** (they contain sensitive target information)

---

## 🧪 Example Workflows

### Scenario 1: Single Target Quick Check

```bash
$ ./smuggler.sh -v api.example.com

[*] Checking for updates...
  
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
TARGET  api.example.com:443  [TLS:true]  [Path:/]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[baseline] Connecting... OK  (142ms)

▸ CL.TE
  CLTE-BASIC                   [T] SAFE
  CLTE-GPOST                   [D] SAFE

▸ TE.CL
  TECL-BASIC                   [T] Potential... verifying (5x)... VULNERABLE ✓
  TECL-LARGE-CL                [T] SAFE
  TECL-GPOST                   [D] SAFE
  
... (output continues)

⚑ VULNERABLE: api.example.com:443
  • TECL-BASIC  (TE.CL: backend uses CL=100, gets only chunked 0-terminator)

━━━━━━ SCAN COMPLETE ━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Targets scanned : 1
Vulnerabilities : 1
Elapsed         : 89s
Results file    : smuggler_results.txt
```

### Scenario 2: Bulk Scan with Manual Guide

```bash
# Create target list
cat > targets.txt << EOF
# Production APIs
api.prod.example.com:443

# Staging environments
api.staging.example.com
admin-api.staging:8443

# Partner integrations
third-party.api.com
EOF

# Run scan with guide generation
./smuggler.sh -f targets.txt -g -j

# Review JSON results
cat smuggler_results.json

# Manual verification steps
cat smuggler_manual_guide.md
```

### Scenario 3: Targeted Path Testing

```bash
# Test a specific endpoint that handles large uploads
./smuggler.sh -p /api/upload target.com

# Test admin panel with extended timeout (slow server)
./smuggler.sh -p /admin -t 30 target.com

# Test via HTTP proxy (local WAF/proxy setup)
./smuggler.sh --proxy 127.0.0.1:8080 target.com
```

---

## 🐛 Troubleshooting

### "cannot reach target, skipping"

**Cause:** Network unreachable or firewall blocking.

```bash
# Test manually
curl -v https://target.com/

# Check with openssl
openssl s_client -connect target.com:443 -servername target.com
```

**Solution:** Verify network access, check firewall rules, ensure correct port.

---

### "openssl not found"

**Cause:** TLS dependency missing.

```bash
# Ubuntu/Debian
sudo apt install openssl

# macOS
brew install openssl
```

---

### "connection timed out at baseline"

**Cause:** Target not responding within baseline timeout (8s).

```bash
# Increase timing timeout
./smuggler.sh -t 20 target.com

# Or check if target is actually online
ping target.com
curl -w "Response: %{http_code}\n" target.com
```

---

### "Update available" prompt blocks scan

**Cause:** Auto-update check finding a newer version.

```bash
# Skip update check
./smuggler.sh -u target.com

# Or answer 'n' to the prompt and continue
```

---

## 📚 References & Further Reading

### Academic Research:
- [PortSwigger: HTTP Desync Attacks](https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn)
- [PortSwigger: HTTP Request Smuggling](https://portswigger.net/web-security/request-smuggling)
- [PortSwigger: Browser-Powered Desync](https://portswigger.net/research/browser-powered-desync-attacks)

### Related Tools:
- [Burp Suite: HTTP Request Smuggler Extension](https://portswigger.net/bappstore/aaaa60ef945341e8a450217a54614e35)
- [h2cSmuggler: HTTP/2 Smuggling](https://github.com/neex/h2csmuggler)
- [smuggler.py: Albinowax's Original Tool](https://github.com/defparam/smuggler)

### RFC Standards:
- [RFC 7230: HTTP/1.1 Message Syntax & Routing](https://tools.ietf.org/html/rfc7230)
- [RFC 7231: HTTP/1.1 Semantics & Content](https://tools.ietf.org/html/rfc7231)
- [RFC 7540: HTTP/2](https://tools.ietf.org/html/rfc7540)

---

## 🛡️ Remediation Strategies

### For Developers & DevOps:

1. **Normalize requests** at proxy layer
   - Strip or normalize conflicting headers
   - Enforce single TE/CL precedence
   
2. **Strict parsing**
   - Reject requests with both CL and TE
   - Reject malformed headers (spaces, tabs, invalid chars)
   - Case-sensitive TE value validation

3. **HTTP/2 end-to-end**
   - Upgrade to HTTP/2 where possible
   - Reduces ambiguity in parsing

4. **WAF rules**
   - Block requests with both CL and TE headers
   - Block obfuscated Transfer-Encoding variants

5. **Upgrade dependencies**
   - Update proxies/balancers (nginx, HAProxy, etc.)
   - Update backend servers (Apache, IIS, etc.)

### Example nginx configuration:

```nginx
# Reject requests with both Content-Length and Transfer-Encoding
if ($http_transfer_encoding != "" && $content_length != "") {
    return 400;
}

# Normalize Transfer-Encoding to lowercase
map $http_transfer_encoding $te_value {
    ~*chunked "chunked";
    ~*identity "identity";
    default "invalid";
}

# Reject if not "chunked" or "identity"
if ($te_value = "invalid") {
    return 400;
}
```

---

## 📝 Contributing

Contributions are welcome! Please:

1. **Report bugs** via GitHub Issues
2. **Propose new payloads** (with proof of concept)
3. **Improve documentation**
4. **Enhance detection logic**

**Before submitting:**
- Test thoroughly on authorized targets only
- Follow existing code style
- Update README with new features
- Add comments for complex logic

---

## 📄 License

MIT License — See LICENSE file for details.

```
MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions...
```

---

## 👤 Author

**mohidqx** — Security Research & Automation  
GitHub: [@mohidqx](https://github.com/mohidqx)

---

## 🙏 Acknowledgments

- **PortSwigger Web Security Academy** — HTTP Request Smuggling research
- **James Kettle** — Original HRS research & Burp plugin development
- **Albinowax** — smuggler.py reference implementation
- **Community** — Bug reports, payload suggestions, and feedback

---

## ⚡ Quick Command Cheat Sheet

```bash
# Help & payload list
./smuggler.sh -h
./smuggler.sh --payloads

# Single target
./smuggler.sh target.com
./smuggler.sh -v -g -j target.com

# Bulk scanning
./smuggler.sh -f targets.txt -T 5 -j
./smuggler.sh -f targets.txt --quick

# Advanced
./smuggler.sh -p /api/upload target.com
./smuggler.sh -t 20 target.com
./smuggler.sh --proxy 127.0.0.1:8080 target.com

# Full power
./smuggler.sh \
  -f targets.txt \
  -p /api/upload \
  -t 20 \
  -T 10 \
  -v -j -g
```

---

**Last Updated:** April 2025  
**Version:** 1.0.0  
**Status:** Production Ready ✓
