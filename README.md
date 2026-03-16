# AresProbe v3

**AresProbe v3** is a comprehensive automated web assessment tool designed for **security research and authorized penetration testing**.

It orchestrates multiple industry‑standard tools to perform reconnaissance, vulnerability scanning, and authentication mechanism analysis.

---

## Features

* Origin IP discovery (CDN/WAF bypass reconnaissance)
* Recursive directory & file enumeration
* Automated vulnerability scanning
* SQL injection assessment
* Login form detection and authentication flow analysis
* Workspace‑based evidence collection
* Structured JSON findings output
* Progress monitoring and logging

---

## Tools Integrated

AresProbe integrates several well‑known security tools:

* ffuf – directory and file fuzzing
* sqlmap – SQL injection testing
* nuclei – vulnerability scanning
* nmap – network discovery

These tools must be installed on the system before running AresProbe.

---

## Requirements

* Python 3.9+
* Linux environment (tested on Debian/Kali)

Required external tools:

```
nmap
ffuf
sqlmap
nuclei
dirsearch
gobuster
git
```

Python dependencies:

```
requests
beautifulsoup4
lxml
rich
```

---

## Installation

Clone the repository:

```
git clone https://github.com/yourusername/AresProbe.git
cd AresProbe
```

Install Python dependencies:

```
pip install -r requirements.txt
```

---

## Usage

Run the tool:

```
python3 aresprobe.py
```

You will be prompted for:

```
Target URL
Proxy (optional)
```

Results are stored inside a workspace folder:

```
ARES_SCAN_<domain>_<timestamp>/
```

This folder contains:

```
evidence/
tools/
findings.json
aresprobe.log
```

---

## Output

AresProbe generates:

* JSON findings report
* raw scan results from integrated tools
* detailed log file
* authentication mechanism analysis

---

## Legal Notice

This tool is intended **only for authorized security testing and educational purposes**.

Do **NOT** use AresProbe against systems you do not own or do not have explicit permission to test.

Unauthorized scanning or exploitation may violate computer misuse laws.

The author assumes **no responsibility for misuse** of this software.

---

## Disclaimer

AresProbe is a research tool and may produce false positives or incomplete results.
Always verify findings manually.


