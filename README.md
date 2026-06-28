# Phishing Email Triage Analyzer

[![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/tests-30%20passing-brightgreen.svg)](tests/)
[![Detections](https://img.shields.io/badge/detections-25%20rules-orange.svg)](docs/DETECTIONS.md)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-mapped-red.svg)](https://attack.mitre.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

> Drop in a raw `.eml`, get back an analyst-ready verdict in under a second. Because manually eyeballing email headers at 2am is nobody's idea of a good time.

---

## 📖 Overview

This is a Python tool that automates the boring-but-critical first pass of phishing triage — the stuff a Tier-1 SOC analyst does dozens of times a day. Feed it a suspicious email and it parses the headers, checks sender authentication, hunts for look-alike domains and link trickery, sniffs out dangerous attachments, reads the social-engineering tells, and spits out a scored report mapped to MITRE ATT&CK.

It's **offline by default** — no message content ever leaves your machine, every result is deterministic, and there are no API keys to fumble with. Online reputation lookups are strictly opt-in.

I built this because "phishing triage" shows up on basically every SOC analyst job description, and I wanted something that proved I understand *why* an email is malicious, not just that a vendor box said so.

**What it flags (and why it matters):**

- **Spoofed senders** — SPF/DKIM/DMARC failures, Return-Path and Reply-To that don't line up with the From domain
- **Look-alike domains** — homoglyphs (`micros0ft.com`), typosquats, punycode/IDN, and brand impersonation in the display name
- **Link manipulation** — the visible text says `paypal.com` but the href goes to `account-verify[.]ru`, URL shorteners, raw-IP links, abuse-prone TLDs
- **Dangerous attachments** — executables, double extensions (`Invoice.pdf.iso`), macro-enabled Office docs, HTML smuggling
- **Social engineering** — urgency/pressure language and payment/wire/gift-card requests (the heart of BEC)

---

## 🏗️ How it works

```
                 ┌──────────────────────────────────────────────────┐
   raw .eml ───► │  parser.py   RFC-822 headers · MIME bodies ·      │
                 │              links (href + anchor text) ·         │
                 │              attachments (+ SHA-256)              │
                 └───────────────────────┬──────────────────────────┘
                                         │  ParsedEmail
                 ┌───────────────────────▼──────────────────────────┐
                 │  analyzers                                        │
                 │   auth.py        SPF / DKIM / DMARC               │
                 │   domains.py     eTLD+1 / registrable domain      │
                 │   indicators.py  homoglyphs · typosquats ·        │
                 │                  shorteners · punycode · TLDs     │
                 └───────────────────────┬──────────────────────────┘
                                         │  signals
                 ┌───────────────────────▼──────────────────────────┐
                 │  scoring.py  ◄───  rules.yaml  (weights + ATT&CK) │
                 │              weighted score ─► verdict band        │
                 └───────────────────────┬──────────────────────────┘
                                         │  Result
                 ┌───────────────────────▼──────────────────────────┐
                 │  report.py     Markdown · JSON · standalone HTML  │
                 └──────────────────────────────────────────────────┘
```

The detection logic is **rules-as-data**: weights, severities, and ATT&CK technique IDs live in [`rules.yaml`](phishtriage/rules.yaml), so tuning the analyzer is a config edit, not a code change. See [docs/DETECTIONS.md](docs/DETECTIONS.md) for the full rule set.

---

## 📊 Sample results

Six messages ship with the repo — two legitimate, four malicious across different attack styles. Running `python -m phishtriage batch samples` produces:

| Sample | Score | Verdict | Technique demonstrated |
|--------|:-----:|---------|------------------------|
| `phish-credential-harvest.eml` | 128 | 🔴 High-Confidence Phishing | Homoglyph domain + link mismatch (M365 cred harvest) |
| `phish-package-delivery.eml` | 121 | 🔴 High-Confidence Phishing | Shortener + punycode + brand impersonation |
| `phish-invoice-malware.eml` | 119 | 🔴 High-Confidence Phishing | Double-extension `.pdf.iso` attachment |
| `phish-prize-scam.eml` | 75 | 🔴 High-Confidence Phishing | Random sender domain + reward-scam + Unicode obfuscation |
| `phish-bec-ceo-wire.eml` | 46 | 🟠 Likely Phishing | BEC wire fraud (no links, clean auth) |
| `benign-internal-it.eml` | 0 | 🟢 Benign | Legitimate internal notice |
| `benign-newsletter.eml` | 0 | 🟢 Benign | Legitimate marketing email |

**2/2 benign messages scored 0 (no false positives); 5/5 phishing messages flagged** — including a BEC email that passes SPF/DKIM/DMARC and carries no links or attachments. Full write-up in [docs/FINDINGS.md](docs/FINDINGS.md).

---

## 🚀 Quick start

```bash
# 1. Install (one dependency: PyYAML)
pip install -e .

# 2. Analyze a single message, print the report to your terminal
python -m phishtriage analyze samples/phish-credential-harvest.eml

# 3. Or batch the whole folder and write Markdown + JSON + HTML reports
python -m phishtriage batch samples -o reports
```

No install needed to kick the tires — `pip install pyyaml` and `python -m phishtriage ...` works straight from the repo. Full instructions in [docs/SETUP.md](docs/SETUP.md).

### Run it from anywhere (Windows)

You don't have to be inside this folder. Three options:

```powershell
# A) Global command - after `pip install -e .` once, run from ANY folder:
phishtriage analyze "C:\Users\Daniel\Downloads\weird-email.eml"

# B) Drag-and-drop - just drag any .eml file onto scan.bat.
#    It analyzes the file and pops open the HTML report automatically.

# C) Right-click "Send to" - put a shortcut to scan.bat in your SendTo folder
#    (run `shell:sendto`), then right-click any .eml -> Send to -> Phishing Scanner.
```

`scan.bat` also accepts a whole folder (it batches every `.eml` inside) and works
without installing, since it runs the tool from its own location.

### Usage

```bash
# Single file, choose your output format
python -m phishtriage analyze suspicious.eml                 # Markdown to stdout
python -m phishtriage analyze suspicious.eml -f json         # JSON to stdout
python -m phishtriage analyze suspicious.eml -f all -o out/  # write md+json+html

# Batch a directory (writes a SUMMARY.md too)
python -m phishtriage batch /path/to/eml/ -o reports

# Optional online reputation enrichment (needs API keys; off by default)
VT_API_KEY=... python -m phishtriage analyze suspicious.eml --enrich
```

---

## 📂 Repository structure

```
phishing-email-triage-analyzer/
├── phishtriage/
│   ├── parser.py        # .eml -> headers, bodies, links, attachments (+SHA-256)
│   ├── auth.py          # SPF / DKIM / DMARC from Authentication-Results
│   ├── domains.py       # registrable-domain (eTLD+1) extraction, no deps
│   ├── indicators.py    # homoglyphs, typosquats, shorteners, punycode, TLDs
│   ├── scoring.py       # weighted detection engine -> verdict
│   ├── report.py        # Markdown / JSON / HTML renderers
│   ├── enrichment.py    # optional, opt-in online reputation lookups
│   ├── cli.py           # `analyze` and `batch` commands
│   └── rules.yaml       # 22 detection rules: weight + severity + ATT&CK
├── samples/             # 7 synthetic .eml files (2 benign, 5 phishing)
├── reports/             # generated triage reports (committed as evidence)
├── tests/               # 30 pytest tests incl. detection regression suite
├── docs/
│   ├── SETUP.md         # install + usage + interpreting results
│   ├── DETECTIONS.md    # every rule, weight, and ATT&CK mapping
│   └── FINDINGS.md      # the lab results write-up
├── scan.bat · scan.ps1  # drag-and-drop launchers (run from anywhere)
├── .github/workflows/ci.yml   # tests + lint on every push (Py 3.9–3.12)
├── pyproject.toml · Makefile · LICENSE · .gitignore
```

---

## 🧪 Testing

```bash
pip install -e ".[dev]"
pytest -q          # 30 tests
ruff check .       # lint
```

The suite isn't just unit tests — the sample corpus is wired up as a **detection regression test**: if a rule change stops catching one of the known-phishing samples (or starts flagging a benign one), CI goes red. That's the same idea as true/false-positive testing in real detection engineering. GitHub Actions runs it across Python 3.9–3.12 on every push.

---

## 🛡️ MITRE ATT&CK coverage

Findings map to techniques across the phishing kill chain, including:

| Technique | ID | Where it shows up |
|-----------|----|--------------------|
| Phishing | T1566 | Auth failures, urgency language |
| Spearphishing Attachment | T1566.001 | Executable / macro / archive attachments |
| Spearphishing Link | T1566.002 | Link-text/href mismatch, shorteners, raw-IP links |
| Phishing for Information | T1598.003 | Credential-harvesting language + link |
| Impersonation | T1656 | Display-name spoofing, Reply-To redirect, BEC |
| Acquire Infrastructure: Domains | T1583.001 | Look-alike / abuse-TLD sender domains |
| Masquerading | T1036 / T1036.007 | Punycode/IDN, double file extensions |
| User Execution: Malicious File | T1204.002 | Macro-enabled Office docs |

---

## ⚠️ Ethical & safe-use note

Everything in `samples/` is **synthetic** — I wrote these messages for the lab. The "malicious" attachment is a harmless text placeholder, not real malware, and every domain/IP is fake or RFC-5737 documentation space. Nothing here detonates payloads or contacts attacker infrastructure.

If you point this at real suspicious mail: do it on messages you're authorized to investigate, keep private evidence out of the repo (`.gitignore` already excludes `*.local.eml` and `private-samples/`), and remember that static triage is the *first* filter, not a verdict you should block production traffic on without enrichment.

---

## 📄 License

MIT — see [LICENSE](LICENSE). Built as part of my [CyberSecurity Portfolio](https://github.com/DMYourz/CyberSecurity-Portfolio).
