# Setup & Usage

## Requirements

- Python 3.9 or newer
- One dependency: `PyYAML` (everything else is standard library)

## Install

```bash
git clone https://github.com/DMYourz/CyberSecurity-Portfolio.git
cd CyberSecurity-Portfolio/<path-to>/phishing-email-triage-analyzer

# Option A: proper install (gives you the `phishtriage` command)
pip install -e .

# Option B: zero-install, run from source
pip install pyyaml
python -m phishtriage --help
```

Dev extras (tests + linter + optional enrichment libraries):

```bash
pip install -e ".[dev,enrich]"
```

## Running it

### Analyze one message

```bash
python -m phishtriage analyze samples/phish-credential-harvest.eml
```

Prints a Markdown report to your terminal and the verdict to stderr. Add `-f json`
or `-f html`, and `-o <dir>` to write files instead of printing.

### Batch a folder

```bash
python -m phishtriage batch samples -o reports
```

Writes `<name>.report.md/.json/.html` for every `.eml`, plus a `SUMMARY.md`
leaderboard sorted by risk score.

### Optional online enrichment

Off by default so the tool stays offline and deterministic. With API keys present
it will light up; without them it cleanly no-ops:

```bash
export VT_API_KEY=...          # VirusTotal
export URLSCAN_API_KEY=...     # urlscan.io
export ABUSEIPDB_API_KEY=...   # AbuseIPDB
python -m phishtriage analyze suspicious.eml --enrich
```

## Running it from anywhere (Windows)

You don't need to `cd` into the project every time.

**Option A — global command.** After `pip install -e .` once, the `phishtriage`
command is on your PATH and works from any folder:

```powershell
phishtriage analyze "C:\Users\Daniel\Downloads\weird-email.eml"
phishtriage batch "C:\Users\Daniel\Downloads\suspicious-emails\" -o reports
```

**Option B — drag-and-drop.** Drag any `.eml` file onto **`scan.bat`** in the
project folder. It analyzes the file, writes reports, and opens the HTML report
in your browser. You can drag a whole folder too. (Works even without installing.)

**Option C — right-click "Send to".** Make `scan.bat` reachable from the right-click
menu: press `Win+R`, run `shell:sendto`, and drop a shortcut to `scan.bat` in there.
Now you can right-click any `.eml` → **Send to → Phishing Scanner**.

## Reading the verdict

| Score | Verdict | What to do |
|-------|---------|------------|
| 0–14 | 🟢 Benign | Deliver; keep for baseline tuning |
| 15–39 | 🟡 Suspicious | Review; confirm sender out-of-band |
| 40–74 | 🟠 Likely Phishing | Quarantine, warn recipient, hunt for copies |
| 75+ | 🔴 High-Confidence Phishing | Block, purge from mailboxes, open an incident |

Each report lists exactly which rules fired, their weights, and the MITRE ATT&CK
technique — so you can see the reasoning, not just the number. See
[DETECTIONS.md](DETECTIONS.md) for the full rule reference.

## Using your own emails

In most mail clients, "Save As" or "Show original → download" gives you a `.eml`.
Drop it anywhere and point the tool at it. Keep real evidence out of the repo —
`.gitignore` already excludes `*.local.eml` and `private-samples/`.
