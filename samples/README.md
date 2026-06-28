# Sample Corpus

Six **synthetic** messages used to exercise and regression-test the analyzer.
All of them are fabricated for this lab: no real payloads, no live attacker
infrastructure, and every domain/IP is fake or RFC-5737 documentation space.
The "malicious" attachment is a plain-text placeholder.

| File | Type | Demonstrates | Verdict |
|------|------|--------------|---------|
| `benign-newsletter.eml` | ✅ Legit | Aligned SPF/DKIM/DMARC, on-brand links | 🟢 Benign (0) |
| `benign-internal-it.eml` | ✅ Legit | Internal notice, no risky indicators | 🟢 Benign (0) |
| `phish-credential-harvest.eml` | ❌ Phish | Homoglyph sender `micros0ft.com` + link-text/href mismatch to `.ru` | 🔴 High (128) |
| `phish-invoice-malware.eml` | ❌ Phish | Double-extension attachment `Invoice_90871.pdf.iso` + invoice fraud | 🔴 High (119) |
| `phish-bec-ceo-wire.eml` | ❌ Phish | BEC/CEO wire fraud — clean auth, no links, Reply-To redirect | 🟠 Likely (46) |
| `phish-package-delivery.eml` | ❌ Phish | DHL impersonation, `bit.ly` shortener, punycode link, `.xyz` TLD | 🔴 High (121) |
| `phish-prize-scam.eml` | ❌ Phish | Random sender domain + 'you are a winner' + Unicode-obfuscated subject | 🔴 High (75) |

Regenerate the reports any time with:

```bash
python -m phishtriage batch samples -o reports
```

Want to add your own? Any `.eml` dropped here is automatically picked up by the
batch command and the test suite. If you add a labeled sample, also add it to the
`EXPECTED` map in `tests/test_phishtriage.py` to keep the regression suite honest.
