# Lab Results - Sample Corpus Triage

All messages below were generated for this lab (synthetic, safe, no real payloads) and analyzed with `python -m phishtriage batch samples -o reports`. Full per-message reports (Markdown/JSON/HTML) are in [`../reports/`](../reports).

## Summary

| Sample | Score | Verdict | Findings | SPF/DKIM/DMARC |
|--------|:-----:|---------|:--------:|----------------|
| `phish-credential-harvest.eml` | 128 | 🔴 High-Confidence Phishing | 7 | fail/none/fail |
| `phish-package-delivery.eml` | 121 | 🔴 High-Confidence Phishing | 8 | fail/none/fail |
| `phish-invoice-malware.eml` | 119 | 🔴 High-Confidence Phishing | 7 | softfail/none/fail |
| `phish-prize-scam.eml` | 75 | 🔴 High-Confidence Phishing | 5 | pass/none/none |
| `phish-bec-ceo-wire.eml` | 46 | 🟠 Likely Phishing | 4 | pass/pass/pass |
| `benign-internal-it.eml` | 0 | 🟢 Benign | 0 | pass/pass/pass |
| `benign-newsletter.eml` | 0 | 🟢 Benign | 0 | pass/pass/pass |

> **2/2 benign messages scored 0** (no false positives) and **5/5 phishing messages were flagged**, including a clean-authenticating BEC email and a Unicode-obfuscated prize scam.

## Per-sample breakdown

### 🔴 `phish-credential-harvest.eml` - High-Confidence Phishing (score 128)

Microsoft 365 credential-harvesting lure. Sender `micros0ft.com` is a homoglyph of `microsoft.com`; the link text reads `login.microsoftonline.com` while the href points to `account-verify[.]ru`.

| Rule | Wt | ATT&CK | Detail |
|------|:--:|:------:|--------|
| `lookalike_sender_domain` | 25 | T1583.001 | Sender domain micros0ft.com resembles 'microsoft' (edit distance 0) |
| `display_name_impersonation` | 22 | T1656 | Display name 'Microsoft Account Team' cites 'microsoft', but sender domain is micros0ft.com |
| `dmarc_fail` | 20 | T1566 | Authentication-Results reports dmarc=fail |
| `link_text_href_mismatch` | 20 | T1566.002 | Link text implies ['live.com', 'microsoft.com', 'microsoftonline.com', 'office.com', 'office… |
| `credential_keywords_with_link` | 18 | T1598.003 | Credential/account-verification language paired with an outbound link |
| `spf_fail` | 15 | T1566 | Authentication-Results reports spf=fail |
| `urgency_language` | 8 | T1566 | Urgency / pressure language detected in the message body |

**ATT&CK techniques:** T1566, T1566.002, T1583.001, T1598.003, T1656

### 🔴 `phish-package-delivery.eml` - High-Confidence Phishing (score 121)

DHL package-delivery lure: brand impersonation from a `.xyz` throwaway, a `bit.ly` shortener, and a punycode/IDN link.

| Rule | Wt | ATT&CK | Detail |
|------|:--:|:------:|--------|
| `display_name_impersonation` | 22 | T1656 | Display name 'DHL Express' cites 'dhl', but sender domain is dhl-tracking-update.xyz |
| `dmarc_fail` | 20 | T1566 | Authentication-Results reports dmarc=fail |
| `punycode_url` | 20 | T1036 | Punycode/IDN link (possible homoglyph): http://xn--dhltracking-1ub.xyz/confirm |
| `spf_fail` | 15 | T1566 | Authentication-Results reports spf=fail |
| `suspicious_sender_tld` | 14 | T1583.001 | Sender domain uses low-reputation TLD .xyz |
| `url_shortener` | 12 | T1566.002 | Shortened link hides its destination: https://bit.ly/3xRpQk9 |
| `suspicious_url_tld` | 10 | T1566.002 | Link uses low-reputation TLD .xyz: http://xn--dhltracking-1ub.xyz/confirm |
| `urgency_language` | 8 | T1566 | Urgency / pressure language detected in the message body |

**ATT&CK techniques:** T1036, T1566, T1566.002, T1583.001, T1656

### 🔴 `phish-invoice-malware.eml` - High-Confidence Phishing (score 119)

Invoice/payment-fraud lure delivering `Invoice_90871.pdf.iso` - a double extension hiding a disk-image payload (ISO smuggling that bypasses Mark-of-the-Web).

| Rule | Wt | ATT&CK | Detail |
|------|:--:|:------:|--------|
| `double_extension_attachment` | 25 | T1036.007 | Double-extension attachment: Invoice_90871.pdf.iso |
| `risky_attachment` | 25 | T1566.001 | Executable/risky attachment: Invoice_90871.pdf.iso (application/octet-stream) |
| `dmarc_fail` | 20 | T1566 | Authentication-Results reports dmarc=fail |
| `spf_fail` | 15 | T1566 | Authentication-Results reports spf=softfail |
| `suspicious_sender_tld` | 14 | T1583.001 | Sender domain uses low-reputation TLD .top |
| `financial_request_language` | 12 | T1656 | Payment/wire/invoice request language detected |
| `urgency_language` | 8 | T1566 | Urgency / pressure language detected in the message body |

**ATT&CK techniques:** T1036.007, T1566, T1566.001, T1583.001, T1656

### 🔴 `phish-prize-scam.eml` - High-Confidence Phishing (score 75)

Prize/reward scam modeled on a real sample. Algorithmically-generated sender domain, reward-scam language ('you are a winner'), and Unicode-obfuscated subject (math-bold letters) to dodge keyword filters.

| Rule | Wt | ATT&CK | Detail |
|------|:--:|:------:|--------|
| `random_sender_domain` | 22 | T1583.001 | Sender domain a7b3k9x2qz.us looks algorithmically generated |
| `reward_scam_language` | 15 | T1566 | Prize/lottery/reward-scam language detected |
| `unicode_obfuscation` | 14 | T1036 | Look-alike Unicode characters used in subject/sender to evade filters |
| `return_path_mismatch` | 12 | T1656 | Return-Path domain 9xk2tp.com != From domain a7b3k9x2qz.us |
| `url_shortener` | 12 | T1566.002 | Shortened link hides its destination: https://tinyurl.com/abc123xyz |

**ATT&CK techniques:** T1036, T1566, T1566.002, T1583.001, T1656

### 🟠 `phish-bec-ceo-wire.eml` - Likely Phishing (score 46)

Business Email Compromise / CEO wire fraud - the hardest class to catch: authenticates cleanly (real Gmail), no links or attachments, caught on the Reply-To redirect plus financial-request language.

| Rule | Wt | ATT&CK | Detail |
|------|:--:|:------:|--------|
| `reply_to_mismatch` | 18 | T1656 | Reply-To accounting@secure-payments-portal.com (secure-payments-portal.com) differs from Fro… |
| `financial_request_language` | 12 | T1656 | Payment/wire/invoice request language detected |
| `freemail_sender` | 8 | T1566 | Sender uses free webmail domain gmail.com |
| `urgency_language` | 8 | T1566 | Urgency / pressure language detected in the message body |

**ATT&CK techniques:** T1566, T1656

### 🟢 `benign-internal-it.eml` - Benign (score 0)

Legitimate internal IT notice - fully aligned, no risky indicators.

_No suspicious indicators - clean._

### 🟢 `benign-newsletter.eml` - Benign (score 0)

Legitimate marketing newsletter - passes SPF/DKIM/DMARC, aligned domains, on-brand links.

_No suspicious indicators - clean._
