# Detection Logic & Scoring

This analyzer is **rules-as-data**: every signal lives in [`phishtriage/rules.yaml`](../phishtriage/rules.yaml) with a weight, severity, and MITRE ATT&CK technique. The engine in `scoring.py` fires a rule, sums the weights, and maps the total to a verdict band. Tuning is a YAML edit, not a code change.

## Scoring bands

| Score | Verdict | Analyst action |
|-------|---------|----------------|
| 0-14 | 🟢 Benign | Deliver; retain for baseline tuning |
| 15-39 | 🟡 Suspicious | Review; banner/confirm sender out-of-band |
| 40-74 | 🟠 Likely Phishing | Quarantine, warn recipient, hunt for copies |
| 75+ | 🔴 High-Confidence Phishing | Block, purge from mailboxes, open an incident |

## Detection rules (25)

| Rule | Severity | Weight | ATT&CK | What it catches |
|------|----------|:------:|:------:|-----------------|
| `lookalike_sender_domain` | 🔴 High | 25 | T1583.001 | Sender domain is a homoglyph/typosquat of a known brand domain. |
| `risky_attachment` | 🔴 High | 25 | T1566.001 | Executable or otherwise dangerous attachment file type. |
| `double_extension_attachment` | 🔴 High | 25 | T1036.007 | Attachment uses a double extension to disguise an executable. |
| `display_name_impersonation` | 🔴 High | 22 | T1656 | Display name impersonates a known brand the sender domain doesn't own. |
| `random_sender_domain` | 🔴 High | 22 | T1583.001 | Sender domain looks algorithmically generated (throwaway/snowshoe). |
| `dmarc_fail` | 🔴 High | 20 | T1566 | DMARC failed: message not aligned/authenticated for the From domain. |
| `link_text_href_mismatch` | 🔴 High | 20 | T1566.002 | Visible link text implies a different domain than the actual href. |
| `punycode_url` | 🔴 High | 20 | T1036 | Link uses punycode/IDN, a common homoglyph masquerading trick. |
| `macro_office_attachment` | 🔴 High | 20 | T1204.002 | Macro-enabled Office document (common malware delivery vector). |
| `reply_to_mismatch` | 🔴 High | 18 | T1656 | Reply-To redirects replies to a different domain than From (BEC tell). |
| `ip_literal_url` | 🔴 High | 18 | T1566.002 | Link points directly to a raw IP address instead of a domain. |
| `credential_keywords_with_link` | 🔴 High | 18 | T1598.003 | Account/credential-verification language paired with an outbound link. |
| `spf_fail` | 🟠 Medium | 15 | T1566 | SPF failed: sending IP not authorised for the envelope domain. |
| `reward_scam_language` | 🟠 Medium | 15 | T1566 | Prize/lottery/reward-scam language ('you are a winner', 'claim your prize'). |
| `suspicious_sender_tld` | 🟠 Medium | 14 | T1583.001 | Sender domain uses a low-reputation / abuse-prone TLD. |
| `unicode_obfuscation` | 🟠 Medium | 14 | T1036 | Subject/sender uses look-alike Unicode (math-bold/full-width) to evade filters. |
| `dkim_fail` | 🟠 Medium | 12 | T1566 | DKIM failed: message signature missing or invalid. |
| `return_path_mismatch` | 🟠 Medium | 12 | T1656 | Return-Path domain does not align with the From domain. |
| `url_shortener` | 🟠 Medium | 12 | T1566.002 | Link uses a URL shortener, concealing the true destination. |
| `financial_request_language` | 🟠 Medium | 12 | T1656 | Payment/wire/gift-card request language (invoice fraud / BEC). |
| `html_attachment` | 🟠 Medium | 12 | T1027.006 | HTML attachment (possible HTML smuggling or local credential page). |
| `suspicious_url_tld` | 🟡 Low | 10 | T1566.002 | Link uses a low-reputation / abuse-prone TLD. |
| `freemail_sender` | 🟡 Low | 8 | T1566 | Sender uses a free webmail provider (context for impersonation). |
| `urgency_language` | 🟡 Low | 8 | T1566 | Urgency / pressure language to provoke a hasty action. |
| `archive_attachment` | 🟡 Low | 8 | T1566.001 | Archive attachment that may conceal an executable payload. |

## Design notes

- **Offline-first.** No rule requires a network call, so results are deterministic and reproducible in CI. Live reputation enrichment is opt-in (`--enrich`).
- **Defense in depth.** No single signal convicts a message; authentication, identity, links, attachments, and language each contribute. A clean-authenticating BEC email with no links can still be flagged, and a 'you won a prize' scam from a throwaway domain stacks multiple weak signals into a high-confidence verdict.
- **Tuned against real mail.** Weights were calibrated so the benign corpus scores 0 while real-world spam/phishing lands 75+. The `random_sender_domain`, `reward_scam_language`, and `unicode_obfuscation` rules were added after testing against an actual phishing sample.
