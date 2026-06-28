"""Unit + regression tests for phishtriage.

The sample-based tests double as *detection regression tests*: every committed
.eml must keep producing the expected verdict, so a rule change that breaks
coverage fails CI.
"""
import pathlib

import pytest

from phishtriage.auth import parse_auth_results
from phishtriage.domains import hostname_of, registered_domain, tld_of
from phishtriage.indicators import is_ip_literal, is_punycode, levenshtein, lookalike_brand
from phishtriage.parser import parse_email
from phishtriage.scoring import evaluate, load_rules, verdict_for

SAMPLES = pathlib.Path(__file__).resolve().parents[1] / "samples"
RULES = load_rules()


# --- domains ---------------------------------------------------------------
@pytest.mark.parametrize("value,expected", [
    ("https://micros0ft.com.account-verify.ru/login", "micros0ft.com.account-verify.ru"),
    ("https://bit.ly/3xRpQk9", "bit.ly"),
    ("user@Example.COM", "example.com"),
    ("HTTP://10.0.0.5:8080/x", "10.0.0.5"),
])
def test_hostname_of(value, expected):
    assert hostname_of(value) == expected


@pytest.mark.parametrize("value,expected", [
    ("a.b.example.co.uk", "example.co.uk"),
    ("mail.acmewidgets.com", "acmewidgets.com"),
    ("https://login.paypal.com/x", "paypal.com"),
])
def test_registered_domain(value, expected):
    assert registered_domain(value) == expected


def test_tld_of():
    assert tld_of("foo.billing-invoices.top") == "top"
    assert tld_of("x.co.uk") == "uk"


# --- auth ------------------------------------------------------------------
def test_auth_parsing():
    v = parse_auth_results("mx; spf=fail smtp.mailfrom=x.com; dkim=none; dmarc=fail header.from=x.com")
    assert (v.spf_state, v.dkim_state, v.dmarc_state) == ("fail", "none", "fail")
    ok = parse_auth_results("mx; spf=pass; dkim=pass; dmarc=pass")
    assert (ok.spf_state, ok.dkim_state, ok.dmarc_state) == ("pass", "pass", "pass")


# --- indicators ------------------------------------------------------------
def test_levenshtein():
    assert levenshtein("microsoft", "microsoft") == 0
    assert levenshtein("paypal", "paypa1") == 1  # pre-normalisation distance


def test_homoglyph_lookalike():
    assert lookalike_brand("micros0ft.com")[0] == "microsoft"
    assert lookalike_brand("paypa1.com")[0] == "paypal"
    assert lookalike_brand("microsoft.com") is None  # the real domain
    assert lookalike_brand("acmewidgets.com") is None


def test_ip_and_punycode():
    assert is_ip_literal("http://193.42.33.18/confirm")
    assert is_punycode("http://xn--dhltracking-1ub.xyz/track")
    assert not is_punycode("https://www.acmewidgets.com")


# --- verdict bands ---------------------------------------------------------
@pytest.mark.parametrize("score,verdict", [
    (0, "Benign"), (14, "Benign"), (15, "Suspicious"),
    (40, "Likely Phishing"), (75, "High-Confidence Phishing"),
])
def test_verdict_bands(score, verdict):
    assert verdict_for(score) == verdict


# --- parser ----------------------------------------------------------------
def test_parser_extracts_links_and_attachments():
    parsed = parse_email(SAMPLES / "phish-invoice-malware.eml")
    assert parsed.attachments and parsed.attachments[0].filename == "Invoice_90871.pdf.iso"
    assert parsed.attachments[0].extension == "iso"
    assert len(parsed.attachments[0].sha256) == 64

    harvest = parse_email(SAMPLES / "phish-credential-harvest.eml")
    hrefs = [link for link in harvest.links if link.source == "href"]
    assert any("account-verify.ru" in link.url for link in hrefs)


# --- end-to-end regression over the sample corpus --------------------------
EXPECTED = {
    "benign-newsletter.eml": ("Benign", 0, 0),
    "benign-internal-it.eml": ("Benign", 0, 0),
    "phish-bec-ceo-wire.eml": ("Likely Phishing", 40, 74),
    "phish-credential-harvest.eml": ("High-Confidence Phishing", 75, 999),
    "phish-invoice-malware.eml": ("High-Confidence Phishing", 75, 999),
    "phish-package-delivery.eml": ("High-Confidence Phishing", 75, 999),
    "phish-prize-scam.eml": ("High-Confidence Phishing", 75, 999),
}


@pytest.mark.parametrize("name,expected", EXPECTED.items())
def test_sample_corpus_verdicts(name, expected):
    verdict, lo, hi = expected
    result = evaluate(parse_email(SAMPLES / name), RULES)
    assert result.verdict == verdict, f"{name}: got {result.verdict} (score {result.score})"
    assert lo <= result.score <= hi


def test_specific_rules_fire():
    rules = {f.rule_id for f in evaluate(parse_email(SAMPLES / "phish-credential-harvest.eml"), RULES).findings}
    assert {"lookalike_sender_domain", "display_name_impersonation", "link_text_href_mismatch"} <= rules

    inv = {f.rule_id for f in evaluate(parse_email(SAMPLES / "phish-invoice-malware.eml"), RULES).findings}
    assert {"double_extension_attachment", "risky_attachment"} <= inv

    bec = {f.rule_id for f in evaluate(parse_email(SAMPLES / "phish-bec-ceo-wire.eml"), RULES).findings}
    assert "reply_to_mismatch" in bec

    prize = {f.rule_id for f in evaluate(parse_email(SAMPLES / "phish-prize-scam.eml"), RULES).findings}
    assert {"random_sender_domain", "reward_scam_language", "unicode_obfuscation"} <= prize


def test_benign_has_no_findings():
    result = evaluate(parse_email(SAMPLES / "benign-newsletter.eml"), RULES)
    assert result.findings == []
    assert result.score == 0


def test_every_finding_maps_to_a_rule():
    """Guard against typo'd rule IDs: every fired rule must exist in rules.yaml."""
    for name in EXPECTED:
        for f in evaluate(parse_email(SAMPLES / name), RULES).findings:
            assert f.rule_id in RULES


def test_random_domain_heuristic():
    from phishtriage.indicators import looks_random_domain
    assert looks_random_domain("b8o9w9hx5v.us")
    assert looks_random_domain("a7b3k9x2qz.us")
    assert not looks_random_domain("acmewidgets.com")
    assert not looks_random_domain("gmail.com")
    assert not looks_random_domain("corp.example.com")


def test_unicode_obfuscation_detection():
    from phishtriage.indicators import has_obfuscated_unicode
    assert has_obfuscated_unicode("You won a \U0001D40F\U0001D420\U0001D421")  # math-bold
    assert not has_obfuscated_unicode("Plain ASCII subject")
