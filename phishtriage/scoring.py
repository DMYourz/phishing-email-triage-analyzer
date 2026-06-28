"""Weighted detection engine: ParsedEmail -> findings, score, verdict."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

import yaml

from . import indicators as ind
from .auth import AuthVerdict, parse_auth_results
from .domains import registered_domain, tld_of
from .parser import ParsedEmail

RULES_PATH = Path(__file__).with_name("rules.yaml")

CREDENTIAL_KEYWORDS = [
    "password", "sign in", "sign-in", "log in", "login", "verify your account",
    "verify your identity", "confirm your account", "confirm your identity",
    "account suspend", "unusual sign-in", "unusual activity", "suspicious activity",
    "reset your password", "validate your account", "update your payment",
    "re-activate", "reactivate", "verify now", "confirm your password",
]
URGENCY_KEYWORDS = [
    "urgent", "immediately", "action required", "within 24 hours", "within 24hrs",
    "as soon as possible", "final notice", "last warning", "will be suspended",
    "will be deactivated", "will be closed", "on hold", "failure to", "expires today",
    "act now", "time-sensitive", "overdue", "immediate attention", "immediate payment",
]
FINANCIAL_KEYWORDS = [
    "wire transfer", "wire the", "bank transfer", "gift card", "invoice", "past due",
    "overdue", "remittance", "purchase order", "bank details", "account number",
    "routing number", "bitcoin", "beneficiary", "swift code", "outstanding balance",
    "payment is", "make a payment", "process the payment",
]
REWARD_SCAM_KEYWORDS = [
    "you are a winner", "you're a winner", "you have won", "you've won",
    "congratulations you", "claim your prize", "claim your reward", "claim now",
    "you have been selected", "you have been chosen", "your reward is waiting",
    "gift card is waiting", "redeem your", "winner of a", "you have won a",
    "2nd attempt", "final attempt", "exclusive reward", "you qualify for",
]

VERDICT_BANDS = [
    (75, "High-Confidence Phishing"),
    (40, "Likely Phishing"),
    (15, "Suspicious"),
    (0, "Benign"),
]


@dataclass
class Finding:
    rule_id: str
    detail: str
    weight: int
    severity: str
    attack: str
    description: str


@dataclass
class Result:
    path: str
    score: int
    verdict: str
    findings: List[Finding]
    auth: AuthVerdict
    summary: dict = field(default_factory=dict)


def load_rules(path: Optional[str] = None) -> dict:
    with open(path or RULES_PATH, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def verdict_for(score: int) -> str:
    for threshold, label in VERDICT_BANDS:
        if score >= threshold:
            return label
    return "Benign"


def _contains_any(text: str, needles: list[str]) -> bool:
    return any(n in text for n in needles)


def evaluate(parsed: ParsedEmail, rules: Optional[dict] = None) -> Result:
    rules = rules or load_rules()
    auth = parse_auth_results(parsed.auth_results)
    findings: list[Finding] = []

    def add(rule_id: str, detail: str) -> None:
        meta = rules[rule_id]
        findings.append(
            Finding(
                rule_id=rule_id,
                detail=detail,
                weight=int(meta["weight"]),
                severity=str(meta.get("severity", "medium")),
                attack=str(meta.get("attack", "-")),
                description=str(meta.get("description", "")),
            )
        )

    from_reg = registered_domain(parsed.from_addr)
    known_good = set(ind.FREEMAIL)
    for legit in ind.BRAND_DOMAINS.values():
        known_good |= legit

    # --- Authentication ---------------------------------------------------
    if auth.spf_state == "fail":
        add("spf_fail", f"Authentication-Results reports spf={auth.spf}")
    if auth.dkim_state == "fail":
        add("dkim_fail", f"Authentication-Results reports dkim={auth.dkim}")
    if auth.dmarc_state == "fail":
        add("dmarc_fail", f"Authentication-Results reports dmarc={auth.dmarc}")
    if parsed.return_path and from_reg:
        rp = registered_domain(parsed.return_path)
        if rp and rp != from_reg:
            add("return_path_mismatch", f"Return-Path domain {rp} != From domain {from_reg}")
    for rt in parsed.reply_to:
        rt_reg = registered_domain(rt)
        if from_reg and rt_reg and rt_reg != from_reg:
            add("reply_to_mismatch", f"Reply-To {rt} ({rt_reg}) differs from From domain {from_reg}")
            break

    # --- Sender identity --------------------------------------------------
    for brand in ind.brands_in_text(parsed.from_display):
        if from_reg not in ind.BRAND_DOMAINS[brand]:
            add(
                "display_name_impersonation",
                f"Display name '{parsed.from_display}' cites '{brand}', "
                f"but sender domain is {from_reg or 'unknown'}",
            )
            break
    lookalike = ind.lookalike_brand(parsed.from_addr)
    if lookalike:
        add(
            "lookalike_sender_domain",
            f"Sender domain {from_reg} resembles '{lookalike[0]}' (edit distance {lookalike[1]})",
        )
    if from_reg in ind.FREEMAIL:
        add("freemail_sender", f"Sender uses free webmail domain {from_reg}")
    if tld_of(parsed.from_addr) in ind.SUSPICIOUS_TLDS:
        add("suspicious_sender_tld", f"Sender domain uses low-reputation TLD .{tld_of(parsed.from_addr)}")
    if from_reg and from_reg not in known_good and ind.looks_random_domain(parsed.from_addr):
        add("random_sender_domain", f"Sender domain {from_reg} looks algorithmically generated")

    # --- Links ------------------------------------------------------------
    seen = {"shortener": False, "ip": False, "puny": False, "tld": False, "mismatch": False}
    for link in parsed.links:
        reg = registered_domain(link.url)
        if reg in ind.URL_SHORTENERS and not seen["shortener"]:
            add("url_shortener", f"Shortened link hides its destination: {link.url}")
            seen["shortener"] = True
        if ind.is_ip_literal(link.url) and not seen["ip"]:
            add("ip_literal_url", f"Link uses a raw IP address: {link.url}")
            seen["ip"] = True
        if ind.is_punycode(link.url) and not seen["puny"]:
            add("punycode_url", f"Punycode/IDN link (possible homoglyph): {link.url}")
            seen["puny"] = True
        if tld_of(link.url) in ind.SUSPICIOUS_TLDS and not seen["tld"]:
            add("suspicious_url_tld", f"Link uses low-reputation TLD .{tld_of(link.url)}: {link.url}")
            seen["tld"] = True
        if link.source == "href" and link.anchor_text and reg and not seen["mismatch"]:
            implied = ind.domains_in_text(link.anchor_text)
            for brand in ind.brands_in_text(link.anchor_text):
                implied |= ind.BRAND_DOMAINS[brand]
            if implied and reg not in implied:
                add(
                    "link_text_href_mismatch",
                    f"Link text implies {sorted(implied)} but href resolves to {reg}: {link.url}",
                )
                seen["mismatch"] = True

    # --- Body language ----------------------------------------------------
    body = parsed.body_combined.lower()
    if parsed.links and _contains_any(body, CREDENTIAL_KEYWORDS):
        add("credential_keywords_with_link", "Credential/account-verification language paired with an outbound link")
    if _contains_any(body, URGENCY_KEYWORDS):
        add("urgency_language", "Urgency / pressure language detected in the message body")
    if _contains_any(body, FINANCIAL_KEYWORDS):
        add("financial_request_language", "Payment/wire/invoice request language detected")
    if _contains_any(body, REWARD_SCAM_KEYWORDS):
        add("reward_scam_language", "Prize/lottery/reward-scam language detected")
    if ind.has_obfuscated_unicode(parsed.subject) or ind.has_obfuscated_unicode(parsed.from_display):
        add("unicode_obfuscation", "Look-alike Unicode characters used in subject/sender to evade filters")

    # --- Attachments ------------------------------------------------------
    for att in parsed.attachments:
        ext = att.extension
        parts = [p.lower() for p in att.filename.split(".")[1:]]
        if len(parts) >= 2 and parts[-1] in ind.RISKY_EXT:
            add("double_extension_attachment", f"Double-extension attachment: {att.filename}")
        if ext in ind.RISKY_EXT:
            add("risky_attachment", f"Executable/risky attachment: {att.filename} ({att.content_type})")
        elif ext in ind.MACRO_EXT:
            add("macro_office_attachment", f"Macro-enabled Office attachment: {att.filename}")
        elif ext in ind.HTML_EXT:
            add("html_attachment", f"HTML attachment (possible smuggling / credential page): {att.filename}")
        elif ext in ind.ARCHIVE_EXT:
            add("archive_attachment", f"Archive attachment (may conceal a payload): {att.filename}")

    score = sum(f.weight for f in findings)
    summary = {
        "num_findings": len(findings),
        "num_links": len(parsed.links),
        "num_attachments": len(parsed.attachments),
        "high": sum(1 for f in findings if f.severity == "high"),
        "medium": sum(1 for f in findings if f.severity == "medium"),
        "low": sum(1 for f in findings if f.severity == "low"),
        "spf": auth.spf, "dkim": auth.dkim, "dmarc": auth.dmarc,
    }
    return Result(parsed.path, score, verdict_for(score), findings, auth, summary)
