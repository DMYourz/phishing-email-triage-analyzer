"""Indicator helpers: brand look-alikes, homoglyphs, URL/domain heuristics."""
from __future__ import annotations

import re

from .domains import hostname_of, primary_label, registered_domain, tld_of

# Map of brand -> set of legitimate registrable domains. Used to flag both
# display-name impersonation and look-alike sender domains.
BRAND_DOMAINS: dict[str, set[str]] = {
    "microsoft": {"microsoft.com", "microsoftonline.com", "office365.com", "office.com", "live.com"},
    "office 365": {"microsoft.com", "office365.com", "office.com"},
    "outlook": {"outlook.com", "microsoft.com"},
    "apple": {"apple.com", "icloud.com"},
    "icloud": {"icloud.com", "apple.com"},
    "google": {"google.com", "gmail.com"},
    "paypal": {"paypal.com"},
    "amazon": {"amazon.com"},
    "netflix": {"netflix.com"},
    "docusign": {"docusign.com", "docusign.net"},
    "adobe": {"adobe.com"},
    "linkedin": {"linkedin.com"},
    "chase": {"chase.com"},
    "wells fargo": {"wellsfargo.com"},
    "bank of america": {"bankofamerica.com"},
    "dhl": {"dhl.com"},
    "fedex": {"fedex.com"},
    "ups": {"ups.com"},
    "usps": {"usps.com"},
}

FREEMAIL = {
    "gmail.com", "googlemail.com", "yahoo.com", "ymail.com", "outlook.com",
    "hotmail.com", "live.com", "aol.com", "icloud.com", "proton.me",
    "protonmail.com", "gmx.com", "mail.com", "zoho.com",
}

SUSPICIOUS_TLDS = {
    "zip", "mov", "xyz", "top", "gq", "cf", "tk", "ml", "ga", "work",
    "click", "link", "country", "kim", "loan", "review", "fit", "date",
    "racing", "stream", "men", "win", "bid", "rest", "quest", "cam", "sbs",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "rb.gy", "shorturl.at", "tiny.cc", "t.ly",
    "lnkd.in", "shorte.st",
}

RISKY_EXT = {
    "exe", "scr", "com", "pif", "bat", "cmd", "js", "jse", "vbs", "vbe",
    "wsf", "wsh", "hta", "jar", "iso", "img", "lnk", "ps1", "msi", "reg",
    "vhd", "vhdx", "cpl", "msc", "scf",
}
MACRO_EXT = {"docm", "xlsm", "pptm", "dotm", "xlam", "xltm", "potm"}
HTML_EXT = {"html", "htm", "shtml", "xhtml"}
ARCHIVE_EXT = {"zip", "rar", "7z", "gz", "tgz", "tar", "cab", "ace"}

_HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b"})
_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_DOMAIN_IN_TEXT = re.compile(r"\b([a-z0-9-]+(?:\.[a-z0-9-]+)+)\b", re.IGNORECASE)


def normalize_homoglyphs(s: str) -> str:
    s = (s or "").lower().replace("rn", "m").replace("vv", "w")
    return s.translate(_HOMOGLYPHS)


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def is_ip_literal(value: str) -> bool:
    return bool(_IPV4_RE.match(hostname_of(value)))


def is_punycode(value: str) -> bool:
    return "xn--" in hostname_of(value)


def lookalike_brand(domain: str) -> tuple[str, int] | None:
    """If `domain` resembles a known brand domain (but isn't one), return
    (brand, edit_distance). Uses homoglyph-normalised primary labels."""
    reg = registered_domain(domain)
    if not reg:
        return None
    label = primary_label(domain)
    norm = normalize_homoglyphs(label)
    best: tuple[str, int] | None = None
    for brand, legit in BRAND_DOMAINS.items():
        if reg in legit:
            return None  # it's the real thing
        for good in legit:
            good_label = good.split(".")[0]
            if len(good_label) < 4:
                continue
            dist = levenshtein(norm, normalize_homoglyphs(good_label))
            if dist <= 1 and (best is None or dist < best[1]):
                best = (brand, dist)
    return best


def brands_in_text(text: str) -> set[str]:
    t = (text or "").lower()
    return {b for b in BRAND_DOMAINS if b in t}


def domains_in_text(text: str) -> set[str]:
    out = set()
    for m in _DOMAIN_IN_TEXT.findall(text or ""):
        if "." in m and tld_of(m):
            out.add(registered_domain(m))
    return out


# --- Algorithmically-generated / obfuscated text heuristics -----------------
def looks_random_domain(value: str) -> bool:
    """Heuristic: does the registrable domain's main label look machine-generated?
    Catches throwaway domains like 'b8o9w9hx5v.us'. Tuned to avoid normal,
    pronounceable brand domains. The caller should still exclude known-good
    and freemail domains before trusting this."""
    label = primary_label(value)
    if len(label) < 8:
        return False
    digits = sum(c.isdigit() for c in label)
    if digits >= 3:
        return True
    letters = [c for c in label if c.isalpha()]
    if letters and len(label) >= 10:
        vowels = sum(c in "aeiou" for c in label.lower())
        if vowels / len(letters) < 0.20:  # vowel-starved -> not a real word
            return True
    return False


# Unicode blocks abused to disguise plain text (math-bold, full-width Latin).
_OBFUSCATED_RANGES = ((0x1D400, 0x1D7FF), (0xFF21, 0xFF3A), (0xFF41, 0xFF5A))


def has_obfuscated_unicode(text: str) -> bool:
    """True if text contains letter-like characters from obfuscation blocks
    (e.g. 'ð\x9d\x90\x86ð\x9d\x90¨ð\x9d\x90«' bold letters) used to evade keyword filters."""
    for ch in text or "":
        cp = ord(ch)
        for lo, hi in _OBFUSCATED_RANGES:
            if lo <= cp <= hi:
                return True
    return False
