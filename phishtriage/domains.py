"""Lightweight registered-domain (eTLD+1) extraction - pure standard library.

Deliberately avoids a hard dependency on `tldextract` so the analyzer runs
anywhere, including air-gapped/offline CI, with deterministic results. Uses a
curated subset of multi-label public suffixes and falls back to the last two
labels otherwise. Good enough for triage; not a substitute for the full PSL.
"""
from __future__ import annotations

from urllib.parse import urlparse

# Curated subset of multi-label public suffixes (eTLDs) seen in the wild.
MULTI_LABEL_SUFFIXES = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk", "ltd.uk", "plc.uk",
    "com.au", "net.au", "org.au", "gov.au", "edu.au", "id.au",
    "co.nz", "org.nz", "co.za", "org.za", "co.jp", "or.jp", "ne.jp",
    "com.br", "com.mx", "com.cn", "com.hk", "com.sg", "com.tr",
    "co.in", "co.kr", "com.ua", "com.pl", "com.ar", "co.id",
}


def hostname_of(value: str) -> str:
    """Return a bare lowercase hostname from an address, URL, or domain."""
    host = (value or "").strip().lower().rstrip(".")
    if "://" in host or host.startswith("//"):  # full URL -> use a real parser
        target = host if "://" in host else "http:" + host
        return (urlparse(target).hostname or "").strip("<>[] ")
    if "@" in host:  # email address -> domain part
        host = host.rsplit("@", 1)[-1]
    if "/" in host:  # stray path
        host = host.split("/", 1)[0]
    if ":" in host:  # strip port
        host = host.split(":", 1)[0]
    return host.strip("<>[] ")


def registered_domain(value: str) -> str:
    """Return the eTLD+1 (registrable domain) for a host/address/domain."""
    host = hostname_of(value)
    if not host or "." not in host:
        return host
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    if ".".join(labels[-2:]) in MULTI_LABEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def primary_label(value: str) -> str:
    """The most-significant label of the registrable domain (e.g. 'paypal')."""
    reg = registered_domain(value)
    return reg.split(".")[0] if reg else ""


def tld_of(value: str) -> str:
    """The final label / effective TLD ('com', 'xyz', 'uk')."""
    reg = registered_domain(value)
    return reg.split(".")[-1] if "." in reg else ""
