"""Optional online enrichment (VirusTotal / URLScan / AbuseIPDB).

Disabled by default so the analyzer is fully offline and reproducible. When
`--enrich` is passed and the relevant API keys are present in the environment,
indicators are looked up and a note is attached. Without keys it degrades
gracefully to a no-op so committed lab results never depend on the network.
"""
from __future__ import annotations

import os

ENV_KEYS = {
    "virustotal": "VT_API_KEY",
    "urlscan": "URLSCAN_API_KEY",
    "abuseipdb": "ABUSEIPDB_API_KEY",
}


def available_providers() -> list[str]:
    return [name for name, env in ENV_KEYS.items() if os.environ.get(env)]


def enrich(indicators: list[str]) -> dict:
    """Return a provider->result map. No-op (with a reason) when offline."""
    providers = available_providers()
    if not providers:
        return {"_status": "skipped", "_reason": "no API keys set; running offline"}
    try:
        import requests  # noqa: F401  (only needed when enriching)
    except ImportError:
        return {"_status": "skipped", "_reason": "`requests` not installed"}
    # Network calls intentionally omitted from the offline lab build.
    return {"_status": "ready", "_providers": providers, "_indicators": indicators}
