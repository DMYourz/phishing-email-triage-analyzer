"""Parse RFC 8601 Authentication-Results into SPF/DKIM/DMARC verdicts."""
from __future__ import annotations

import re
from dataclasses import dataclass

_PASS = {"pass"}
_FAIL = {"fail", "softfail", "permerror", "temperror", "policy", "neutral"}


@dataclass
class AuthVerdict:
    spf: str = "none"
    dkim: str = "none"
    dmarc: str = "none"

    def _state(self, value: str) -> str:
        v = (value or "none").lower()
        if v in _PASS:
            return "pass"
        if v in _FAIL:
            return "fail"
        return "none"

    @property
    def spf_state(self) -> str:
        return self._state(self.spf)

    @property
    def dkim_state(self) -> str:
        return self._state(self.dkim)

    @property
    def dmarc_state(self) -> str:
        return self._state(self.dmarc)


def parse_auth_results(auth_header: str) -> AuthVerdict:
    """Extract spf=/dkim=/dmarc= tokens from Authentication-Results header(s)."""
    a = (auth_header or "").lower()

    def grab(key: str) -> str:
        m = re.search(rf"(?:^|[;\s]){key}\s*=\s*([a-z]+)", a)
        return m.group(1) if m else "none"

    return AuthVerdict(spf=grab("spf"), dkim=grab("dkim"), dmarc=grab("dmarc"))
