"""Parse a raw .eml file into a structured, analyzer-friendly object."""
from __future__ import annotations

import email
import hashlib
import re
from dataclasses import dataclass, field
from email import policy
from email.utils import getaddresses, parseaddr
from html.parser import HTMLParser
from pathlib import Path
from typing import List

# URLs in plain text. Intentionally permissive, trimmed afterwards.
URL_RE = re.compile(r"""https?://[^\s"'<>)\]}\\]+""", re.IGNORECASE)
_TRIM = ".,);:!?”’'\""


@dataclass
class Attachment:
    filename: str
    content_type: str
    size: int
    sha256: str
    extension: str


@dataclass
class Link:
    url: str
    source: str            # "href" | "body-text"
    anchor_text: str = ""


@dataclass
class ParsedEmail:
    path: str
    from_display: str
    from_addr: str
    reply_to: List[str]
    return_path: str
    to: List[str]
    subject: str
    date: str
    message_id: str
    received: List[str]
    auth_results: str
    body_text: str
    body_html: str
    links: List[Link]
    attachments: List[Attachment]
    raw_size: int
    headers: dict = field(default_factory=dict)

    @property
    def body_combined(self) -> str:
        return f"{self.subject}\n{self.body_text}\n{self.body_html}"


class _AnchorExtractor(HTMLParser):
    """Collect (href, anchor_text) pairs from HTML bodies."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[tuple[str, str]] = []
        self._href: str | None = None
        self._text: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "a":
            self._href = dict(attrs).get("href")
            self._text = []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag.lower() == "a" and self._href is not None:
            self.links.append((self._href, "".join(self._text).strip()))
            self._href, self._text = None, []


def _sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _extension(filename: str) -> str:
    name = (filename or "").strip().strip('"')
    return name.rsplit(".", 1)[-1].lower() if "." in name else ""


def _decode(part) -> str:
    try:
        content = part.get_content()
        return content if isinstance(content, str) else ""
    except Exception:
        payload = part.get_payload(decode=True) or b""
        charset = part.get_content_charset() or "utf-8"
        return payload.decode(charset, errors="replace")


def _extract_bodies(msg) -> tuple[str, str]:
    text, html = "", ""
    parts = msg.walk() if msg.is_multipart() else [msg]
    for part in parts:
        if part.is_multipart():
            continue
        if (part.get_content_disposition() or "") == "attachment":
            continue
        ctype = part.get_content_type()
        if ctype == "text/plain":
            text += _decode(part)
        elif ctype == "text/html":
            html += _decode(part)
    return text, html


def _extract_links(text: str, html: str) -> List[Link]:
    links: list[Link] = []
    seen: set[tuple[str, str]] = set()

    def add(url: str, source: str, anchor: str = "") -> None:
        url = (url or "").strip().rstrip(_TRIM)
        if not url.lower().startswith(("http://", "https://")):
            return
        key = (url, anchor)
        if key in seen:
            return
        seen.add(key)
        links.append(Link(url=url, source=source, anchor_text=anchor))

    if html:
        ax = _AnchorExtractor()
        try:
            ax.feed(html)
        except Exception:
            pass
        for href, anchor in ax.links:
            add(href, "href", anchor)
        for u in URL_RE.findall(re.sub(r"<[^>]+>", " ", html)):
            add(u, "body-text")
    for u in URL_RE.findall(text or ""):
        add(u, "body-text")
    return links


def _extract_attachments(msg) -> List[Attachment]:
    out: list[Attachment] = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        disposition = part.get_content_disposition()
        filename = part.get_filename()
        if disposition == "attachment" or (filename and disposition != "inline"):
            payload = part.get_payload(decode=True) or b""
            out.append(
                Attachment(
                    filename=filename or "(unnamed)",
                    content_type=part.get_content_type(),
                    size=len(payload),
                    sha256=_sha256(payload),
                    extension=_extension(filename or ""),
                )
            )
    return out


def parse_email(path: str | Path) -> ParsedEmail:
    p = Path(path)
    raw = p.read_bytes()
    msg = email.message_from_bytes(raw, policy=policy.default)

    from_display, from_addr = parseaddr(msg.get("From", ""))
    reply_to = [a for _, a in getaddresses(msg.get_all("Reply-To", [])) if a]
    to = [a for _, a in getaddresses(msg.get_all("To", [])) if a]
    return_path = parseaddr(msg.get("Return-Path", ""))[1]
    auth = " ".join(
        msg.get_all("Authentication-Results", [])
        + msg.get_all("ARC-Authentication-Results", [])
    )
    body_text, body_html = _extract_bodies(msg)

    return ParsedEmail(
        path=str(p),
        from_display=from_display,
        from_addr=from_addr,
        reply_to=reply_to,
        return_path=return_path,
        to=to,
        subject=str(msg.get("Subject", "")),
        date=str(msg.get("Date", "")),
        message_id=str(msg.get("Message-ID", "")),
        received=msg.get_all("Received", []),
        auth_results=auth,
        body_text=body_text,
        body_html=body_html,
        links=_extract_links(body_text, body_html),
        attachments=_extract_attachments(msg),
        raw_size=len(raw),
        headers={k: str(v) for k, v in msg.items()},
    )
