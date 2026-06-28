"""Command-line interface for phishtriage."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from . import report as report_mod
from .parser import parse_email
from .scoring import evaluate, load_rules

_VERDICT_EMOJI = {
    "Benign": "🟢", "Suspicious": "🟡",
    "Likely Phishing": "🟠", "High-Confidence Phishing": "🔴",
}


def _analyze(path, rules):
    parsed = parse_email(path)
    return parsed, evaluate(parsed, rules)


def _write_outputs(parsed, result, outdir, fmt) -> list[Path]:
    out = Path(outdir)
    out.mkdir(parents=True, exist_ok=True)
    stem = Path(parsed.path).stem
    written: list[Path] = []
    targets = {
        "md": (".report.md", report_mod.render_markdown),
        "json": (".report.json", report_mod.render_json),
        "html": (".report.html", report_mod.render_html),
    }
    for key, (suffix, fn) in targets.items():
        if fmt in (key, "all"):
            p = out / f"{stem}{suffix}"
            p.write_text(fn(result, parsed), encoding="utf-8")
            written.append(p)
    return written


def _write_batch_summary(rows, outdir) -> Path:
    out = Path(outdir)
    lines = [
        "# Batch Triage Summary",
        "",
        f"Analyzed **{len(rows)}** message(s).",
        "",
        "| Sample | Score | Verdict |",
        "|--------|:-----:|---------|",
    ]
    for name, score, verdict in sorted(rows, key=lambda r: -r[1]):
        lines.append(f"| `{name}` | {score} | {_VERDICT_EMOJI.get(verdict,'')} {verdict} |")
    lines.append("")
    p = out / "SUMMARY.md"
    p.write_text("\n".join(lines), encoding="utf-8")
    return p


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="phishtriage",
                                 description="Offline-first phishing email triage analyzer.")
    ap.add_argument("--version", action="version", version=f"phishtriage {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("analyze", help="Analyze a single .eml file")
    a.add_argument("file")
    a.add_argument("-f", "--format", choices=["md", "json", "html", "all"], default="md")
    a.add_argument("-o", "--output", help="Directory to write report(s) into")
    a.add_argument("--enrich", action="store_true",
                   help="Enable optional online enrichment (requires API keys)")

    b = sub.add_parser("batch", help="Analyze every .eml in a directory")
    b.add_argument("directory")
    b.add_argument("-f", "--format", choices=["md", "json", "html", "all"], default="all")
    b.add_argument("-o", "--output", default="reports")

    args = ap.parse_args(argv)
    rules = load_rules()

    if args.cmd == "analyze":
        parsed, result = _analyze(args.file, rules)
        if args.enrich:
            from .enrichment import enrich
            note = enrich([link.url for link in parsed.links] + [parsed.from_addr])
            print(f"[enrichment] {note.get('_status')}: {note.get('_reason', note.get('_providers'))}",
                  file=sys.stderr)
        if args.output:
            for w in _write_outputs(parsed, result, args.output, args.format):
                print(f"[+] wrote {w}")
        else:
            renderer = {"json": report_mod.render_json, "html": report_mod.render_html}.get(
                args.format, report_mod.render_markdown)
            print(renderer(result, parsed))
        print(f"[=] {_VERDICT_EMOJI.get(result.verdict,'')} {result.verdict} "
              f"(score {result.score})", file=sys.stderr)
        return 0

    if args.cmd == "batch":
        files = sorted(Path(args.directory).glob("*.eml"))
        if not files:
            print(f"No .eml files found in {args.directory}", file=sys.stderr)
            return 2
        rows = []
        for fp in files:
            parsed, result = _analyze(fp, rules)
            _write_outputs(parsed, result, args.output, args.format)
            rows.append((fp.name, result.score, result.verdict))
            print(f"[+] {fp.name:<40s} score={result.score:>3d}  "
                  f"{_VERDICT_EMOJI.get(result.verdict,'')} {result.verdict}")
        summary = _write_batch_summary(rows, args.output)
        print(f"[+] wrote {summary}")
        return 0

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
