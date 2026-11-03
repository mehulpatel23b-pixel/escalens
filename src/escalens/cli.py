"""Command-line interface for escalens."""

from __future__ import annotations

import argparse
import sys

from .engine import analyze
from .loader import LoaderError, load_path
from .report import render_json, render_text
from .rules import CATALOG

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2
EXIT_USAGE = 64

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="escalens",
        description=(
            "Offline AWS IAM privilege-escalation auditor. Reads policy JSON or an "
            "IAM account-authorization-details export and reports privilege-escalation "
            "primitives. Never contacts AWS, never needs credentials."
        ),
        epilog=(
            "Defensive use only. This tool analyses policy documents you already have; "
            "it performs no API calls and no exploitation."
        ),
    )
    parser.add_argument("path", help="policy JSON file, authorization-details export, or directory of *.json")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of text")
    parser.add_argument("--no-color", action="store_true", help="disable ANSI colours (auto-off when piped)")
    parser.add_argument("-v", "--verbose", action="store_true", help="show every piece of evidence per finding")
    parser.add_argument(
        "--fail-on",
        choices=("none", "low", "medium", "high", "critical"),
        default="none",
        help="exit 1 when an active finding at or above this severity exists (default: none)",
    )
    parser.add_argument("--min-score", type=int, default=None, metavar="N",
                        help="exit 1 when the risk score is at or above N")
    parser.add_argument("--list-rules", action="store_true", help="print the rule catalog and exit")
    parser.add_argument("--quiet", action="store_true", help="suppress the report, keep the exit code")
    return parser


def _command_list_rules() -> int:
    print(f"{len(CATALOG)} privilege-escalation primitives\n")
    for rule in CATALOG:
        actions = " AND ".join(" | ".join(clause) for clause in rule.requires)
        print(f"{rule.id}  [{rule.severity:8}] {rule.title}")
        print(f"    requires : {actions}")
        print(f"    category : {rule.category}")
        print(f"    fix      : {rule.remediation}")
        print()
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.list_rules:
        return _command_list_rules()

    try:
        principals = load_path(args.path)
    except LoaderError as exc:
        print(f"escalens: {exc}", file=sys.stderr)
        return EXIT_ERROR

    result = analyze(principals)

    if not args.quiet:
        color = not args.no_color and sys.stdout.isatty()
        print(render_json(result) if args.json else render_text(result, color=color, verbose=args.verbose))

    worst = max((SEVERITY_RANK.get(f.severity, 0) for f in result.active), default=-1)
    if args.fail_on != "none" and worst >= SEVERITY_RANK[args.fail_on]:
        return EXIT_FINDINGS
    if args.min_score is not None and result.score() >= args.min_score:
        return EXIT_FINDINGS
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
