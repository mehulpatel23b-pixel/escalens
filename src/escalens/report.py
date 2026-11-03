"""Rendering analysis results as human-readable text or JSON."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from .engine import AnalysisResult

SEVERITY_COLORS = {
    "critical": "\033[1;31m",
    "high": "\033[31m",
    "medium": "\033[33m",
    "low": "\033[36m",
}
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"


def _c(text: str, severity: str, color: bool) -> str:
    if not color:
        return text
    return f"{SEVERITY_COLORS.get(severity, '')}{text}{RESET}"


def render_text(result: AnalysisResult, color: bool = True, verbose: bool = False) -> str:
    """Render a detailed terminal report."""
    lines: list[str] = []
    bar = "=" * 78
    lines.append(bar)
    lines.append(f"{BOLD if color else ''}ESCALENS - AWS IAM privilege-escalation audit{RESET if color else ''}")
    lines.append(f"generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    lines.append(bar)

    active = result.active
    suppressed = [f for f in result.findings if f.reported and not f.active]
    subsumed = [f for f in result.findings if f.subsumed]

    lines.append("")
    lines.append(
        f"principals scanned : {len(result.principals)}  "
        f"({sum(1 for p in result.principals if p.kind == 'user')} users, "
        f"{sum(1 for p in result.principals if p.kind == 'role')} roles, "
        f"{sum(1 for p in result.principals if p.kind == 'group')} groups)"
    )
    lines.append(f"active findings    : {len(active)}")
    if suppressed:
        lines.append(f"suppressed by Deny : {len(suppressed)}")
    if subsumed:
        lines.append(f"moot (full admin)  : {len(subsumed)}")
    lines.append(f"risk score         : {result.score()}/100   grade {result.grade()}")
    lines.append("")

    if not active:
        lines.append("No active privilege-escalation paths detected.")
        lines.append("")
        if not suppressed:
            lines.append("Note: this checks known permission combinations only. It is not a")
            lines.append("proof of safety - review trust policies and Access Analyzer output too.")
        return "\n".join(lines)

    current_principal = None
    for finding in active:
        if finding.principal.name != current_principal:
            current_principal = finding.principal.name
            header = f"{current_principal} [{finding.principal.kind}]"
            lines.append("")
            lines.append(f"--- {header} " + "-" * max(0, 74 - len(header)))
        sev = finding.severity
        lines.append("")
        lines.append(f"  {_c('[' + sev.upper() + ']', sev, color)} {finding.rule.id}  {finding.rule.title}")
        lines.append(f"    impact     : {finding.rule.impact}")
        if verbose:
            for ev in finding.evidence:
                lines.append(f"    evidence   : {ev}")
        else:
            lines.append(f"    evidence   : {finding.evidence[0]}")
        lines.append(f"    fix        : {finding.rule.remediation}")
        if finding.rule.mitre:
            lines.append(f"    {DIM if color else ''}mitre      : {finding.rule.mitre}{RESET if color else ''}")
        if finding.suppressed_by:
            lines.append(
                f"    {DIM if color else ''}partial deny: {', '.join(finding.suppressed_by)} on some resources{RESET if color else ''}"
            )

    for principal in {id(f.principal): f.principal for f in subsumed}.values():
        moot = [f for f in subsumed if f.principal is principal]
        ids = ", ".join(sorted({f.rule.id for f in moot}))
        lines.append("")
        lines.append(
            f"  {DIM if color else ''}{principal.name}: {len(moot)} further primitive(s) moot - "
            f"the principal is already an effective administrator ({ids}){RESET if color else ''}"
        )

    if suppressed:
        lines.append("")
        lines.append("-" * 78)
        lines.append("SUPPRESSED (explicit Deny neutralises the grant)")
        for finding in suppressed:
            lines.append(
                f"  ok  {finding.rule.id} {finding.rule.title} "
                f"[{finding.principal.name}] denied by {', '.join(finding.suppressed_by)}"
            )

    lines.append("")
    lines.append("-" * 78)
    lines.append("Defensive audit output. Verify findings against your actual trust policies")
    lines.append("and AWS IAM Access Analyzer before acting.")
    return "\n".join(lines)


def render_json(result: AnalysisResult) -> str:
    """Render a machine-readable report for CI, ticketing or SOAR ingestion."""
    findings = []
    for finding in result.findings:
        findings.append(
            {
                "id": finding.rule.id,
                "title": finding.rule.title,
                "severity": finding.severity,
                "active": finding.active,
                "category": finding.rule.category,
                "principal": finding.principal.name,
                "principal_type": finding.principal.kind,
                "principal_arn": finding.principal.arn,
                "impact": finding.rule.impact,
                "remediation": finding.rule.remediation,
                "evidence": finding.evidence,
                "suppressed_by": finding.suppressed_by,
                "mitre": finding.rule.mitre,
            }
        )
    payload = {
        "tool": "escalens",
        "generated": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "principals": len(result.principals),
            "findings_active": len(result.active),
            "findings_suppressed": len(result.findings) - len(result.active),
            "risk_score": result.score(),
            "grade": result.grade(),
            "by_severity": {
                sev: sum(1 for f in result.active if f.severity == sev)
                for sev in ("critical", "high", "medium", "low")
            },
        },
        "findings": findings,
    }
    return json.dumps(payload, indent=2)
