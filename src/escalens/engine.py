"""Privilege-escalation analysis: match a principal's effective permissions
against the known escalation primitive catalog.

The engine is deliberately conservative in the auditor's favour: every finding
carries the evidence that produced it, and an explicit `Deny` that neutralises a
grant is reported as a suppression instead of a finding.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .documents import Statement
from .rules import CATALOG, Rule


@dataclass
class PolicyRef:
    """A named policy attached to a principal."""

    name: str
    statements: list[Statement] = field(default_factory=list)
    kind: str = "inline"


@dataclass
class Principal:
    """An IAM user or role with every policy attached to it."""

    name: str
    kind: str = "user"  # user | role | group
    arn: str = ""
    policies: list[PolicyRef] = field(default_factory=list)
    groups: list[str] = field(default_factory=list)

    def all_statements(self) -> list[tuple[str, Statement]]:
        out = []
        for policy in self.policies:
            for st in policy.statements:
                out.append((policy.name, st))
        return out


@dataclass
class Finding:
    """One matched escalation primitive for one principal."""

    rule: Rule
    principal: Principal
    evidence: list[str]
    suppressed_by: list[str] = field(default_factory=list)
    subsumed: bool = False

    @property
    def active(self) -> bool:
        return not self.suppressed_by and not self.subsumed

    @property
    def reported(self) -> bool:
        """Findings suppressed only by a deny are still shown as suppressed."""
        return not self.subsumed

    @property
    def severity(self) -> str:
        """Suppressed findings drop one severity step: the deny is a real control."""
        if self.active:
            return self.rule.severity
        order = ["critical", "high", "medium", "low"]
        idx = order.index(self.rule.severity) if self.rule.severity in order else 3
        return order[min(idx + 1, len(order) - 1)]


@dataclass
class AnalysisResult:
    findings: list[Finding]
    principals: list[Principal]
    errors: list[str] = field(default_factory=list)

    @property
    def active(self) -> list[Finding]:
        return [f for f in self.findings if f.active]

    def subsumed_for(self, principal: Principal) -> list[Finding]:
        return [f for f in self.findings if f.subsumed and f.principal is principal]

    def score(self) -> int:
        """0-100 risk score. Criticals dominate, breadth adds background weight."""
        weights = {"critical": 60, "high": 20, "medium": 8, "low": 2}
        total = 0
        for finding in self.active:
            total += finding.rule.score_weight or weights.get(finding.severity, 0)
        return min(total, 100)

    def grade(self) -> str:
        score = self.score()
        for cutoff, grade in ((90, "F"), (70, "D"), (50, "C"), (25, "B"), (1, "A")):
            if score >= cutoff:
                return grade
        return "A+"


def _denying_statements(
    statements: list[tuple[str, Statement]], action: str, resource: str
) -> list[str]:
    """Policy names whose explicit Deny blocks `action` on `resource`.

    A Deny carrying a Condition only blocks *some* calls, so it is recorded as a
    conditional mitigation. Conditions are not evaluated (that needs request
    context the tool does not have), so a conditional deny must be verified by a
    human before it is treated as a control.
    """
    hits = []
    for name, st in statements:
        if st.is_deny and st.covers_action(action) and st.covers_resource(resource):
            hits.append(f"{name} (conditional deny - verify)" if st.conditions else name)
    return sorted(set(hits))


def _allow_evidence(
    statements: list[tuple[str, Statement]], action: str
) -> list[tuple[str, Statement]]:
    """Allow statements (with their policy name) that grant `action`."""
    return [(n, st) for n, st in statements if st.is_allow and st.covers_action(action)]


def _evaluate_clause(
    statements: list[tuple[str, Statement]],
    patterns: tuple[str, ...],
    broad_only: bool,
) -> tuple[list[str], list[str], bool] | None:
    """Evaluate one rule clause (a set of OR-ed action patterns).

    Returns (evidence, suppresses, broad) or None when the clause is not granted.
    """
    for pattern in patterns:
        for name, st in _allow_evidence(statements, pattern):
            if broad_only and not st.is_wildcard_resource:
                continue
            resources = st.resources or ["*"]
            # A grant is real unless every resource it covers is denied.
            surviving = [
                r for r in resources if not _denying_statements(statements, pattern, r)
            ]
            denies: list[str] = []
            if not surviving:
                for r in resources:
                    denies.extend(_denying_statements(statements, pattern, r))
            sid = f" ({st.sid})" if st.sid else ""
            evidence = [f"{name}{sid}: allows {pattern} on {', '.join(resources)}"]
            return evidence, sorted(set(denies)), "*" in resources
    return None


def evaluate_principal(principal: Principal, catalog=CATALOG) -> list[Finding]:
    """Return every catalog rule that the principal's policies trip."""
    statements = principal.all_statements()
    findings: list[Finding] = []

    for rule in catalog:
        evidence: list[str] = []
        denies: list[str] = []
        broad = False
        matched_all = True

        for clause in rule.requires:
            result = _evaluate_clause(statements, clause, rule.needs_broad_resource)
            if result is None:
                matched_all = False
                break
            clause_evidence, clause_denies, clause_broad = result
            evidence.extend(clause_evidence)
            denies.extend(clause_denies)
            broad = broad or clause_broad

        if not matched_all:
            continue
        # Rules flagged needs_broad_resource must include a wildcard-resource grant.
        if rule.needs_broad_resource and not broad:
            continue

        findings.append(
            Finding(
                rule=rule,
                principal=principal,
                evidence=evidence,
                suppressed_by=sorted(set(denies)),
            )
        )

    return findings


def analyze(principals: list[Principal], catalog=CATALOG) -> AnalysisResult:
    """Analyze a list of principals and return a storable result."""
    findings: list[Finding] = []
    for principal in principals:
        findings.extend(evaluate_principal(principal, catalog))
    _collapse_full_admin(findings)
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda f: (order.get(f.severity, 9), not f.reported, f.principal.name))
    return AnalysisResult(findings=findings, principals=principals)


def _collapse_full_admin(findings: list[Finding]) -> None:
    """Mark primitives moot for principals that already hold full admin.

    Reporting twenty escalation paths for an account administrator buries the
    one finding that matters. The admin finding stays; the rest are recorded as
    subsumed so the report stays readable and the score is not inflated.
    """
    admins = {
        id(f.principal)
        for f in findings
        if f.rule.id == "ADM-001" and f.active
    }
    for finding in findings:
        if id(finding.principal) in admins and finding.rule.id != "ADM-001" and finding.active:
            finding.subsumed = True
