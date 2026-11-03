"""Parsing and normalization of AWS IAM policy documents."""

from __future__ import annotations

from dataclasses import dataclass, field

from .actions import as_list, matches


@dataclass
class Statement:
    """A single normalized IAM statement."""

    effect: str
    actions: list[str] = field(default_factory=list)
    not_actions: list[str] = field(default_factory=list)
    resources: list[str] = field(default_factory=list)
    not_resources: list[str] = field(default_factory=list)
    conditions: dict = field(default_factory=dict)
    sid: str = ""

    @property
    def is_allow(self) -> bool:
        return self.effect == "allow"

    @property
    def is_deny(self) -> bool:
        return self.effect == "deny"

    def covers_action(self, action: str) -> bool:
        """True when this statement's Action/NotAction selects `action`."""
        if self.actions:
            return any(matches(p, action) for p in self.actions)
        if self.not_actions:
            return not any(matches(p, action) for p in self.not_actions)
        return False

    def covers_resource(self, resource: str) -> bool:
        """True when this statement's Resource/NotResource selects `resource`."""
        if self.resources:
            return any(matches(p, resource) for p in self.resources)
        if self.not_resources:
            return not any(matches(p, resource) for p in self.not_resources)
        return True

    @property
    def is_wildcard_resource(self) -> bool:
        return "*" in self.resources


def normalize_statement(raw: dict) -> Statement:
    """Build a Statement from a raw AWS statement mapping."""
    return Statement(
        effect=str(raw.get("Effect", "")).strip().lower(),
        actions=as_list(raw.get("Action")),
        not_actions=as_list(raw.get("NotAction")),
        resources=as_list(raw.get("Resource")),
        not_resources=as_list(raw.get("NotResource")),
        conditions=raw.get("Condition") or {},
        sid=str(raw.get("Sid", "") or ""),
    )


def parse_policy(document) -> list[Statement]:
    """Parse a policy document (dict or JSON string) into statements."""
    if document is None:
        return []
    if isinstance(document, str):
        import json

        document = json.loads(document)
    if not isinstance(document, dict):
        return []
    raw_statements = document.get("Statement", [])
    if isinstance(raw_statements, dict):
        raw_statements = [raw_statements]
    if not isinstance(raw_statements, list):
        return []
    statements = []
    for raw in raw_statements:
        if isinstance(raw, dict):
            statements.append(normalize_statement(raw))
    return statements
