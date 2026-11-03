"""Load principals and their policies from local files.

Supported inputs, all offline (no AWS API calls, no credentials required):

* IAM `get-account-authorization-details` JSON export
* A single IAM policy document ({"Version": ..., "Statement": [...]})
* A directory of `*.json` policy files, one policy per file
* Terraform plan/source JSON listing aws_iam_policy_document objects
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from .documents import parse_policy
from .engine import PolicyRef, Principal


class LoaderError(Exception):
    """Raised when an input file cannot be interpreted."""


def _read(path: Path):
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise LoaderError(f"cannot read {path}: {exc}") from exc
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise LoaderError(f"{path} is not valid JSON: line {exc.lineno}: {exc.msg}") from exc


def _from_authorization_details(doc: dict) -> list[Principal]:
    """Parse the AWS get-account-authorization-details export."""
    principals: list[Principal] = []

    for user in doc.get("UserDetailList", []) or []:
        name = user.get("UserName", "unknown-user")
        policies: list[PolicyRef] = []
        for inline in user.get("UserPolicyList", []) or []:
            policies.append(
                PolicyRef(
                    name=f"{name}/{inline.get('PolicyName', 'inline')}",
                    statements=parse_policy(inline.get("PolicyDocument")),
                    kind="inline",
                )
            )
        for attached in user.get("AttachedManagedPolicies", []) or []:
            policies.append(
                PolicyRef(
                    name=attached.get("PolicyName", "managed"),
                    statements=parse_policy(attached.get("PolicyDocument")),
                    kind="managed",
                )
            )
        groups = []
        for g in user.get("GroupList", []) or []:
            if isinstance(g, str):
                groups.append(g)
            elif isinstance(g, dict):
                groups.append(g.get("GroupName", ""))
        principals.append(
            Principal(
                name=name,
                kind="user",
                arn=user.get("Arn", ""),
                policies=policies,
                groups=[g for g in groups if g],
            )
        )

    for role in doc.get("RoleDetailList", []) or []:
        name = role.get("RoleName", "unknown-role")
        policies = []
        for inline in role.get("RolePolicyList", []) or []:
            policies.append(
                PolicyRef(
                    name=f"{name}/{inline.get('PolicyName', 'inline')}",
                    statements=parse_policy(inline.get("PolicyDocument")),
                    kind="inline",
                )
            )
        for attached in role.get("AttachedManagedPolicies", []) or []:
            policies.append(
                PolicyRef(
                    name=attached.get("PolicyName", "managed"),
                    statements=parse_policy(attached.get("PolicyDocument")),
                    kind="managed",
                )
            )
        principals.append(
            Principal(name=name, kind="role", arn=role.get("Arn", ""), policies=policies)
        )

    for group in doc.get("GroupDetailList", []) or []:
        name = group.get("GroupName", "unknown-group")
        policies = []
        for inline in group.get("GroupPolicyList", []) or []:
            policies.append(
                PolicyRef(
                    name=f"{name}/{inline.get('PolicyName', 'inline')}",
                    statements=parse_policy(inline.get("PolicyDocument")),
                    kind="inline",
                )
            )
        for attached in group.get("AttachedManagedPolicies", []) or []:
            policies.append(
                PolicyRef(
                    name=attached.get("PolicyName", "managed"),
                    statements=parse_policy(attached.get("PolicyDocument")),
                    kind="managed",
                )
            )
        principals.append(Principal(name=name, kind="group", policies=policies))

    return principals


def _from_policy_document(doc: dict, label: str) -> list[Principal]:
    statements = parse_policy(doc)
    if not statements:
        raise LoaderError(
            f"{label}: no IAM statements found (expected a policy document with a "
            "'Statement' key, or an account authorization details export)"
        )
    return [Principal(name=label, kind="policy", policies=[PolicyRef(name=label, statements=statements)])]


def _from_terraform(doc: dict, label: str) -> list[Principal]:
    """Extract aws_iam_policy_document data sources from a Terraform plan/source."""
    principals: list[Principal] = []
    resources = doc.get("resource", {})
    if isinstance(resources, dict):
        resources = [resources]
    for resource_block in resources:
        if not isinstance(resource_block, dict):
            continue
        for kind, items in resource_block.items():
            if "iam_policy" not in kind and "iam_role_policy" not in kind:
                continue
            if not isinstance(items, dict):
                continue
            for res_name, body in items.items():
                if not isinstance(body, dict):
                    continue
                raw = body.get("policy")
                if isinstance(raw, str):
                    try:
                        raw = json.loads(raw)
                    except json.JSONDecodeError:
                        continue
                statements = parse_policy(raw)
                if statements:
                    principals.append(
                        Principal(
                            name=f"{kind}.{res_name}",
                            kind="policy",
                            policies=[PolicyRef(name=f"{kind}.{res_name}", statements=statements)],
                        )
                    )
    if not principals:
        data = doc.get("data", {})
        for entry in data.get("aws_iam_policy_document", []) if isinstance(data, dict) else []:
            if isinstance(entry, dict):
                for res_name, body in entry.items():
                    if isinstance(body, dict):
                        stmts = parse_policy(body.get("statement"))
                        if stmts:
                            principals.append(
                                Principal(
                                    name=f"data.aws_iam_policy_document.{res_name}",
                                    kind="policy",
                                    policies=[PolicyRef(name=res_name, statements=stmts)],
                                )
                            )
    if not principals:
        raise LoaderError(f"{label}: no aws_iam_policy / aws_iam_role_policy documents found")
    return principals


def load_path(path: str | os.PathLike) -> list[Principal]:
    """Load principals from a file or directory."""
    p = Path(path)
    if not p.exists():
        raise LoaderError(f"path does not exist: {p}")

    if p.is_dir():
        files = sorted(p.glob("*.json"))
        if not files:
            raise LoaderError(f"no *.json files found in {p}")
        principals: list[Principal] = []
        for f in files:
            principals.extend(_from_policy_document(_read(f), f.stem))
        return principals

    doc = _read(p)
    if not isinstance(doc, dict):
        raise LoaderError(f"{p}: expected a JSON object at the top level")

    if "UserDetailList" in doc or "RoleDetailList" in doc or "GroupDetailList" in doc:
        principals = _from_authorization_details(doc)
        if not principals:
            raise LoaderError(f"{p}: authorization details file contains no principals")
        return principals

    if "resource" in doc or "data" in doc:
        return _from_terraform(doc, p.stem)

    return _from_policy_document(doc, p.stem)
