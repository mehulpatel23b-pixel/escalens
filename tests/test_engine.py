"""Tests for the escalation engine: rule matching, deny suppression, scoring."""

import unittest

from escalens.documents import parse_policy
from escalens.engine import PolicyRef, Principal, analyze, evaluate_principal


def principal(policy_doc, name="test-principal", kind="user"):
    return Principal(
        name=name,
        kind=kind,
        policies=[PolicyRef(name=f"{name}-policy", statements=parse_policy(policy_doc))],
    )


def allow(*actions, resource="*"):
    return {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": list(actions), "Resource": resource}],
    }


def rule_ids(p):
    return {f.rule.id for f in evaluate_principal(p) if f.active}


class SingleActionRuleTests(unittest.TestCase):
    def test_create_policy_version_is_critical(self):
        findings = evaluate_principal(principal(allow("iam:CreatePolicyVersion")))
        ids = {f.rule.id for f in findings if f.active}
        self.assertIn("ESC-001", ids)
        critical = [f for f in findings if f.rule.id == "ESC-001"][0]
        self.assertEqual(critical.severity, "critical")

    def test_create_access_key(self):
        self.assertIn("ESC-003", rule_ids(principal(allow("iam:CreateAccessKey"))))

    def test_add_user_to_group(self):
        self.assertIn("ESC-010", rule_ids(principal(allow("iam:AddUserToGroup"))))

    def test_benign_policy_triggers_nothing(self):
        p = principal(allow("s3:GetObject", "s3:ListBucket",
                            resource="arn:aws:s3:::bucket/*"))
        self.assertEqual(rule_ids(p), set())

    def test_wildcard_action_triggers_admin(self):
        self.assertIn("ADM-001", rule_ids(principal(allow("*"))))


class CombinationRuleTests(unittest.TestCase):
    def test_pass_role_alone_is_not_lambda_escalation(self):
        ids = rule_ids(principal(allow("iam:PassRole")))
        self.assertNotIn("ESC-014", ids)
        self.assertIn("BRD-001", ids)

    def test_lambda_plus_pass_role_escalates(self):
        ids = rule_ids(principal(allow("lambda:CreateFunction", "iam:PassRole")))
        self.assertIn("ESC-014", ids)

    def test_ec2_plus_pass_role_escalates(self):
        ids = rule_ids(principal(allow("ec2:RunInstances", "iam:PassRole")))
        self.assertIn("ESC-018", ids)

    def test_cloudformation_plus_pass_role(self):
        ids = rule_ids(principal(allow("cloudformation:CreateStack", "iam:PassRole")))
        self.assertIn("ESC-016", ids)

    def test_multi_clause_glue(self):
        ids = rule_ids(principal(allow("glue:CreateDevEndpoint", "iam:PassRole")))
        self.assertIn("ESC-017", ids)

    def test_pass_role_scoped_to_role_does_not_flag_broad_passrole(self):
        doc = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "iam:PassRole",
                "Resource": "arn:aws:iam::123456789012:role/specific",
            }],
        }
        self.assertNotIn("BRD-001", rule_ids(principal(doc)))

    def test_full_admin_marks_other_primitives_moot(self):
        result = analyze([principal(allow("*"), name="admin")])
        active_ids = [f.rule.id for f in result.active]
        self.assertEqual(active_ids, ["ADM-001"])
        self.assertTrue(any(f.subsumed for f in result.findings))


class DenyTests(unittest.TestCase):
    def test_explicit_deny_suppresses_finding(self):
        doc = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "iam:CreatePolicyVersion", "Resource": "*"},
                {"Effect": "Deny", "Action": "iam:CreatePolicyVersion", "Resource": "*"},
            ],
        }
        findings = evaluate_principal(principal(doc))
        target = [f for f in findings if f.rule.id == "ESC-001"]
        self.assertTrue(target, "finding should still be reported")
        self.assertFalse(target[0].active)
        self.assertIn("test-principal-policy", target[0].suppressed_by)

    def test_deny_on_other_action_does_not_suppress(self):
        doc = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "iam:CreateAccessKey", "Resource": "*"},
                {"Effect": "Deny", "Action": "s3:DeleteObject", "Resource": "*"},
            ],
        }
        self.assertIn("ESC-003", rule_ids(principal(doc)))

    def test_conditional_deny_is_flagged_for_review(self):
        doc = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "iam:CreateAccessKey", "Resource": "*"},
                {"Effect": "Deny", "Action": "iam:CreateAccessKey", "Resource": "*",
                 "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "false"}}},
            ],
        }
        findings = [f for f in evaluate_principal(principal(doc)) if f.rule.id == "ESC-003"]
        self.assertFalse(findings[0].active)
        self.assertTrue(any("conditional deny" in s for s in findings[0].suppressed_by))

    def test_multi_statement_deny_still_suppresses(self):
        doc = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"},
                {"Effect": "Allow", "Action": "lambda:CreateFunction", "Resource": "*"},
                {"Effect": "Deny", "Action": "iam:PassRole", "Resource": "*"},
            ],
        }
        ids = rule_ids(principal(doc))
        self.assertNotIn("ESC-014", ids)


class ScoringTests(unittest.TestCase):
    def test_clean_is_a_plus(self):
        result = analyze([principal(allow("s3:GetObject"))])
        self.assertEqual(result.score(), 0)
        self.assertEqual(result.grade(), "A+")

    def test_one_critical_is_high_risk(self):
        result = analyze([principal(allow("iam:CreatePolicyVersion"))])
        self.assertGreaterEqual(result.score(), 40)

    def test_admin_scores_f(self):
        result = analyze([principal(allow("*"))])
        self.assertEqual(result.grade(), "F")

    def test_suppressed_findings_score_lower(self):
        clean = analyze([principal(allow("iam:CreatePolicyVersion"))])
        denied_doc = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "iam:CreatePolicyVersion", "Resource": "*"},
                {"Effect": "Deny", "Action": "iam:CreatePolicyVersion", "Resource": "*"},
            ],
        }
        denied = analyze([principal(denied_doc)])
        self.assertLess(denied.score(), clean.score())

    def test_multiple_principals_are_all_scanned(self):
        result = analyze([
            principal(allow("iam:CreateAccessKey"), name="a"),
            principal(allow("s3:GetObject"), name="b"),
        ])
        self.assertEqual(len(result.principals), 2)
        self.assertEqual({f.principal.name for f in result.active}, {"a"})


class RuleCatalogTests(unittest.TestCase):
    def test_catalog_ids_unique(self):
        from escalens.rules import CATALOG
        ids = [r.id for r in CATALOG]
        self.assertEqual(len(ids), len(set(ids)))

    def test_every_rule_has_remediation_and_impact(self):
        from escalens.rules import CATALOG
        for rule in CATALOG:
            self.assertTrue(rule.remediation, rule.id)
            self.assertTrue(rule.impact, rule.id)
            self.assertTrue(rule.requires, rule.id)

    def test_every_rule_is_reachable(self):
        """Each rule must fire on at least one synthetic policy."""
        from escalens.rules import CATALOG
        for rule in CATALOG:
            actions = []
            for clause in rule.requires:
                actions.append(clause[0])
            doc = allow(*actions)
            ids = rule_ids(principal(doc))
            self.assertIn(rule.id, ids, f"{rule.id} never matched {actions}")

    def test_severities_are_known(self):
        from escalens.rules import CATALOG
        for rule in CATALOG:
            self.assertIn(rule.severity, {"critical", "high", "medium", "low"}, rule.id)


if __name__ == "__main__":
    unittest.main()
