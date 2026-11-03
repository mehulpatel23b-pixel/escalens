"""Tests for policy document parsing and statement matching."""

import json
import unittest

from escalens.documents import normalize_statement, parse_policy


class ParsePolicyTests(unittest.TestCase):
    def test_single_statement_dict(self):
        st = parse_policy({"Statement": {"Effect": "Allow", "Action": "s3:*", "Resource": "*"}})
        self.assertEqual(len(st), 1)
        self.assertTrue(st[0].is_allow)
        self.assertEqual(st[0].actions, ["s3:*"])

    def test_statement_list(self):
        doc = {"Statement": [
            {"Effect": "Allow", "Action": ["a:1"], "Resource": ["*"]},
            {"Effect": "Deny", "Action": "b:2", "Resource": "*"},
        ]}
        st = parse_policy(doc)
        self.assertEqual(len(st), 2)
        self.assertTrue(st[1].is_deny)

    def test_json_string_input(self):
        st = parse_policy(json.dumps({"Statement": [
            {"Effect": "Allow", "Action": "iam:*", "Resource": "*"}]}))
        self.assertEqual(st[0].actions, ["iam:*"])

    def test_empty_and_invalid(self):
        self.assertEqual(parse_policy(None), [])
        self.assertEqual(parse_policy({}), [])
        self.assertEqual(parse_policy({"Statement": "nonsense"}), [])
        self.assertEqual(parse_policy({"Statement": [None, 5]}), [])

    def test_effect_case_insensitive(self):
        st = normalize_statement({"Effect": "ALLOW", "Action": "a:b"})
        self.assertTrue(st.is_allow)


class StatementMatchTests(unittest.TestCase):
    def test_covers_action_wildcard(self):
        st = normalize_statement({"Effect": "Allow", "Action": "iam:Create*"})
        self.assertTrue(st.covers_action("iam:CreatePolicyVersion"))
        self.assertFalse(st.covers_action("iam:DeleteUser"))

    def test_not_action(self):
        st = normalize_statement({"Effect": "Allow", "NotAction": "s3:DeleteObject", "Resource": "*"})
        self.assertTrue(st.covers_action("ec2:DescribeInstances"))
        self.assertFalse(st.covers_action("s3:DeleteObject"))

    def test_resource_and_not_resource(self):
        st = normalize_statement({"Effect": "Allow", "Action": "s3:*",
                                  "Resource": "arn:aws:s3:::b/*"})
        self.assertTrue(st.covers_resource("arn:aws:s3:::b/x"))
        self.assertFalse(st.covers_resource("arn:aws:s3:::c/x"))
        self.assertFalse(st.is_wildcard_resource)

    def test_missing_resource_defaults_to_all(self):
        st = normalize_statement({"Effect": "Allow", "Action": "a:b"})
        self.assertTrue(st.covers_resource("anything"))
        self.assertEqual(st.resources, [])

    def test_sid_captured(self):
        st = normalize_statement({"Sid": "Test", "Effect": "Allow", "Action": "a:b"})
        self.assertEqual(st.sid, "Test")


if __name__ == "__main__":
    unittest.main()
