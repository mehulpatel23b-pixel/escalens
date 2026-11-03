"""Tests for AWS wildcard pattern matching."""

import unittest

from escalens.actions import as_list, matches, service_of


class MatchesTests(unittest.TestCase):
    def test_exact(self):
        self.assertTrue(matches("s3:GetObject", "s3:GetObject"))

    def test_star_suffix(self):
        self.assertTrue(matches("s3:Get*", "s3:GetObject"))
        self.assertFalse(matches("s3:Get*", "s3:PutObject"))

    def test_bare_star_matches_everything(self):
        self.assertTrue(matches("*", "iam:CreateUser"))

    def test_question_mark(self):
        self.assertTrue(matches("iam:?reateUser", "iam:CreateUser"))
        self.assertFalse(matches("iam:?reateUser", "iam:CreateeUser"))

    def test_case_insensitive(self):
        self.assertTrue(matches("S3:getobject", "s3:GetObject"))

    def test_dot_is_literal(self):
        self.assertFalse(matches("s3:GetObject", "s3:GetObjectX"))
        self.assertTrue(matches("arn:aws:s3:::bucket/*", "arn:aws:s3:::bucket/key"))

    def test_no_partial_prefix_match(self):
        self.assertFalse(matches("iam:CreateUser", "iam:CreateUserX"))


class HelperTests(unittest.TestCase):
    def test_service_of(self):
        self.assertEqual(service_of("s3:GetObject"), "s3")
        self.assertEqual(service_of("IAM:CreateUser"), "iam")

    def test_as_list_normalizes(self):
        self.assertEqual(as_list(None), [])
        self.assertEqual(as_list("a"), ["a"])
        self.assertEqual(as_list(["a", "b"]), ["a", "b"])


if __name__ == "__main__":
    unittest.main()
