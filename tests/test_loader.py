"""Tests for offline input loading."""

import json
import os
import tempfile
import unittest
from pathlib import Path

from escalens.loader import LoaderError, load_path

HERE = Path(__file__).resolve().parent.parent
EXAMPLES = HERE / "examples" / "policies"


class ExampleFileTests(unittest.TestCase):
    def test_loads_single_policy_file(self):
        principals = load_path(EXAMPLES / "dangerous-team-role.json")
        self.assertEqual(len(principals), 1)
        self.assertTrue(principals[0].policies[0].statements)

    def test_loads_authorization_details_export(self):
        principals = load_path(EXAMPLES / "account-details.json")
        kinds = {p.kind for p in principals}
        self.assertEqual(kinds, {"user", "role", "group"})
        self.assertEqual(len(principals), 5)

    def test_authorization_details_keeps_attached_policies(self):
        principals = {p.name: p for p in load_path(EXAMPLES / "account-details.json")}
        self.assertGreater(len(principals["intern-sandbox"].policies), 1)
        self.assertEqual(principals["intern-sandbox"].groups, ["developers"])

    def test_loads_directory(self):
        tmp = Path(tempfile.mkdtemp())
        for name in ("a", "b"):
            (tmp / f"{name}.json").write_text(json.dumps({
                "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]
            }))
        principals = load_path(tmp)
        self.assertEqual({p.name for p in principals}, {"a", "b"})


class ErrorTests(unittest.TestCase):
    def test_missing_path(self):
        with self.assertRaises(LoaderError):
            load_path("/nonexistent/policy.json")

    def test_invalid_json(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            fh.write("{not json")
            path = fh.name
        try:
            with self.assertRaises(LoaderError) as ctx:
                load_path(path)
            self.assertIn("not valid JSON", str(ctx.exception))
        finally:
            os.unlink(path)

    def test_json_without_statements(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump({"hello": "world"}, fh)
            path = fh.name
        try:
            with self.assertRaises(LoaderError):
                load_path(path)
        finally:
            os.unlink(path)

    def test_empty_directory(self):
        with self.assertRaises(LoaderError):
            load_path(tempfile.mkdtemp())


class TerraformTests(unittest.TestCase):
    def test_extracts_terraform_iam_policy(self):
        tf = {
            "resource": {
                "aws_iam_policy": {
                    "deployer": {
                        "name": "deployer",
                        "policy": json.dumps({
                            "Version": "2012-10-17",
                            "Statement": [
                                {"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"},
                                {"Effect": "Allow", "Action": "ec2:RunInstances", "Resource": "*"},
                            ],
                        }),
                    }
                }
            }
        }
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump(tf, fh)
            path = fh.name
        try:
            principals = load_path(path)
            self.assertEqual(len(principals), 1)
            self.assertIn("aws_iam_policy.deployer", principals[0].name)
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
