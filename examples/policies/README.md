# Example policies

Nothing here is a real account, a real key, or a real secret. These are synthetic
policy documents used to demonstrate what `escalens` catches and to keep the test
suite honest.

| File | What it represents |
|---|---|
| `dangerous-team-role.json` | A "developer" policy that has quietly accumulated enough permissions to escalate to administrator. Trips many rules at once. |
| `hardened-role.json` | A least-privilege role with explicit denies. Should report zero active findings. |
| `account-details.json` | A trimmed `aws iam get-account-authorization-details` export with several users, roles and a group. |
