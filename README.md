# escalens

**Offline AWS IAM privilege-escalation auditor.** Point it at policy JSON and it tells you which principals could grant themselves administrator, and exactly which permission combination lets them do it.

Zero dependencies. Zero AWS API calls. No credentials, ever.

```bash
pip install escalens
escalens account-authorization-details.json --fail-on critical
```

---

## Table of contents

- [Why this exists](#why-this-exists)
- [What it checks](#what-it-checks)
- [Installation](#installation)
- [Usage](#usage)
- [Getting the input](#getting-the-input)
- [Sample output](#sample-output)
- [How it works](#how-it-works)
- [Architecture](#architecture)
- [Severity model and scoring](#severity-model-and-scoring)
- [CI/CD integration](#cicd-integration)
- [Security use cases](#security-use-cases)
- [Design decisions](#design-decisions)
- [Limitations](#limitations)
- [Legal and ethical use](#legal-and-ethical-use)
- [License](#license)

---

## Why this exists

Inadequate identity and access management is the top cloud threat in 2026 surveys, and identity compromise features in the overwhelming majority of cloud intrusions. The pattern behind most of them is not a zero-day: it is a single role that holds `iam:PassRole` next to `lambda:CreateFunction`, or an `iam:CreatePolicyVersion` grant sitting quietly in a "developer" policy.

The two mature tools in this space, [Cloudsplaining](https://github.com/salesforce/cloudsplaining) and [PMapper](https://github.com/nccgroup/PMapper), are excellent and both expect live AWS credentials and a substantial dependency tree. That is the right shape for a scheduled account-wide sweep. It is the wrong shape for the three places teams actually need this check:

1. **In a pull request**, before a policy change merges. No reviewer reliably spots `iam:PassRole` in a 200-line Terraform diff.
2. **On a laptop or an air-gapped machine**, where a real account export already exists and the AWS CLI is not installed.
3. **In a locked-down CI runner**, where installing a Haskell binary, a JS toolchain or a boto3 stack is not permitted.

`escalens` covers those three cases with the Python standard library only. It is a complement to those tools, not a replacement: they can see a whole account's trust graph, `escalens` sees only the documents you hand it.

---

## What it checks

31 rules across four categories. Each rule maps to a documented escalation primitive and ships with its impact, its remediation, and where applicable its MITRE ATT&CK technique.

### Escalation primitives (`ESC-*`)

The core: permission combinations that let a principal grant itself more privilege.

| ID | Requires | Why it escalates |
|---|---|---|
| ESC-001 | `iam:CreatePolicyVersion` | Publishes `Action:*` into a policy the principal already holds. No new identity, no alert. |
| ESC-002 | `iam:SetDefaultPolicyVersion` | Activates a dormant permissive version. Policy *content* never changes, so diffs see nothing. |
| ESC-003 | `iam:CreateAccessKey` | Long-lived key for any user, including administrators. Survives password resets. |
| ESC-004 | `iam:CreateLoginProfile` | Console password on a privileged user that never had console access. |
| ESC-005 | `iam:UpdateLoginProfile` | Resets a privileged user's console password. |
| ESC-006 | `iam:AttachUserPolicy` | Attaches `AdministratorAccess` to a controlled user. |
| ESC-007 | `iam:AttachGroupPolicy` | Escalates through a group the attacker already belongs to. |
| ESC-008 | `iam:PutUserPolicy` | Inline admin policy, frequently missed by managed-policy tooling. |
| ESC-009 | `iam:PutGroupPolicy` | Inline admin policy inherited by every group member. |
| ESC-010 | `iam:AddUserToGroup` | Joins a privileged group with no policy write at all. |
| ESC-011 | `iam:PutRolePolicy` + `iam:PassRole` | Writes a trust-widening policy onto a powerful role, then passes it to a service. |
| ESC-012 | `iam:AttachRolePolicy` + `iam:PassRole` | Attaches admin to a role the principal can hand to compute. |
| ESC-013 | `iam:UpdateAssumeRolePolicy` + `sts:AssumeRole` | Rewrites the trust policy and assumes the role directly. |
| ESC-014 | `lambda:CreateFunction` + `iam:PassRole` | Code runs under a privileged execution role; the Lambda service is the caller of record. |
| ESC-015 | `lambda:CreateEventSourceMapping` + `lambda:CreateFunction` + `iam:PassRole` | Triggers a privileged function without `lambda:InvokeFunction`. |
| ESC-016 | `cloudformation:CreateStack` + `iam:PassRole` | A stack with a capability runs under a passed role and creates IAM resources. |
| ESC-017 | `glue:CreateDevEndpoint` + `iam:PassRole` | SSH into a development endpoint to read the role's temporary credentials. |
| ESC-018 | `ec2:RunInstances` + `iam:PassRole` | Launch an instance with a privileged profile, read IMDS credentials. |
| ESC-019 | `ssm:SendCommand` + `iam:PassRole` | Run shell commands on instances and harvest their profile credentials. |
| ESC-020 | `codestar:CreateProject` + `iam:PassRole` | Generated toolchain stores credentials for a passed role. |
| ESC-021 | `datapipeline:CreatePipeline` + `datapipeline:PutPipelineDefinition` + `iam:PassRole` | Pipeline step executes under a passed role. |
| ESC-022 | `sagemaker:CreateNotebookInstance` + `iam:PassRole` | Interactive notebook with a privileged role and a presigned URL. |

### Blast radius (`ESC-023`, `BRD-*`)

Breadth rather than a specific chain: unconstrained `sts:AssumeRole`, unconstrained `iam:PassRole` (the privilege multiplier that makes most `ESC-*` chains reachable), wildcard `iam:*`, and wildcard `s3:*` / `kms:*`.

### Effective administrator (`ADM-001`)

`Action:*` on `Resource:*`. When a principal is *already* an administrator, the report collapses the 20-odd primitives that are now moot into one line instead of burying the finding that matters.

### Explicit Deny suppression

If an explicit `Deny` neutralises a grant, the finding is reported as **suppressed**, not as active, and it no longer adds to the risk score. That is what makes an `--fail-on critical` gate usable: a team that has denied `iam:CreateAccessKey` account-wide does not get a red build for a stale allow they can no longer exercise.

A `Deny` that carries a `Condition` only blocks *some* calls. Conditions are not evaluated, so those are labelled `(conditional deny - verify)` and left for a human to confirm. The tool never claims a conditional deny is a real control.

---

## Installation

Requires Python 3.9+. No third-party packages.

```bash
# From PyPI-style source
pip install .

# Editable, for working on the rules
pip install -e .

# Or run it straight from a clone with no install at all
PYTHONPATH=src python3 -m escalens examples/policies/dangerous-team-role.json
```

Verify:

```bash
escalens --help
escalens --list-rules | head -20
```

---

## Usage

```bash
escalens <path> [options]
```

`<path>` accepts any of:

| Input | Example |
|---|---|
| Account authorization details export | `aws iam get-account-authorization-details > details.json` |
| A single IAM policy document | `{"Version": "2012-10-17", "Statement": [...]}` |
| A directory of `*.json` policy files | one policy per file, filename becomes the principal label |
| A Terraform plan/source JSON | `aws_iam_policy` / `aws_iam_role_policy` bodies are extracted |

### Options

| Flag | Effect |
|---|---|
| `--json` | Machine-readable report for CI, ticketing, SOAR ingestion |
| `-v`, `--verbose` | Show every piece of evidence per finding, not just the first |
| `--fail-on {none,low,medium,high,critical}` | Exit 1 when an active finding at or above this severity exists |
| `--min-score N` | Exit 1 when the risk score reaches N |
| `--no-color` | Disable ANSI colour (auto-disabled when piped) |
| `--quiet` | Suppress the report, keep the exit code |
| `--list-rules` | Print the full rule catalog and exit |

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Analysis completed, no gate tripped |
| 1 | Gate tripped (`--fail-on` / `--min-score`) |
| 2 | Input could not be read or parsed |
| 64 | Bad command-line usage |

Findings alone do not fail the build. You opt into that with a gate, so the tool is safe to add to an existing pipeline without turning every repo red on day one.

### Common invocations

```bash
# Human review of a single team policy
escalens policies/team-role.json -v

# Whole-account sweep, text report
escalens account-authorization-details.json

# CI gate: fail the PR if it introduces a critical escalation path
escalens account-authorization-details.json --fail-on critical --quiet

# Pipe JSON into jq to list only the principals that matter
escalens account-authorization-details.json --json \
  | jq -r '.findings[] | select(.active and .severity=="critical") | .principal' | sort -u
```

---

## Getting the input

`escalens` never calls AWS. You produce the file, on a machine that already has credentials, with a read-only audit role:

```bash
aws iam get-account-authorization-details \
  --filter User Role Group \
  --output json > /tmp/details.json

escalens /tmp/details.json
```

> The export contains no secrets, but it does describe your whole identity surface. Keep it out of git. The shipped `.gitignore` blocks the common filenames for these exports by default.

For a pull-request check, feed it the policy documents from the diff instead. Terraform works via `terraform show -json plan.out`, or by pointing at a directory of rendered policy JSON.

---

## Sample output

Real run against [`examples/policies/dangerous-team-role.json`](examples/policies/dangerous-team-role.json), a plausible "developer" policy that has quietly accumulated escalation rights:

```
==============================================================================
ESCALENS - AWS IAM privilege-escalation audit
generated 2026-11-03 03:41 UTC
==============================================================================

principals scanned : 1  (0 users, 0 roles, 0 groups)
active findings    : 6
risk score         : 100/100   grade F


--- dangerous-team-role [policy] ----------------------------------------------

  [CRITICAL] ESC-001  iam:CreatePolicyVersion grants full administrative control
    impact     : A principal with this permission can publish a new default version of any policy attached to an identity it controls, writing Action:* Resource:* into it. The escalation is silent: no new user, role or key is created, so most alerting never fires.
    evidence   : dangerous-team-role (EmergencyPolicyTweak): allows iam:CreatePolicyVersion on *
    fix        : Restrict iam:CreatePolicyVersion to a break-glass role, or add a policy-arn condition limiting it to non-privileged policies.
    mitre      : T1098.003

  [CRITICAL] ESC-006  iam:AttachUserPolicy attaches AdministratorAccess to a controlled user
    impact     : Directly attaches the AWS-managed AdministratorAccess policy to a user the attacker controls. Instant, complete account takeover.
    evidence   : dangerous-team-role (EmergencyPolicyTweak): allows iam:AttachUserPolicy on *
    fix        : Gate iam:AttachUserPolicy behind an approval workflow and deny attachment of policies with Action:*.
    mitre      : T1098.003

  [HIGH] ESC-014  Lambda execution-role bypass (CreateFunction + PassRole)
    impact     : Deploys a function whose execution role is an existing privileged role, then runs arbitrary AWS API calls as that role. The Lambda service, not the attacker, is the caller of record.
    evidence   : dangerous-team-role (DeployHelper): allows lambda:CreateFunction on *
    fix        : Constrain iam:PassRole to specific role ARNs per team, and deny lambda:CreateFunction outside the deployment pipeline roles.
    mitre      : T1648
```

And the hardened counterpart, [`examples/policies/hardened-role.json`](examples/policies/hardened-role.json), which holds `iam:PassRole` scoped to one role plus account-wide explicit denies:

```
principals scanned : 1  (0 users, 0 roles, 0 groups)
active findings    : 0
risk score         : 0/100   grade A+

No active privilege-escalation paths detected.
```

The two example files are a regression contract: the test suite asserts the dangerous one still trips rules and the hardened one still comes back clean.

---

## How it works

1. **Load.** `loader.py` reads a policy document, an authorization-details export, a directory, or Terraform JSON, and normalizes everything into `Principal` objects holding `PolicyRef`s. Every statement becomes a `Statement` with `Action` / `NotAction` / `Resource` / `NotResource` / `Condition` split into queryable fields.
2. **Match.** `actions.py` compiles each AWS glob (`*`, `?`, case-insensitive) once, with an LRU cache, and answers "does this pattern select this action?".
3. **Evaluate.** For each rule, `engine.py` evaluates each `AND` clause, where a clause is a set of `OR`-ed action patterns. A clause is satisfied only by an **Allow** statement whose resource set is not fully denied.
4. **Suppress.** Any resource covered by an explicit `Deny` for that action is removed from the grant. A grant whose every resource is denied becomes a suppressed finding.
5. **Collapse and score.** Full administrators get their moot primitives collapsed. Remaining active findings are weighted into a 0-100 score and an A+ to F grade.
6. **Render.** `report.py` produces a text report or JSON.

---

## Architecture

```
                        ┌───────────────────────────────────────┐
   policy JSON   ──────▶│  loader.py                            │
   authz export  ──────▶│  - authorization details              │
   directory/    ──────▶│  - single policy document             │
   terraform     ──────▶│  - directory of *.json                │
                        │  - terraform aws_iam_policy bodies    │
                        └───────────────┬───────────────────────┘
                                        │  Principal[] { policies[] { Statement[] } }
                                        ▼
                        ┌───────────────────────────────────────┐
                        │  engine.py                            │
                        │                                       │
                        │  for each rule in rules.CATALOG:      │
                        │    every AND clause satisfied?  ──────┼── no ──▶ skip
                        │    (clause = OR-ed action patterns)   │
                        │            │ yes                      │
                        │            ▼                          │
                        │    explicit Deny covers all resources │
                        │      ├─ no  ──▶ Finding(active)       │
                        │      └─ yes ──▶ Finding(suppressed)   │
                        └───────────────┬───────────────────────┘
                                        │
                    ┌───────────────────┴───────────────────┐
                    ▼                                       ▼
        ┌───────────────────────┐               ┌───────────────────────┐
        │ report.py (text)      │               │ report.py (JSON)      │
        │ severity-sorted,      │               │ summary + findings[]  │
        │ evidence + fix        │               │ for CI / SOAR / jq    │
        └───────────┬───────────┘               └───────────┬───────────┘
                    └───────────────────┬───────────────────┘
                                        ▼
                        ┌───────────────────────────────────────┐
                        │  cli.py                               │
                        │  --fail-on / --min-score  ──▶ 0 | 1   │
                        │  parse failure            ──▶ 2      │
                        └───────────────────────────────────────┘

   Data flow only. No network call, no AWS SDK, no credential use at any stage.
```

---

## Severity model and scoring

| Severity | Weight | Meaning |
|---|---|---|
| critical | 60 | One permission away from administrator. Fix before merge. |
| high | 20 | Needs a second permission the principal usually has, or a service to run code under a role. |
| medium | 8 | Breadth or reachability risk; matters in aggregate. |
| low | 2 | Advisory. |

Grade: `A+` 0, `A` 1-24, `B` 25-49, `C` 50-69, `D` 70-89, `F` 90-100. `ADM-001` pins the score to 100: if a principal holds `Action:*`, the account is compromised the moment that credential leaks, whatever else is true.

Suppressed findings score as zero. This is deliberate: the score should fall when a team adds a real control, otherwise nobody trusts the number.

---

## CI/CD integration

```yaml
# .github/workflows/iam-audit.yml
name: IAM escalation audit
on: [pull_request]

jobs:
  escalens:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.11" }
      - run: pip install .
      - name: Render policies changed in this PR
        run: ./scripts/render-policies.sh > /tmp/policies.json
      - name: Audit
        run: escalens /tmp/policies.json --fail-on critical
```

For an account-wide nightly sweep, store the authorization-details export as an encrypted artifact and run `escalens details.json --min-score 70`. Add `--json` and POST the payload to your ticketing or SIEM pipeline.

---

## Security use cases

1. **Pull-request gate on IAM changes.** Stop a `iam:PassRole` + `ec2:RunInstances` pair from merging, without a human memorising 31 primitives.
2. **Quarterly least-privilege review.** Run against the account export, hand each team its own findings, and track the score trend rather than arguing about intent.
3. **Post-incident scoping.** Given a compromised role, see what it could reach, which is usually more than what it did reach.
4. **Migration assurance.** Before and after an account restructure, diff the JSON reports to prove the new policy set is not more permissive.
5. **Terraform module review.** Audit a shared IAM module once, so every consumer inherits a checked policy instead of a copy-pasted one.
6. **Acquisition and audit evidence.** Produce a defensible, timestamped record of identity risk for an auditor who cannot be given console access.
7. **Teaching least privilege.** The `-v` output names the exact statement and the exact fix, which is more useful in a review comment than a severity badge.

---

## Design decisions

**Offline first.** No AWS SDK is a feature, not a shortcut. It means no credential handling, no `--profile` confusion, no accidental write to a production account, and it runs where the AWS CLI does not exist.

**Conditions are recorded, never evaluated.** Deciding whether `aws:MultiFactorAuthPresent` is true requires request context the tool does not have. Rather than guess, conditional denies are surfaced for review. A false "you are safe" is the one failure mode an audit tool cannot afford.

**Deny suppression is per-resource.** A grant is only fully suppressed when every resource it covers is denied. A `Deny` on one bucket does not silence a `Resource:*` allow; it narrows it.

**Full admins get collapsed.** Reporting twenty escalation paths for a principal that is already root trains people to ignore the output. The admin finding stays and explains why the rest are moot.

**Rules are data.** `rules.py` is a list of declarative objects with impact, remediation, and MITRE mapping. Adding a primitive is a data change, reviewable in a diff, with no engine surgery.

---

## Limitations

Stated plainly, because a security tool that oversells itself is worse than none:

- **Document-level only.** `escalens` reads the policies you give it. It does not resolve SCPs, permission boundaries, resource policies, session policies, or the trust graph across accounts. Cloudsplaining and PMapper are the right tools for that.
- **Conditions are not evaluated** (see above). A conditional deny is flagged, not trusted.
- **Known primitives only.** The catalog covers documented, publicly researched escalation paths. Novel or account-specific chains are out of scope.
- **Inline group membership is partial.** For an authorization-details export, a user's groups and the group's policies are both analysed, but permissions are not merged into a single effective set per user. Review group findings alongside user findings.
- **Heuristic severity weights.** The 60/20/8/2 weights are opinionated. Tune them to your environment; the point is the direction of travel, not the absolute number.
- **Not a substitute for Access Analyzer.** AWS IAM Access Analyzer finds unused and external access. This finds escalation combinations. Run both.

---

## Legal and ethical use

**Defensive and authorized use only.**

`escalens` is an audit tool. It reads policy documents you already possess, performs no network calls, executes no AWS API operations, and contains no exploitation code. It cannot attack anything.

Use it on infrastructure you own, or that you have explicit written authorization to assess. Analysing a third party's IAM configuration without permission may be unlawful in your jurisdiction regardless of the tool's intent. Findings may describe sensitive architecture: treat reports as confidential, keep exports out of version control, and follow your organization's disclosure process.

The rule catalog reproduces publicly documented AWS permission behaviour for defensive detection. It is published so defenders can fix these gaps, not as a playbook.

---

## License

MIT. See [LICENSE](LICENSE).
