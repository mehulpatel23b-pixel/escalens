"""Catalog of known AWS IAM privilege-escalation primitives.

Each rule describes a *combination* of permissions that, when held together,
lets a principal grant itself (or another identity) more privilege than it
started with. Sources: Rhino Security Labs' IAM privesc research, AWS
documentation, and public cloud-incident post-mortems.

Rules are declarative and defensive: they describe what an auditor should look
for. Nothing here performs an API call or executes an attack.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Rule:
    """A privilege-escalation primitive.

    `requires` is a list of clauses joined with AND. Each clause is a list of
    action patterns joined with OR, so a single clause can express
    "iam:PutUserPolicy *or* iam:PutRolePolicy".
    """

    id: str
    title: str
    severity: str
    requires: tuple[tuple[str, ...], ...]
    impact: str
    remediation: str
    category: str = "escalation"
    reference: str = ""
    # When True at least one required grant must be scoped to a broad resource.
    needs_broad_resource: bool = False
    notes: str = ""
    mitre: str = ""
    tags: tuple[str, ...] = field(default_factory=tuple)
    # Overrides the severity-derived score contribution when set (0 = derive it).
    score_weight: int = 0


CATALOG: tuple[Rule, ...] = (
    Rule(
        id="ESC-001",
        title="iam:CreatePolicyVersion grants full administrative control",
        severity="critical",
        requires=(("iam:CreatePolicyVersion",),),
        impact=(
            "A principal with this permission can publish a new default version of any "
            "policy attached to an identity it controls, writing Action:* Resource:* "
            "into it. The escalation is silent: no new user, role or key is created, so "
            "most alerting never fires."
        ),
        remediation=(
            "Restrict iam:CreatePolicyVersion to a break-glass role, or add a "
            "policy-arn condition limiting it to non-privileged policies."
        ),
        reference="https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/",
        mitre="T1098.003",
    ),
    Rule(
        id="ESC-002",
        title="iam:SetDefaultPolicyVersion activates a dormant permissive version",
        severity="critical",
        requires=(("iam:SetDefaultPolicyVersion",),),
        impact=(
            "An attacker flips the default version of an existing managed policy to an "
            "older, more permissive one. No policy content changes, so diff-based review "
            "sees nothing."
        ),
        remediation=(
            "Deny iam:SetDefaultPolicyVersion outside a privileged pipeline role and "
            "prune stale policy versions on a schedule."
        ),
        mitre="T1098.003",
    ),
    Rule(
        id="ESC-003",
        title="iam:CreateAccessKey mints persistent credentials for another identity",
        severity="critical",
        requires=(("iam:CreateAccessKey",),),
        impact=(
            "Creates a long-lived access key for any user the principal can name, "
            "including administrators. The key survives password resets and is invisible "
            "in console-only reviews."
        ),
        remediation=(
            "Permit iam:CreateAccessKey only for self-service with an "
            "iam:ResourceTag condition, and alert on keys created for other principals."
        ),
        mitre="T1098.001",
    ),
    Rule(
        id="ESC-004",
        title="iam:CreateLoginProfile sets a console password on another identity",
        severity="critical",
        requires=(("iam:CreateLoginProfile",),),
        impact=(
            "Attaches a fresh console password to an existing privileged user that has "
            "never had console access, giving interactive administrator login."
        ),
        remediation="Remove iam:CreateLoginProfile from all non-identity-team roles.",
        mitre="T1098.001",
    ),
    Rule(
        id="ESC-005",
        title="iam:UpdateLoginProfile resets another identity's console password",
        severity="critical",
        requires=(("iam:UpdateLoginProfile",),),
        impact=(
            "Overwrites the console password of a privileged user, locking out the "
            "legitimate owner while the attacker logs in."
        ),
        remediation="Remove iam:UpdateLoginProfile from all non-identity-team roles.",
        mitre="T1098.001",
    ),
    Rule(
        id="ESC-006",
        title="iam:AttachUserPolicy attaches AdministratorAccess to a controlled user",
        severity="critical",
        requires=(("iam:AttachUserPolicy",),),
        impact=(
            "Directly attaches the AWS-managed AdministratorAccess policy to a user the "
            "attacker controls. Instant, complete account takeover."
        ),
        remediation=(
            "Gate iam:AttachUserPolicy behind an approval workflow and deny attachment of "
            "policies with Action:*."
        ),
        mitre="T1098.003",
    ),
    Rule(
        id="ESC-007",
        title="iam:AttachGroupPolicy escalates via group membership",
        severity="critical",
        requires=(("iam:AttachGroupPolicy",),),
        impact=(
            "Attaches a permissive managed policy to a group the attacker already belongs "
            "to, inheriting administrator rights with no per-user change to review."
        ),
        remediation="Restrict iam:AttachGroupPolicy to the identity platform team.",
        mitre="T1098.003",
    ),
    Rule(
        id="ESC-008",
        title="iam:PutUserPolicy writes an inline admin policy onto a user",
        severity="critical",
        requires=(("iam:PutUserPolicy",),),
        impact=(
            "Inline policies bypass managed-policy guardrails and are frequently excluded "
            "from policy-diff tooling. One call yields Action:* Resource:*."
        ),
        remediation=(
            "Deny iam:PutUserPolicy account-wide and standardize on managed policies or "
            "permission sets."
        ),
        mitre="T1098.003",
    ),
    Rule(
        id="ESC-009",
        title="iam:PutGroupPolicy writes an inline admin policy onto a group",
        severity="high",
        requires=(("iam:PutGroupPolicy",),),
        impact=(
            "A group the principal belongs to silently gains administrator permissions, "
            "affecting every member."
        ),
        remediation="Deny iam:PutGroupPolicy account-wide.",
        mitre="T1098.003",
    ),
    Rule(
        id="ESC-010",
        title="iam:AddUserToGroup joins a privileged group",
        severity="high",
        requires=(("iam:AddUserToGroup",),),
        impact=(
            "Adds a controlled user to an existing administrative group. Requires no "
            "policy write at all, which is why it survives policy-content reviews."
        ),
        remediation=(
            "Alert on every iam:AddUserToGroup call and restrict it to administrators of "
            "the identity store."
        ),
        mitre="T1098.007",
    ),
    Rule(
        id="ESC-011",
        title="iam:PutRolePolicy + iam:PassRole hijacks a privileged role",
        severity="critical",
        requires=(("iam:PutRolePolicy",), ("iam:PassRole",)),
        impact=(
            "Writes an inline trust-widening policy onto a powerful role, then passes it "
            "to a service that runs attacker code under that role."
        ),
        remediation=(
            "Remove iam:PutRolePolicy from service roles and constrain iam:PassRole with "
            "iam:PassedToService conditions."
        ),
        mitre="T1098.003",
    ),
    Rule(
        id="ESC-012",
        title="iam:AttachRolePolicy + iam:PassRole attaches admin to a used role",
        severity="critical",
        requires=(("iam:AttachRolePolicy",), ("iam:PassRole",)),
        impact=(
            "Attaches AdministratorAccess to a role the principal can pass into a compute "
            "service, then assumes it indirectly."
        ),
        remediation="Require change approval for iam:AttachRolePolicy on privileged roles.",
        mitre="T1098.003",
    ),
    Rule(
        id="ESC-013",
        title="iam:UpdateAssumeRolePolicy widens a role's trust to the attacker",
        severity="high",
        requires=(("iam:UpdateAssumeRolePolicy",), ("sts:AssumeRole",)),
        impact=(
            "Rewrites the trust policy so the attacker's principal can assume an existing "
            "privileged role. No new identity is created and no permission is granted "
            "directly."
        ),
        remediation=(
            "Deny iam:UpdateAssumeRolePolicy except from the identity pipeline, and alert "
            "on trust-policy diffs."
        ),
        mitre="T1098.003",
    ),
    Rule(
        id="ESC-014",
        title="Lambda execution-role bypass (CreateFunction + PassRole)",
        severity="high",
        requires=(("lambda:CreateFunction",), ("iam:PassRole",)),
        impact=(
            "Deploys a function whose execution role is an existing privileged role, then "
            "runs arbitrary AWS API calls as that role. The Lambda service, not the "
            "attacker, is the caller of record."
        ),
        remediation=(
            "Constrain iam:PassRole to specific role ARNs per team, and deny "
            "lambda:CreateFunction outside the deployment pipeline roles."
        ),
        reference="https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/",
        mitre="T1648",
    ),
    Rule(
        id="ESC-015",
        title="Lambda event-source mapping bypass (PassRole + CreateFunction)",
        severity="high",
        requires=(
            ("lambda:CreateEventSourceMapping",),
            ("lambda:CreateFunction",),
            ("iam:PassRole",),
        ),
        impact=(
            "Points an event source at an existing privileged function, triggering it "
            "without needing lambda:InvokeFunction."
        ),
        remediation="Deny lambda:CreateEventSourceMapping outside platform roles.",
        mitre="T1648",
    ),
    Rule(
        id="ESC-016",
        title="CloudFormation stack creation with a privileged service role",
        severity="high",
        requires=(("cloudformation:CreateStack",), ("iam:PassRole",)),
        impact=(
            "Submits a template with a Capability that runs under a passed role, creating "
            "IAM users or keys with administrator access."
        ),
        remediation=(
            "Require cloudformation:CreateStack to use a constrained service role and "
            "review templates that reference IAM resources."
        ),
        mitre="T1674",
    ),
    Rule(
        id="ESC-017",
        title="Glue dev endpoint SSH path to role credentials",
        severity="high",
        requires=(("glue:CreateDevEndpoint",), ("iam:PassRole",)),
        impact=(
            "Creates a Glue development endpoint running under a privileged role, then "
            "SSHes in to read the role's temporary credentials from the instance."
        ),
        remediation=(
            "Deny glue:CreateDevEndpoint outside data-platform accounts and constrain "
            "iam:PassRole for glue.amazonaws.com."
        ),
        mitre="T1078.004",
    ),
    Rule(
        id="ESC-018",
        title="EC2 instance-profile bypass (RunInstances + PassRole)",
        severity="high",
        requires=(("ec2:RunInstances",), ("iam:PassRole",)),
        impact=(
            "Launches an instance with an existing privileged instance profile and reads "
            "its temporary credentials from the metadata service."
        ),
        remediation=(
            "Constrain iam:PassRole to ec2.amazonaws.com with explicit role ARNs, and "
            "require IMDSv2."
        ),
        mitre="T1552.005",
    ),
    Rule(
        id="ESC-019",
        title="SSM SendCommand runs code on instances with privileged profiles",
        severity="high",
        requires=(("ssm:SendCommand",), ("iam:PassRole",)),
        impact=(
            "Executes shell commands on managed instances, harvesting the credentials of "
            "whatever instance profile they hold."
        ),
        remediation="Restrict ssm:SendCommand to fleet-management roles.",
        mitre="T1059.004",
    ),
    Rule(
        id="ESC-020",
        title="CodeStar project creation leaks a privileged role's credentials",
        severity="high",
        requires=(("codestar:CreateProject",), ("iam:PassRole",)),
        impact=(
            "Creates a CodeStar project bound to a passed role; the generated toolchain "
            "stores credentials the attacker can retrieve."
        ),
        remediation="Deny codestar:CreateProject in accounts without an active CodeStar footprint.",
        mitre="T1078.004",
    ),
    Rule(
        id="ESC-021",
        title="Data-pipeline creation executes under a privileged role",
        severity="medium",
        requires=(
            ("datapipeline:CreatePipeline",),
            ("datapipeline:PutPipelineDefinition",),
            ("iam:PassRole",),
        ),
        impact=(
            "Defines a pipeline step that runs arbitrary commands in an EC2 resource "
            "carrying the passed role's credentials."
        ),
        remediation="Retire unused AWS Data Pipeline usage; deny creation account-wide.",
        mitre="T1078.004",
    ),
    Rule(
        id="ESC-022",
        title="SageMaker notebook grants interactive access to a privileged role",
        severity="high",
        requires=(("sagemaker:CreateNotebookInstance",), ("iam:PassRole",)),
        impact=(
            "Provisions a notebook with a privileged execution role and returns a "
            "presigned URL, giving an interactive shell with that role's permissions."
        ),
        remediation="Constrain iam:PassRole for sagemaker.amazonaws.com to scoped roles.",
        mitre="T1078.004",
    ),
    Rule(
        id="ESC-023",
        title="sts:AssumeRole on a wildcard resource allows trust-graph pivoting",
        severity="medium",
        requires=(("sts:AssumeRole",),),
        impact=(
            "With Resource:* the principal may assume any role whose trust policy accepts "
            "it, turning a small foothold into whatever the trust graph reaches."
        ),
        remediation="Scope sts:AssumeRole to explicit role ARNs.",
        category="blast_radius",
        needs_broad_resource=True,
        mitre="T1550.001",
    ),
    Rule(
        id="ADM-001",
        title="Effective administrator (Action:* on Resource:*)",
        severity="critical",
        requires=(("*",),),
        impact=(
            "The policy grants every action on every resource. Any credential using it is "
            "an account-takeover primitive on its own."
        ),
        remediation="Replace with scoped policies; reserve full admin for break-glass roles.",
        category="breadth",
        needs_broad_resource=True,
        score_weight=100,
    ),
    Rule(
        id="BRD-001",
        title="Unconstrained iam:PassRole is a privilege multiplier",
        severity="high",
        requires=(("iam:PassRole",),),
        impact=(
            "iam:PassRole with Resource:* lets the principal hand any role, including "
            "administrator roles, to any compatible service. On its own it grants nothing; "
            "combined with a compute-create permission it grants everything."
        ),
        remediation=(
            "Scope iam:PassRole to explicit role ARNs and add iam:PassedToService "
            "conditions."
        ),
        category="bloat",
        needs_broad_resource=True,
        mitre="T1548",
    ),
    Rule(
        id="BRD-002",
        title="Wildcard action grant on a sensitive service",
        severity="medium",
        requires=(("iam:*",),),
        impact="Full control of the IAM service, equivalent to account takeover.",
        remediation="Enumerate the specific IAM actions the workload actually needs.",
        category="bloat",
    ),
    Rule(
        id="BRD-003",
        title="Wildcard action grant on S3 or KMS",
        severity="medium",
        requires=(("s3:*", "kms:*"),),
        impact=(
            "Unrestricted data-plane and key access: read or destroy every bucket the "
            "principal can reach, or disable the keys protecting them."
        ),
        remediation="Scope to explicit bucket ARNs and split key administration away from data access.",
        category="bloat",
    ),
)

BY_ID: dict[str, Rule] = {rule.id: rule for rule in CATALOG}
CATEGORIES = ("escalation", "blast_radius", "breadth", "bloat")
