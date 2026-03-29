"""
Custom Checkov Policy: CDE No Wildcard IAM Permissions
Enforces PCI-DSS Req 7.2 — No IAM policy in the CDE may use both
Action: "*" and Resource: "*" simultaneously.

Rationale: Wildcard IAM policies in a CDE are the #1 blast radius amplifier.
If an attacker compromises an EC2 instance or ECS task with Action:*/Resource:*,
they have full administrative access to the entire AWS account — including the
ability to exfiltrate cardholder data, modify security groups, disable logging,
and create backdoor IAM users. This single misconfiguration can turn a container
escape into a full account takeover.
"""

import json
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checkov.common.models.enums import CheckCategories, CheckResult


class CDENoWildcardIAM(BaseResourceCheck):
    def __init__(self):
        name = "Ensure CDE IAM policies do not use Action:* with Resource:* (least privilege)"
        id = "CKV_YUNO_003"
        supported_resources = ["aws_iam_role_policy", "aws_iam_policy"]
        categories = [CheckCategories.IAM]
        super().__init__(name=name, id=id, categories=categories,
                         supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        policy = conf.get("policy", [{}])
        if isinstance(policy, list):
            policy = policy[0]

        # Policy may be a string (JSON) or already parsed
        if isinstance(policy, str):
            try:
                policy = json.loads(policy)
            except (json.JSONDecodeError, TypeError):
                return CheckResult.UNKNOWN

        statements = policy.get("Statement", [])
        if not isinstance(statements, list):
            statements = [statements]

        for statement in statements:
            if statement.get("Effect") != "Allow":
                continue

            actions = statement.get("Action", [])
            resources = statement.get("Resource", [])

            if isinstance(actions, str):
                actions = [actions]
            if isinstance(resources, str):
                resources = [resources]

            has_wildcard_action = "*" in actions
            has_wildcard_resource = "*" in resources

            # Block if BOTH action and resource are wildcard
            if has_wildcard_action and has_wildcard_resource:
                return CheckResult.FAILED

        return CheckResult.PASSED


check = CDENoWildcardIAM()
