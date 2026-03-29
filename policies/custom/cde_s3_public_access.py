"""
Custom Checkov Policy: CDE S3 BlockPublicAccess
Enforces PCI-DSS Req 3.4 — All S3 buckets in the CDE must have all four
BlockPublicAccess flags set to true. No exceptions.

Rationale: A single misconfigured S3 bucket holding cardholder data backups
or encrypted card vaults can expose millions of card records. The 2017 Capital
One breach demonstrated that S3 misconfigurations in payment environments cause
catastrophic data exposure. This policy ensures all four flags are explicitly
true — not just some of them.
"""

from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checkov.common.models.enums import CheckCategories, CheckResult


class CDES3FullPublicAccessBlock(BaseResourceCheck):
    def __init__(self):
        name = "Ensure CDE S3 buckets have ALL four BlockPublicAccess flags enabled"
        id = "CKV_YUNO_002"
        supported_resources = ["aws_s3_bucket_public_access_block"]
        categories = [CheckCategories.GENERAL_SECURITY]
        super().__init__(name=name, id=id, categories=categories,
                         supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        required_flags = [
            "block_public_acls",
            "block_public_policy",
            "ignore_public_acls",
            "restrict_public_buckets"
        ]

        for flag in required_flags:
            value = conf.get(flag, [False])
            if isinstance(value, list):
                value = value[0]
            if value is not True:
                return CheckResult.FAILED

        return CheckResult.PASSED


check = CDES3FullPublicAccessBlock()
