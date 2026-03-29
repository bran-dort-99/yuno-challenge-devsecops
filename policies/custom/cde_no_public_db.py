"""
Custom Checkov Policy: CDE No Publicly Accessible Databases
Enforces PCI-DSS Req 1.3 — No RDS instance in the CDE may be publicly accessible.

Rationale: A publicly accessible RDS instance containing tokenized card data
is directly reachable from the internet. Even with strong authentication, this
violates PCI-DSS network segmentation requirements and exposes the database to
brute force attacks, SQL injection via direct connections, and potential
exploitation of database engine vulnerabilities without the protection of
application-layer controls.
"""

from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checkov.common.models.enums import CheckCategories, CheckResult


class CDENoPublicDB(BaseResourceCheck):
    def __init__(self):
        name = "Ensure CDE RDS instances are not publicly accessible (PCI-DSS Req 1.3)"
        id = "CKV_YUNO_004"
        supported_resources = ["aws_db_instance"]
        categories = [CheckCategories.NETWORKING]
        super().__init__(name=name, id=id, categories=categories,
                         supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        publicly_accessible = conf.get("publicly_accessible", [False])
        if isinstance(publicly_accessible, list):
            publicly_accessible = publicly_accessible[0]

        if publicly_accessible is True:
            return CheckResult.FAILED

        return CheckResult.PASSED


check = CDENoPublicDB()
