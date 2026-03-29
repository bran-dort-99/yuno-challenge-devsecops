"""
Custom Checkov Policy: CDE RDS Encryption
Enforces PCI-DSS Req 3.4/3.5 — All RDS instances in the CDE must use
storage encryption with a customer-managed KMS key (not AWS default key).

Rationale: PCI-DSS requires that cardholder data encryption keys are managed
by the organization, not the cloud provider. AWS default encryption uses an
AWS-managed key which does not satisfy PCI-DSS key management requirements
for CDE databases storing tokenized card data.
"""

from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checkov.common.models.enums import CheckCategories, CheckResult


class CDERdsEncryptionWithCMK(BaseResourceCheck):
    def __init__(self):
        name = "Ensure CDE RDS instances use storage encryption with customer-managed KMS key"
        id = "CKV_YUNO_001"
        supported_resources = ["aws_db_instance"]
        categories = [CheckCategories.ENCRYPTION]
        super().__init__(name=name, id=id, categories=categories,
                         supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        # Check storage_encrypted is explicitly true
        storage_encrypted = conf.get("storage_encrypted", [False])
        if isinstance(storage_encrypted, list):
            storage_encrypted = storage_encrypted[0]

        if not storage_encrypted:
            return CheckResult.FAILED

        # Check kms_key_id is specified (not relying on AWS default key)
        kms_key_id = conf.get("kms_key_id", [None])
        if isinstance(kms_key_id, list):
            kms_key_id = kms_key_id[0]

        if not kms_key_id or kms_key_id in ["", None]:
            return CheckResult.FAILED

        return CheckResult.PASSED


check = CDERdsEncryptionWithCMK()
