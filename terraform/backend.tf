# ============================================================
# Remote backend with encryption and locking.
# State files contain sensitive resource attributes (RDS endpoints,
# SG IDs, etc.) and MUST be encrypted and access-controlled.
# PCI-DSS Req 3: Protect stored data; Req 7: Least privilege access.
# ============================================================

terraform {
  backend "s3" {
    bucket         = "yuno-terraform-state-production"
    key            = "cde/sa-east-2/terraform.tfstate"
    region         = "sa-east-1"
    encrypt        = true
    kms_key_id     = "alias/terraform-state-key"
    dynamodb_table = "yuno-terraform-locks"

    # Enforce TLS for state access — PCI-DSS Req 4
    # skip_metadata_api_check = false (default, uses IMDSv2)
  }
}
