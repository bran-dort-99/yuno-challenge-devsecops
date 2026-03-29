# ============================================================
# Yuno CDE — Provider Configuration
# No static credentials. Authentication via IAM role, environment
# variables, or AWS CLI profile — never hardcoded keys.
# PCI-DSS Req 8: No shared or embedded credentials in code.
# ============================================================

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project            = "yuno-cde"
      Environment        = var.environment
      ManagedBy          = "terraform"
      PCI_Scope          = "In-Scope"
      DataClassification = "Confidential"
      Owner              = "platform-security"
    }
  }
}
