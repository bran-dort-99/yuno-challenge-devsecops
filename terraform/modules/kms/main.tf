# ============================================================
# Module: kms
# Customer-managed KMS keys for CDE encryption at rest.
# PCI-DSS Req 3.5: Protect encryption keys used to secure cardholder data.
# ============================================================

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# ── RDS Encryption Key ────────────────────────────────────────

resource "aws_kms_key" "rds" {
  description             = "CMK for Yuno CDE RDS encryption at rest"
  deletion_window_in_days = 30
  enable_key_rotation     = true # PCI-DSS Req 3.6.4: Rotate keys periodically
  multi_region            = false

  policy = jsonencode({
    Version = "2012-10-17"
    Id      = "yuno-cde-rds-key-policy"
    Statement = [
      {
        Sid       = "AllowRootAccountFullAccess"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid    = "AllowRDSServiceAccess"
        Effect = "Allow"
        Principal = { Service = "rds.amazonaws.com" }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey",
          "kms:CreateGrant"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "kms:ViaService" = "rds.${data.aws_region.current.name}.amazonaws.com"
          }
        }
      }
    ]
  })

  tags = {
    Name    = "${var.project}-${var.environment}-rds-cmk"
    Purpose = "RDS encryption at rest"
  }
}

resource "aws_kms_alias" "rds" {
  name          = "alias/${var.project}-${var.environment}-rds"
  target_key_id = aws_kms_key.rds.key_id
}

# ── S3 Encryption Key ────────────────────────────────────────

resource "aws_kms_key" "s3" {
  description             = "CMK for Yuno CDE S3 bucket encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Id      = "yuno-cde-s3-key-policy"
    Statement = [
      {
        Sid       = "AllowRootAccountFullAccess"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid    = "AllowS3ServiceAccess"
        Effect = "Allow"
        Principal = { Service = "s3.amazonaws.com" }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
      }
    ]
  })

  tags = {
    Name    = "${var.project}-${var.environment}-s3-cmk"
    Purpose = "S3 encryption at rest"
  }
}

resource "aws_kms_alias" "s3" {
  name          = "alias/${var.project}-${var.environment}-s3"
  target_key_id = aws_kms_key.s3.key_id
}

# ── CloudTrail / Logs Encryption Key ─────────────────────────

resource "aws_kms_key" "logs" {
  description             = "CMK for Yuno CDE CloudTrail and log encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Id      = "yuno-cde-logs-key-policy"
    Statement = [
      {
        Sid       = "AllowRootAccountFullAccess"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid    = "AllowCloudTrailEncrypt"
        Effect = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action = [
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:SourceArn" = "arn:aws:cloudtrail:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:trail/${var.project}-${var.environment}-trail"
          }
        }
      },
      {
        Sid    = "AllowCloudWatchLogs"
        Effect = "Allow"
        Principal = { Service = "logs.${data.aws_region.current.name}.amazonaws.com" }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
        Condition = {
          ArnLike = {
            "kms:EncryptionContext:aws:logs:arn" = "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:*"
          }
        }
      }
    ]
  })

  tags = {
    Name    = "${var.project}-${var.environment}-logs-cmk"
    Purpose = "CloudTrail and CloudWatch Logs encryption"
  }
}

resource "aws_kms_alias" "logs" {
  name          = "alias/${var.project}-${var.environment}-logs"
  target_key_id = aws_kms_key.logs.key_id
}

# ── EBS Encryption Key ───────────────────────────────────────

resource "aws_kms_key" "ebs" {
  description             = "CMK for Yuno CDE EBS volume encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Id      = "yuno-cde-ebs-key-policy"
    Statement = [
      {
        Sid       = "AllowRootAccountFullAccess"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid    = "AllowEC2Service"
        Effect = "Allow"
        Principal = { Service = "ec2.amazonaws.com" }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey",
          "kms:CreateGrant"
        ]
        Resource = "*"
      }
    ]
  })

  tags = {
    Name    = "${var.project}-${var.environment}-ebs-cmk"
    Purpose = "EBS volume encryption at rest"
  }
}

resource "aws_kms_alias" "ebs" {
  name          = "alias/${var.project}-${var.environment}-ebs"
  target_key_id = aws_kms_key.ebs.key_id
}
