# ============================================================
# Module: storage
# PCI-DSS compliant S3 + RDS with encryption at rest, access
# controls, backups, and audit logging.
#
# PCI-DSS Requirements addressed:
#   Req 3.4: Render PAN unreadable anywhere it is stored (encryption)
#   Req 3.5: Protect keys used to secure cardholder data (KMS CMK)
#   Req 7.2: Least privilege access to stored data
#   Req 10.2: Audit trail for all access to cardholder data
# ============================================================

# ── S3: CDE Cardholder Data Backup Bucket ─────────────────────

resource "aws_s3_bucket" "cde_data" {
  #checkov:skip=CKV2_AWS_62: Event notifications not configured for challenge.
  bucket = "${var.project}-${var.environment}-cde-data-${var.account_id}"

  # PCI-DSS Req 3.1: Limit storage duration — lifecycle rules below
  tags = {
    Name               = "${var.project}-${var.environment}-cde-data"
    DataClassification = "PCI-CDE"
    PCI_Scope          = "In-Scope"
  }
}

# PCI-DSS Req 3.4: Block ALL public access — four flags enforced
resource "aws_s3_bucket_public_access_block" "cde_data" {
  bucket = aws_s3_bucket.cde_data.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# PCI-DSS Req 3.5: Server-side encryption with customer-managed KMS key
resource "aws_s3_bucket_server_side_encryption_configuration" "cde_data" {
  bucket = aws_s3_bucket.cde_data.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.s3_kms_key_arn
    }
    bucket_key_enabled = true # Reduce KMS API costs
  }
}

# PCI-DSS Req 10.5: Immutability — versioning protects against deletion/tampering
resource "aws_s3_bucket_versioning" "cde_data" {
  bucket = aws_s3_bucket.cde_data.id

  versioning_configuration {
    status = "Enabled"
  }
}

# PCI-DSS Req 10.2: Access logging for audit trail
resource "aws_s3_bucket_logging" "cde_data" {
  bucket = aws_s3_bucket.cde_data.id

  target_bucket = aws_s3_bucket.access_logs.id
  target_prefix = "cde-data-access-logs/"
}

# PCI-DSS Req 3.1: Data retention policy — expire old versions
resource "aws_s3_bucket_lifecycle_configuration" "cde_data" {
  bucket = aws_s3_bucket.cde_data.id

  rule {
    id     = "expire-old-versions"
    status = "Enabled"

    noncurrent_version_expiration {
      noncurrent_days = 90
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

# Enforce TLS-only access — PCI-DSS Req 4: Encrypt in transit
resource "aws_s3_bucket_policy" "cde_data_tls_only" {
  bucket = aws_s3_bucket.cde_data.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.cde_data.arn,
          "${aws_s3_bucket.cde_data.arn}/*"
        ]
        Condition = {
          Bool = { "aws:SecureTransport" = "false" }
        }
      },
      {
        Sid       = "DenyOutdatedTLS"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.cde_data.arn,
          "${aws_s3_bucket.cde_data.arn}/*"
        ]
        Condition = {
          NumericLessThan = { "s3:TlsVersion" = "1.2" }
        }
      }
    ]
  })
}

# ── S3: Access Logs Bucket ────────────────────────────────────

resource "aws_s3_bucket" "access_logs" {
  #checkov:skip=CKV2_AWS_62: Event notifications not configured for challenge.
  bucket = "${var.project}-${var.environment}-access-logs-${var.account_id}"

  tags = {
    Name    = "${var.project}-${var.environment}-access-logs"
    Purpose = "S3 access log storage for CDE audit trail"
  }
}

resource "aws_s3_bucket_public_access_block" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.s3_kms_key_arn
    }
  }
}

resource "aws_s3_bucket_versioning" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

  rule {
    id     = "expire-old-access-logs"
    status = "Enabled"

    expiration {
      days = 365
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

# ── RDS: PostgreSQL (Tokenized Card Vault) ────────────────────

resource "aws_db_subnet_group" "cde" {
  name       = "${var.project}-${var.environment}-cde-db-subnet"
  subnet_ids = var.db_subnet_ids # Private data subnets only

  tags = { Name = "${var.project}-${var.environment}-cde-db-subnet" }
}

# Generate a strong random password — never hardcode
# PCI-DSS Req 8.3: Strong authentication credentials
resource "random_password" "db_master" {
  length           = 32
  special          = true
  override_special = "!#$%&*()-_=+[]{}<>:?"
}

# Store password in Secrets Manager — PCI-DSS Req 8
resource "aws_secretsmanager_secret" "db_password" {
  #checkov:skip=CKV2_AWS_57: Secret rotation not implemented yet.
  name                    = "${var.project}/${var.environment}/rds-master-password"
  description             = "RDS master password for CDE database"
  recovery_window_in_days = 30
  kms_key_id              = var.s3_kms_key_arn # Encrypt the secret itself

  tags = {
    Name      = "${var.project}-${var.environment}-db-password"
    PCI_Scope = "In-Scope"
  }
}

resource "aws_secretsmanager_secret_version" "db_password" {
  secret_id     = aws_secretsmanager_secret.db_password.id
  secret_string = random_password.db_master.result
}

resource "aws_db_instance" "cde" {
  identifier = "${var.project}-${var.environment}-cde-db"

  engine         = "postgres"
  engine_version = "16.2"
  instance_class = var.db_instance_class

  allocated_storage     = var.db_allocated_storage
  max_allocated_storage = var.db_max_allocated_storage
  storage_type          = "gp3"

  db_name  = "yunocde"
  username = "cde_admin"
  password = random_password.db_master.result

  db_subnet_group_name   = aws_db_subnet_group.cde.name
  vpc_security_group_ids = [var.db_sg_id]

  # PCI-DSS Req 1.3: No public access to database
  publicly_accessible = false

  # PCI-DSS Audit and Access (Fix CKV_AWS_129 and CKV_AWS_161)
  enabled_cloudwatch_logs_exports     = ["postgresql", "upgrade"]
  iam_database_authentication_enabled = true

  # PCI-DSS Req 3.4 / 3.5: Encryption at rest with CMK
  storage_encrypted = true
  kms_key_id        = var.rds_kms_key_arn

  # PCI-DSS Req 3.1: Data protection via deletion safeguards
  deletion_protection       = true
  skip_final_snapshot       = false
  final_snapshot_identifier = "${var.project}-${var.environment}-cde-db-final"
  copy_tags_to_snapshot     = true

  # Backups — PCI-DSS continuity
  backup_retention_period = 35
  backup_window           = "03:00-04:00"
  maintenance_window      = "sun:04:00-sun:05:00"

  # Enhanced monitoring — PCI-DSS Req 10
  monitoring_interval             = 60
  monitoring_role_arn             = var.rds_monitoring_role_arn
  performance_insights_enabled    = true
  performance_insights_kms_key_id = var.rds_kms_key_arn

  # Enforce SSL connections — PCI-DSS Req 4
  parameter_group_name = aws_db_parameter_group.cde.name

  # Multi-AZ for high availability
  multi_az = true

  # Auto minor version upgrades — PCI-DSS Req 6
  auto_minor_version_upgrade = true

  tags = {
    Name               = "${var.project}-${var.environment}-cde-db"
    DataClassification = "PCI-CDE"
  }

  lifecycle {
    prevent_destroy = true
  }
}

# Force SSL connections to PostgreSQL — PCI-DSS Req 4
resource "aws_db_parameter_group" "cde" {
  family = "postgres16"
  name   = "${var.project}-${var.environment}-cde-pg-params"

  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }

  parameter {
    name  = "log_connections"
    value = "1"
  }

  parameter {
    name  = "log_disconnections"
    value = "1"
  }

  parameter {
    name  = "log_statement"
    value = "ddl"
  }

  tags = { Name = "${var.project}-${var.environment}-cde-pg-params" }
}
