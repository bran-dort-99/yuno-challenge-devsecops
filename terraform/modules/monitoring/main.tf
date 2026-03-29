# ============================================================
# Module: monitoring
# CloudTrail (multi-region), CloudWatch Logs, VPC Flow Logs,
# metric filters, and alarms for the Yuno CDE.
#
# PCI-DSS Requirements addressed:
#   Req 10.1:   Audit trails for all access to CDE
#   Req 10.2:   Automated audit trails for reconstructing events
#   Req 10.5:   Secure audit trails against tampering (KMS + validation)
#   Req 10.5.2: Log file integrity monitoring
#   Req 10.6:   Review logs and security events
# ============================================================

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# ── CloudTrail S3 Bucket ─────────────────────────────────────

resource "aws_s3_bucket" "cloudtrail" {
  bucket = "${var.project}-${var.environment}-cloudtrail-${data.aws_caller_identity.current.account_id}"

  tags = {
    Name    = "${var.project}-${var.environment}-cloudtrail"
    Purpose = "PCI-DSS Req 10 audit trail storage"
  }
}

resource "aws_s3_bucket_public_access_block" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.logs_kms_key_arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_versioning" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_lifecycle_configuration" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id

  rule {
    id     = "archive-old-logs"
    status = "Enabled"

    transition {
      days          = 90
      storage_class = "GLACIER"
    }

    # PCI-DSS Req 10.7: Retain logs for at least 1 year
    expiration {
      days = 365
    }
  }
}

resource "aws_s3_bucket_policy" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowCloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.cloudtrail.arn
        Condition = {
          StringEquals = {
            "aws:SourceArn" = "arn:aws:cloudtrail:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:trail/${var.project}-${var.environment}-trail"
          }
        }
      },
      {
        Sid       = "AllowCloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.cloudtrail.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
            "aws:SourceArn" = "arn:aws:cloudtrail:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:trail/${var.project}-${var.environment}-trail"
          }
        }
      },
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.cloudtrail.arn,
          "${aws_s3_bucket.cloudtrail.arn}/*"
        ]
        Condition = {
          Bool = { "aws:SecureTransport" = "false" }
        }
      }
    ]
  })
}

# ── CloudTrail ────────────────────────────────────────────────

resource "aws_cloudtrail" "cde" {
  name           = "${var.project}-${var.environment}-trail"
  s3_bucket_name = aws_s3_bucket.cloudtrail.id

  # PCI-DSS Req 10.1: Cover ALL regions — no audit blind spots
  is_multi_region_trail         = true
  include_global_service_events = true

  # PCI-DSS Req 10.5: Protect logs with KMS encryption
  kms_key_id = var.logs_kms_key_arn

  # PCI-DSS Req 10.5.2: Log file integrity validation
  enable_log_file_validation = true

  # Send to CloudWatch for real-time alerting
  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
  cloud_watch_logs_role_arn  = var.cloudtrail_cw_role_arn

  # Data events for S3 CDE bucket access — PCI-DSS Req 10.2
  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type   = "AWS::S3::Object"
      values = ["${var.cde_bucket_arn}/"]
    }
  }

  tags = {
    Name     = "${var.project}-${var.environment}-trail"
    PCI_Scope = "In-Scope"
  }

  depends_on = [aws_s3_bucket_policy.cloudtrail]
}

# ── CloudWatch Log Groups ────────────────────────────────────

resource "aws_cloudwatch_log_group" "cloudtrail" {
  name              = "/cloudtrail/${var.project}-${var.environment}"
  retention_in_days = 365 # PCI-DSS Req 10.7
  kms_key_id        = var.logs_kms_key_arn

  tags = { Name = "${var.project}-${var.environment}-cloudtrail-logs" }
}

resource "aws_cloudwatch_log_group" "vpc_flow" {
  name              = "/vpc/${var.project}-${var.environment}-flow-logs"
  retention_in_days = 365
  kms_key_id        = var.logs_kms_key_arn

  tags = { Name = "${var.project}-${var.environment}-vpc-flow-logs" }
}

resource "aws_cloudwatch_log_group" "ecs" {
  name              = "/ecs/${var.project}-${var.environment}"
  retention_in_days = 365
  kms_key_id        = var.logs_kms_key_arn

  tags = { Name = "${var.project}-${var.environment}-ecs-logs" }
}

# ── CloudWatch Metric Filters & Alarms (PCI-DSS Req 10.6) ────

resource "aws_sns_topic" "security_alerts" {
  name              = "${var.project}-${var.environment}-security-alerts"
  kms_master_key_id = var.logs_kms_key_arn

  tags = { Name = "${var.project}-${var.environment}-security-alerts" }
}

# Alarm 1: Root Account Usage
resource "aws_cloudwatch_log_metric_filter" "root_login" {
  name           = "${var.project}-root-account-usage"
  pattern        = "{ $.userIdentity.type = \"Root\" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != \"AwsServiceEvent\" }"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name

  metric_transformation {
    name      = "RootAccountUsage"
    namespace = "${var.project}/SecurityMetrics"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "root_login" {
  alarm_name          = "${var.project}-${var.environment}-root-account-usage"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "RootAccountUsage"
  namespace           = "${var.project}/SecurityMetrics"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "PCI-DSS 10.6: Root account was used. Investigate immediately."
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
  treat_missing_data  = "notBreaching"
}

# Alarm 2: Security Group Changes
resource "aws_cloudwatch_log_metric_filter" "sg_changes" {
  name           = "${var.project}-security-group-changes"
  pattern        = "{ ($.eventName = AuthorizeSecurityGroupIngress) || ($.eventName = AuthorizeSecurityGroupEgress) || ($.eventName = RevokeSecurityGroupIngress) || ($.eventName = RevokeSecurityGroupEgress) || ($.eventName = CreateSecurityGroup) || ($.eventName = DeleteSecurityGroup) }"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name

  metric_transformation {
    name      = "SecurityGroupChanges"
    namespace = "${var.project}/SecurityMetrics"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "sg_changes" {
  alarm_name          = "${var.project}-${var.environment}-security-group-changes"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "SecurityGroupChanges"
  namespace           = "${var.project}/SecurityMetrics"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "PCI-DSS 10.6: CDE security group modified. Verify authorized change."
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
  treat_missing_data  = "notBreaching"
}

# Alarm 3: Unauthorized API Calls
resource "aws_cloudwatch_log_metric_filter" "unauthorized_api" {
  name           = "${var.project}-unauthorized-api-calls"
  pattern        = "{ ($.errorCode = \"*UnauthorizedAccess\") || ($.errorCode = \"AccessDenied*\") }"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name

  metric_transformation {
    name      = "UnauthorizedAPICalls"
    namespace = "${var.project}/SecurityMetrics"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "unauthorized_api" {
  alarm_name          = "${var.project}-${var.environment}-unauthorized-api-calls"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "UnauthorizedAPICalls"
  namespace           = "${var.project}/SecurityMetrics"
  period              = 300
  statistic           = "Sum"
  threshold           = 5
  alarm_description   = "PCI-DSS 10.6: Multiple unauthorized API calls detected. Possible credential compromise."
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
  treat_missing_data  = "notBreaching"
}

# Alarm 4: IAM Policy Changes
resource "aws_cloudwatch_log_metric_filter" "iam_changes" {
  name           = "${var.project}-iam-policy-changes"
  pattern        = "{ ($.eventName = CreatePolicy) || ($.eventName = DeletePolicy) || ($.eventName = PutRolePolicy) || ($.eventName = AttachRolePolicy) || ($.eventName = DetachRolePolicy) || ($.eventName = DeleteRolePolicy) }"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name

  metric_transformation {
    name      = "IAMPolicyChanges"
    namespace = "${var.project}/SecurityMetrics"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "iam_changes" {
  alarm_name          = "${var.project}-${var.environment}-iam-policy-changes"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "IAMPolicyChanges"
  namespace           = "${var.project}/SecurityMetrics"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "PCI-DSS 10.6: IAM policy modified in CDE account. Verify authorized change."
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
  treat_missing_data  = "notBreaching"
}
