variable "project" { type = string }
variable "environment" { type = string }

variable "logs_kms_key_arn" {
  description = "ARN of the KMS CMK for encrypting logs"
  type        = string
}

variable "cde_bucket_arn" {
  description = "ARN of the CDE S3 bucket (for CloudTrail data events)"
  type        = string
}

variable "cloudtrail_cw_role_arn" {
  description = "IAM role ARN allowing CloudTrail to write to CloudWatch Logs"
  type        = string
}
