variable "project" { type = string }
variable "environment" { type = string }

variable "db_secret_arn" {
  description = "ARN of the Secrets Manager secret for DB password"
  type        = string
}

variable "cde_bucket_arn" {
  description = "ARN of the CDE S3 bucket"
  type        = string
}

variable "s3_kms_key_arn" {
  description = "ARN of the KMS key used for S3 encryption"
  type        = string
}
