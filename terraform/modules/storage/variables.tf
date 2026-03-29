variable "project" { type = string }
variable "environment" { type = string }
variable "account_id" { type = string }

variable "s3_kms_key_arn" {
  description = "ARN of the KMS CMK for S3 encryption"
  type        = string
}

variable "rds_kms_key_arn" {
  description = "ARN of the KMS CMK for RDS encryption"
  type        = string
}

variable "db_subnet_ids" {
  description = "Subnet IDs for the RDS subnet group (private data tier only)"
  type        = list(string)
}

variable "db_sg_id" {
  description = "Security group ID for the RDS instance"
  type        = string
}

variable "db_instance_class" {
  description = "RDS instance class"
  type        = string
  default     = "db.r6g.large"
}

variable "db_allocated_storage" {
  description = "Initial storage allocation in GB"
  type        = number
  default     = 100
}

variable "db_max_allocated_storage" {
  description = "Maximum storage for auto-scaling in GB"
  type        = number
  default     = 500
}

variable "rds_monitoring_role_arn" {
  description = "ARN of the IAM role for RDS Enhanced Monitoring"
  type        = string
}
