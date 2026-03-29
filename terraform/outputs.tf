# ============================================================
# Root outputs — NEVER expose secrets.
# All sensitive values marked with sensitive = true.
# ============================================================

output "vpc_id" {
  description = "ID of the CDE VPC"
  value       = module.networking.vpc_id
}

output "alb_dns_name" {
  description = "DNS name of the CDE Application Load Balancer"
  value       = module.compute.alb_dns_name
}

output "rds_endpoint" {
  description = "RDS instance endpoint"
  value       = module.storage.rds_endpoint
  sensitive   = true # Contains hostname — treat as infrastructure detail
}

output "cde_bucket_arn" {
  description = "ARN of the CDE S3 bucket"
  value       = module.storage.cde_bucket_arn
}

output "cloudtrail_arn" {
  description = "ARN of the CDE CloudTrail"
  value       = module.monitoring.cloudtrail_arn
}

output "security_alerts_topic" {
  description = "SNS topic for security alerts"
  value       = module.monitoring.security_alerts_topic_arn
}
