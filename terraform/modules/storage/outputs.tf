output "cde_bucket_arn" {
  description = "ARN of the CDE data S3 bucket"
  value       = aws_s3_bucket.cde_data.arn
}

output "cde_bucket_id" {
  description = "ID of the CDE data S3 bucket"
  value       = aws_s3_bucket.cde_data.id
}

output "access_logs_bucket_arn" {
  description = "ARN of the access logs S3 bucket"
  value       = aws_s3_bucket.access_logs.arn
}

output "access_logs_bucket_id" {
  description = "ID of the access logs S3 bucket"
  value       = aws_s3_bucket.access_logs.id
}

output "rds_endpoint" {
  description = "RDS instance endpoint (host:port)"
  value       = aws_db_instance.cde.endpoint
}

output "rds_arn" {
  description = "ARN of the RDS instance"
  value       = aws_db_instance.cde.arn
}

output "db_secret_arn" {
  description = "ARN of the Secrets Manager secret containing the DB password"
  value       = aws_secretsmanager_secret.db_password.arn
  sensitive   = true
}
