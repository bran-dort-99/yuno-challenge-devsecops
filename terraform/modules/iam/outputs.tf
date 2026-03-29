output "ecs_execution_role_arn" {
  description = "ARN of the ECS task execution role"
  value       = aws_iam_role.ecs_execution.arn
}

output "ecs_task_role_arn" {
  description = "ARN of the ECS task role (application permissions)"
  value       = aws_iam_role.ecs_task.arn
}

output "flow_logs_role_arn" {
  description = "ARN of the VPC Flow Logs IAM role"
  value       = aws_iam_role.flow_logs.arn
}

output "rds_monitoring_role_arn" {
  description = "ARN of the RDS Enhanced Monitoring role"
  value       = aws_iam_role.rds_monitoring.arn
}
