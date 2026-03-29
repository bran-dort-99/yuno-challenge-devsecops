output "cloudtrail_arn" {
  description = "ARN of the CloudTrail trail"
  value       = aws_cloudtrail.cde.arn
}

output "vpc_flow_log_group_arn" {
  description = "ARN of the VPC Flow Logs CloudWatch Log Group"
  value       = aws_cloudwatch_log_group.vpc_flow.arn
}

output "ecs_log_group_name" {
  description = "Name of the ECS CloudWatch Log Group"
  value       = aws_cloudwatch_log_group.ecs.name
}

output "security_alerts_topic_arn" {
  description = "ARN of the security alerts SNS topic"
  value       = aws_sns_topic.security_alerts.arn
}
