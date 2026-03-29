output "alb_dns_name" {
  description = "DNS name of the CDE Application Load Balancer"
  value       = aws_lb.cde.dns_name
}

output "alb_arn" {
  description = "ARN of the CDE ALB"
  value       = aws_lb.cde.arn
}

output "ecs_cluster_name" {
  description = "Name of the ECS cluster"
  value       = aws_ecs_cluster.cde.name
}

output "ecs_service_name" {
  description = "Name of the ECS service"
  value       = aws_ecs_service.payment_api.name
}
