variable "project" { type = string }
variable "environment" { type = string }
variable "aws_region" { type = string }

variable "vpc_id" { type = string }
variable "public_subnet_ids" { type = list(string) }
variable "private_app_subnet_ids" { type = list(string) }
variable "alb_sg_id" { type = string }
variable "app_sg_id" { type = string }

variable "ecs_execution_role_arn" { type = string }
variable "ecs_task_role_arn" { type = string }

variable "acm_certificate_arn" {
  description = "ARN of the ACM certificate for HTTPS (TLS 1.2+)"
  type        = string
}

variable "container_image" {
  description = "Container image URI for the payment API"
  type        = string
  default     = "yuno/payment-api:latest"
}

variable "app_port" {
  description = "Application container port"
  type        = number
  default     = 8443
}

variable "task_cpu" {
  description = "Fargate task CPU units"
  type        = number
  default     = 1024
}

variable "task_memory" {
  description = "Fargate task memory in MB"
  type        = number
  default     = 2048
}

variable "desired_count" {
  description = "Number of ECS tasks"
  type        = number
  default     = 2
}

variable "db_endpoint" { type = string }
variable "db_secret_arn" {
  type      = string
  sensitive = true
}
variable "ecs_log_group_name" { type = string }
variable "access_logs_bucket_id" { type = string }
