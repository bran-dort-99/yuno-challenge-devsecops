# ============================================================
# Root-level variables — configurable per environment.
# No secrets. No defaults that weaken security posture.
# ============================================================

variable "project" {
  description = "Project identifier used in resource naming"
  type        = string
  default     = "yuno-cde"
}

variable "environment" {
  description = "Deployment environment"
  type        = string
  default     = "production"

  validation {
    condition     = contains(["production", "staging", "development"], var.environment)
    error_message = "Environment must be production, staging, or development."
  }
}

variable "aws_region" {
  description = "AWS region for CDE deployment"
  type        = string
  default     = "sa-east-1" # Sao Paulo — closest to Yuno's LATAM operations
}

variable "vpc_cidr" {
  description = "CIDR block for the CDE VPC"
  type        = string
  default     = "10.0.0.0/16"

  validation {
    condition     = can(cidrhost(var.vpc_cidr, 0))
    error_message = "vpc_cidr must be a valid CIDR block."
  }
}

variable "az_count" {
  description = "Number of availability zones (min 2 for HA)"
  type        = number
  default     = 2

  validation {
    condition     = var.az_count >= 2 && var.az_count <= 3
    error_message = "az_count must be 2 or 3 for production HA."
  }
}

variable "app_port" {
  description = "Application listener port"
  type        = number
  default     = 8443
}

variable "allowed_ingress_cidrs" {
  description = "CIDR blocks allowed to reach the ALB"
  type        = list(string)
  default     = ["0.0.0.0/0"] # ALB is the only internet-facing entry point
}

variable "acm_certificate_arn" {
  description = "ARN of the ACM certificate for ALB HTTPS listener"
  type        = string
}

variable "container_image" {
  description = "Container image URI for the payment API service"
  type        = string
  default     = "yuno/payment-api:latest"
}

variable "db_instance_class" {
  description = "RDS instance class"
  type        = string
  default     = "db.r6g.large"
}
