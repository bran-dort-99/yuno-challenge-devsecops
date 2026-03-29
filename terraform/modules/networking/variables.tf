variable "project" { type = string }
variable "environment" { type = string }

variable "vpc_cidr" {
  description = "CIDR block for the CDE VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "az_count" {
  description = "Number of availability zones to use (multi-AZ for HA)"
  type        = number
  default     = 2
}

variable "app_port" {
  description = "Application listener port"
  type        = number
  default     = 8443
}

variable "allowed_ingress_cidrs" {
  description = "CIDR blocks allowed to reach the ALB (restrict to known ranges in production)"
  type        = list(string)
  default     = ["0.0.0.0/0"] # ALB is the only public-facing resource
}

variable "flow_log_group_arn" {
  description = "ARN of the CloudWatch Log Group for VPC Flow Logs"
  type        = string
}

variable "flow_log_role_arn" {
  description = "ARN of the IAM role that allows VPC Flow Logs to write to CloudWatch"
  type        = string
}
