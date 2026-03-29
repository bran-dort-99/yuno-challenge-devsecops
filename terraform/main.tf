# ============================================================
# Yuno CDE — Root Module
# Wires all modules together to provision a PCI-DSS compliant
# Cardholder Data Environment on AWS.
#
# Architecture:
#   Internet → ALB (public subnet, HTTPS only)
#            → ECS Fargate (private app subnet)
#            → RDS PostgreSQL (private data subnet, encrypted)
#            → S3 (encrypted, BlockPublicAccess)
#
# All modules use customer-managed KMS keys for encryption.
# No wildcard IAM permissions. No public access to data stores.
# Full audit trail via CloudTrail + VPC Flow Logs + CloudWatch.
# ============================================================

data "aws_caller_identity" "current" {}

# ── KMS (encryption keys — provisioned first) ────────────────

module "kms" {
  source = "./modules/kms"

  project     = var.project
  environment = var.environment
}

# ── IAM (roles — needed before compute and networking) ────────

module "iam" {
  source = "./modules/iam"

  project     = var.project
  environment = var.environment

  db_secret_arn  = module.storage.db_secret_arn
  cde_bucket_arn = module.storage.cde_bucket_arn
  s3_kms_key_arn = module.kms.s3_key_arn
}

# ── Monitoring (log groups — needed before networking & compute)

module "monitoring" {
  source = "./modules/monitoring"

  project     = var.project
  environment = var.environment

  logs_kms_key_arn       = module.kms.logs_key_arn
  cde_bucket_arn         = module.storage.cde_bucket_arn
  cloudtrail_cw_role_arn = module.iam.flow_logs_role_arn
}

# ── Networking ────────────────────────────────────────────────

module "networking" {
  source = "./modules/networking"

  project     = var.project
  environment = var.environment
  vpc_cidr    = var.vpc_cidr
  az_count    = var.az_count
  app_port    = var.app_port

  allowed_ingress_cidrs = var.allowed_ingress_cidrs
  flow_log_group_arn    = module.monitoring.vpc_flow_log_group_arn
  flow_log_role_arn     = module.iam.flow_logs_role_arn
}

# ── Storage (S3 + RDS) ───────────────────────────────────────

module "storage" {
  source = "./modules/storage"

  project     = var.project
  environment = var.environment
  account_id  = data.aws_caller_identity.current.account_id

  s3_kms_key_arn  = module.kms.s3_key_arn
  rds_kms_key_arn = module.kms.rds_key_arn

  db_subnet_ids           = module.networking.private_data_subnet_ids
  db_sg_id                = module.networking.db_sg_id
  db_instance_class       = var.db_instance_class
  rds_monitoring_role_arn = module.iam.rds_monitoring_role_arn
}

# ── Compute (ALB + ECS Fargate) ──────────────────────────────

module "compute" {
  source = "./modules/compute"

  project     = var.project
  environment = var.environment
  aws_region  = var.aws_region

  vpc_id                 = module.networking.vpc_id
  public_subnet_ids      = module.networking.public_subnet_ids
  private_app_subnet_ids = module.networking.private_app_subnet_ids
  alb_sg_id              = module.networking.alb_sg_id
  app_sg_id              = module.networking.app_sg_id
  app_port               = var.app_port

  ecs_execution_role_arn = module.iam.ecs_execution_role_arn
  ecs_task_role_arn      = module.iam.ecs_task_role_arn
  acm_certificate_arn    = var.acm_certificate_arn
  container_image        = var.container_image

  db_endpoint           = module.storage.rds_endpoint
  db_secret_arn         = module.storage.db_secret_arn
  ecs_log_group_name    = module.monitoring.ecs_log_group_name
  access_logs_bucket_id = module.storage.access_logs_bucket_id
}
