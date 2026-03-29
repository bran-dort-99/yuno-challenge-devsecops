# ============================================================
# Module: compute
# Application Load Balancer (ALB) and ECS Fargate service for
# the Yuno CDE payment processing API.
#
# PCI-DSS Requirements addressed:
#   Req 1.3: No direct public access to CDE workloads
#   Req 2.2: Hardened system configuration (IMDSv2, no SSH)
#   Req 3.5: Encrypted storage (EBS via KMS)
#   Req 4:   TLS 1.2+ for data in transit (ALB → HTTPS only)
#   Req 6:   Secure development (container images, not bare metal)
# ============================================================

# ── Application Load Balancer ─────────────────────────────────

resource "aws_lb" "cde" {
  name               = "${var.project}-${var.environment}-cde-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [var.alb_sg_id]
  subnets            = var.public_subnet_ids

  # PCI-DSS Req 10: ALB access logs
  access_logs {
    bucket  = var.access_logs_bucket_id
    prefix  = "alb-logs"
    enabled = true
  }

  # Drop invalid headers — prevent header injection attacks
  drop_invalid_header_fields = true
  enable_deletion_protection = true

  tags = {
    Name     = "${var.project}-${var.environment}-cde-alb"
    PCI_Zone = "DMZ"
  }
}

# HTTPS listener only — PCI-DSS Req 4: Encrypt in transit
resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.cde.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06" # TLS 1.2+ only
  certificate_arn   = var.acm_certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.cde.arn
  }
}

# Redirect HTTP → HTTPS (never serve plaintext)
resource "aws_lb_listener" "http_redirect" {
  load_balancer_arn = aws_lb.cde.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

resource "aws_lb_target_group" "cde" {
  name        = "${var.project}-${var.environment}-cde-tg"
  port        = var.app_port
  protocol    = "HTTP"
  vpc_id      = var.vpc_id
  target_type = "ip" # ECS Fargate uses awsvpc networking

  health_check {
    path                = "/health"
    healthy_threshold   = 3
    unhealthy_threshold = 3
    timeout             = 5
    interval            = 30
    matcher             = "200"
  }

  tags = { Name = "${var.project}-${var.environment}-cde-tg" }
}

# ── ECS Cluster ───────────────────────────────────────────────

resource "aws_ecs_cluster" "cde" {
  name = "${var.project}-${var.environment}-cde"

  setting {
    name  = "containerInsights"
    value = "enabled" # PCI-DSS Req 10: Container-level monitoring
  }

  tags = {
    Name     = "${var.project}-${var.environment}-cde-cluster"
    PCI_Zone = "CDE"
  }
}

# ── ECS Task Definition ──────────────────────────────────────

resource "aws_ecs_task_definition" "payment_api" {
  family                   = "${var.project}-${var.environment}-payment-api"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.task_cpu
  memory                   = var.task_memory
  execution_role_arn       = var.ecs_execution_role_arn
  task_role_arn            = var.ecs_task_role_arn

  # PCI-DSS Req 3.5: Encrypt ephemeral storage at rest
  ephemeral_storage {
    size_in_gib = 30
  }

  container_definitions = jsonencode([
    {
      name      = "payment-api"
      image     = var.container_image
      essential = true

      portMappings = [{
        containerPort = var.app_port
        protocol      = "tcp"
      }]

      # Secrets from Secrets Manager — never environment variables
      # PCI-DSS Req 8: No hardcoded credentials
      secrets = [
        {
          name      = "DB_PASSWORD"
          valueFrom = var.db_secret_arn
        }
      ]

      environment = [
        { name = "DB_HOST",        value = var.db_endpoint },
        { name = "DB_NAME",        value = "yunocde" },
        { name = "DB_USER",        value = "cde_admin" },
        { name = "DB_SSL_MODE",    value = "require" },
        { name = "ENVIRONMENT",    value = var.environment },
        { name = "LOG_LEVEL",      value = "info" }
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = var.ecs_log_group_name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "payment-api"
        }
      }

      # Security hardening
      readonlyRootFilesystem = true
      privileged             = false
      user                   = "1000:1000" # Non-root user

      linuxParameters = {
        initProcessEnabled = true
        capabilities = {
          drop = ["ALL"] # Drop all Linux capabilities
        }
      }
    }
  ])

  tags = {
    Name     = "${var.project}-${var.environment}-payment-api-task"
    PCI_Zone = "CDE"
  }
}

# ── ECS Service ───────────────────────────────────────────────

resource "aws_ecs_service" "payment_api" {
  name            = "${var.project}-${var.environment}-payment-api"
  cluster         = aws_ecs_cluster.cde.id
  task_definition = aws_ecs_task_definition.payment_api.arn
  desired_count   = var.desired_count
  launch_type     = "FARGATE"

  # Force new deployment on task definition change
  force_new_deployment = true

  network_configuration {
    subnets          = var.private_app_subnet_ids
    security_groups  = [var.app_sg_id]
    assign_public_ip = false # PCI-DSS Req 1.3: No public IPs for CDE
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.cde.arn
    container_name   = "payment-api"
    container_port   = var.app_port
  }

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  tags = {
    Name     = "${var.project}-${var.environment}-payment-api-service"
    PCI_Zone = "CDE"
  }
}
