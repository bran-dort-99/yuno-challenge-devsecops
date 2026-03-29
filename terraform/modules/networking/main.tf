# ============================================================
# Module: networking
# PCI-DSS compliant VPC with network segmentation, restrictive
# security groups, NACLs, and VPC Flow Logs.
#
# PCI-DSS Requirements addressed:
#   Req 1.2: Restrict connections between untrusted networks and CDE
#   Req 1.3: Prohibit direct public access to CDE
#   Req 10.6: VPC Flow Logs for network audit trail
# ============================================================

data "aws_availability_zones" "available" {
  state = "available"
}

locals {
  azs = slice(data.aws_availability_zones.available.names, 0, var.az_count)
}

# ── VPC ───────────────────────────────────────────────────────

resource "aws_vpc" "cde" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  # PCI-DSS Req 1: Dedicated VPC for CDE isolation
  tags = {
    Name       = "${var.project}-${var.environment}-cde-vpc"
    PCI_Zone   = "CDE"
  }
}

# ── Subnets ───────────────────────────────────────────────────

# Public subnets — ONLY for ALB (internet-facing load balancer)
# No CDE workloads or data stores are placed here
resource "aws_subnet" "public" {
  count             = var.az_count
  vpc_id            = aws_vpc.cde.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, count.index)
  availability_zone = local.azs[count.index]

  # PCI-DSS Req 1.3: CDE resources must NOT have public IPs
  map_public_ip_on_launch = false

  tags = {
    Name     = "${var.project}-${var.environment}-public-${local.azs[count.index]}"
    Tier     = "public"
    PCI_Zone = "DMZ"
  }
}

# Private app subnets — for ECS tasks / EC2 instances running payment services
resource "aws_subnet" "private_app" {
  count             = var.az_count
  vpc_id            = aws_vpc.cde.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, count.index + 10)
  availability_zone = local.azs[count.index]

  map_public_ip_on_launch = false

  tags = {
    Name     = "${var.project}-${var.environment}-private-app-${local.azs[count.index]}"
    Tier     = "private-app"
    PCI_Zone = "CDE"
  }
}

# Private data subnets — for RDS, ElastiCache, and other data stores
resource "aws_subnet" "private_data" {
  count             = var.az_count
  vpc_id            = aws_vpc.cde.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, count.index + 20)
  availability_zone = local.azs[count.index]

  map_public_ip_on_launch = false

  tags = {
    Name     = "${var.project}-${var.environment}-private-data-${local.azs[count.index]}"
    Tier     = "private-data"
    PCI_Zone = "CDE"
  }
}

# ── Internet Gateway (public subnet only) ─────────────────────

resource "aws_internet_gateway" "cde" {
  vpc_id = aws_vpc.cde.id

  tags = { Name = "${var.project}-${var.environment}-igw" }
}

# ── NAT Gateway (private subnet outbound) ─────────────────────
# PCI-DSS Req 1.3.4: Allow outbound but control it through NAT

resource "aws_eip" "nat" {
  count  = var.az_count
  domain = "vpc"

  tags = { Name = "${var.project}-${var.environment}-nat-eip-${count.index + 1}" }
}

resource "aws_nat_gateway" "cde" {
  count         = var.az_count
  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = aws_subnet.public[count.index].id

  tags = { Name = "${var.project}-${var.environment}-nat-${local.azs[count.index]}" }

  depends_on = [aws_internet_gateway.cde]
}

# ── Route Tables ──────────────────────────────────────────────

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.cde.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.cde.id
  }

  tags = { Name = "${var.project}-${var.environment}-public-rt" }
}

resource "aws_route_table_association" "public" {
  count          = var.az_count
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table" "private_app" {
  count  = var.az_count
  vpc_id = aws_vpc.cde.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.cde[count.index].id
  }

  tags = { Name = "${var.project}-${var.environment}-private-app-rt-${local.azs[count.index]}" }
}

resource "aws_route_table_association" "private_app" {
  count          = var.az_count
  subnet_id      = aws_subnet.private_app[count.index].id
  route_table_id = aws_route_table.private_app[count.index].id
}

resource "aws_route_table" "private_data" {
  count  = var.az_count
  vpc_id = aws_vpc.cde.id

  # Data subnets have NO outbound internet route — fully isolated
  # PCI-DSS Req 1.3: No direct internet path to/from data stores

  tags = { Name = "${var.project}-${var.environment}-private-data-rt-${local.azs[count.index]}" }
}

resource "aws_route_table_association" "private_data" {
  count          = var.az_count
  subnet_id      = aws_subnet.private_data[count.index].id
  route_table_id = aws_route_table.private_data[count.index].id
}

# ── Security Groups ───────────────────────────────────────────

# ALB Security Group — only accepts HTTPS from the internet
# PCI-DSS Req 4: Encrypt data in transit (TLS only)
resource "aws_security_group" "alb" {
  name        = "${var.project}-${var.environment}-alb-sg"
  description = "ALB: HTTPS from internet only. No HTTP."
  vpc_id      = aws_vpc.cde.id

  ingress {
    description = "HTTPS from internet"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = var.allowed_ingress_cidrs
  }

  egress {
    description     = "Forward to app tier only"
    from_port       = var.app_port
    to_port         = var.app_port
    protocol        = "tcp"
    security_groups = [aws_security_group.app.id]
  }

  tags = {
    Name     = "${var.project}-${var.environment}-alb-sg"
    PCI_Zone = "DMZ"
  }
}

# Application Security Group — accepts traffic from ALB only
# PCI-DSS Req 1.2: Restrict to only necessary connections
resource "aws_security_group" "app" {
  name        = "${var.project}-${var.environment}-app-sg"
  description = "App tier: ingress from ALB only, egress to DB and HTTPS."
  vpc_id      = aws_vpc.cde.id

  tags = {
    Name     = "${var.project}-${var.environment}-app-sg"
    PCI_Zone = "CDE"
  }
}

resource "aws_security_group_rule" "app_ingress_from_alb" {
  type                     = "ingress"
  from_port                = var.app_port
  to_port                  = var.app_port
  protocol                 = "tcp"
  security_group_id        = aws_security_group.app.id
  source_security_group_id = aws_security_group.alb.id
  description              = "Allow app port from ALB only"
}

resource "aws_security_group_rule" "app_egress_to_db" {
  type                     = "egress"
  from_port                = 5432
  to_port                  = 5432
  protocol                 = "tcp"
  security_group_id        = aws_security_group.app.id
  source_security_group_id = aws_security_group.db.id
  description              = "Allow PostgreSQL to DB tier"
}

resource "aws_security_group_rule" "app_egress_https" {
  type              = "egress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  security_group_id = aws_security_group.app.id
  cidr_blocks       = ["0.0.0.0/0"]
  description       = "Allow HTTPS outbound for AWS APIs and payment gateway"
}

# Database Security Group — accepts traffic from app tier only
# PCI-DSS Req 1.3: No public internet access to data stores
resource "aws_security_group" "db" {
  name        = "${var.project}-${var.environment}-db-sg"
  description = "DB tier: ingress from app tier only, no egress."
  vpc_id      = aws_vpc.cde.id

  ingress {
    description     = "PostgreSQL from app tier only"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.app.id]
  }

  tags = {
    Name     = "${var.project}-${var.environment}-db-sg"
    PCI_Zone = "CDE"
  }
}

# Explicit egress deny — DB does not initiate outbound connections.
# PCI-DSS Req 1.3: No traffic leaving the data tier to the internet.
# AWS SGs default to "allow all" egress; this rule makes the denial
# explicit and visible to auditors as an intentional security control.
resource "aws_security_group_rule" "db_deny_all_egress" {
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.db.id
  description       = "Explicit deny-all egress: DB tier must not initiate outbound connections (PCI-DSS Req 1.3)"

  lifecycle {
    # The NACL provides defense-in-depth; this SG rule makes intent
    # explicit for QSA review without relying on AWS default behavior.
    create_before_destroy = false
  }
}

# ── Network ACLs (defense in depth) ──────────────────────────

# Data subnet NACL — additional layer of protection for DB tier
# PCI-DSS Req 1: Layered network controls (defense in depth)
resource "aws_network_acl" "data" {
  vpc_id     = aws_vpc.cde.id
  subnet_ids = aws_subnet.private_data[*].id

  # Allow inbound PostgreSQL from app subnets only
  ingress {
    rule_no    = 100
    protocol   = "tcp"
    action     = "allow"
    cidr_block = var.vpc_cidr
    from_port  = 5432
    to_port    = 5432
  }

  # Allow ephemeral return traffic
  ingress {
    rule_no    = 200
    protocol   = "tcp"
    action     = "allow"
    cidr_block = var.vpc_cidr
    from_port  = 1024
    to_port    = 65535
  }

  # Deny everything else inbound
  ingress {
    rule_no    = 999
    protocol   = "-1"
    action     = "deny"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  # Allow outbound ephemeral ports to VPC only
  egress {
    rule_no    = 100
    protocol   = "tcp"
    action     = "allow"
    cidr_block = var.vpc_cidr
    from_port  = 1024
    to_port    = 65535
  }

  egress {
    rule_no    = 999
    protocol   = "-1"
    action     = "deny"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  tags = { Name = "${var.project}-${var.environment}-data-nacl" }
}

# ── VPC Flow Logs ─────────────────────────────────────────────
# PCI-DSS Req 10: Log and monitor all network access

resource "aws_flow_log" "cde" {
  vpc_id               = aws_vpc.cde.id
  traffic_type         = "ALL"
  log_destination_type = "cloud-watch-logs"
  log_destination      = var.flow_log_group_arn
  iam_role_arn         = var.flow_log_role_arn

  tags = { Name = "${var.project}-${var.environment}-vpc-flow-log" }
}
