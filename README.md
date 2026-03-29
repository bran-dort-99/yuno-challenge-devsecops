# The Terraform Wildfire: Secure IaC for Yuno's New Cloud CDE

Hardened Terraform infrastructure for Yuno's PCI-DSS Level 1 Cardholder Data Environment on AWS, with automated security scanning pipeline, custom compliance policies, and shift-left prevention mechanisms.

---

## Architecture

```
                 Internet
                    │
                    ▼
    ┌──────────────────────────────┐
    │   Application Load Balancer  │  ← Public subnet (HTTPS 443 only)
    │   TLS 1.2+ (ACM cert)       │    HTTP → HTTPS redirect
    │   Access logs to S3          │
    └──────────────┬───────────────┘
                   │ Port 8443
    ┌──────────────▼───────────────┐
    │   ECS Fargate (Payment API)  │  ← Private app subnet
    │   Non-root, read-only FS     │    No public IP
    │   All capabilities dropped   │    Secrets from Secrets Manager
    │   CloudWatch Logs            │
    └──────────────┬───────────────┘
                   │ Port 5432 (TLS required)
    ┌──────────────▼───────────────┐
    │   RDS PostgreSQL (Card Vault)│  ← Private data subnet (no internet route)
    │   KMS encryption at rest     │    Multi-AZ, 35-day backups
    │   publicly_accessible=false  │    Enhanced monitoring
    │   force_ssl=1                │    Deletion protection
    └──────────────────────────────┘

    ┌──────────────────────────────┐
    │   S3 (Encrypted Backups)     │  ← BlockPublicAccess (all 4 flags)
    │   SSE-KMS, versioning        │    TLS-only bucket policy
    │   Access logging             │    Lifecycle rules (90-day expiry)
    └──────────────────────────────┘

    ┌──────────────────────────────┐
    │   Monitoring & Audit         │
    │   CloudTrail (multi-region)  │  ← KMS encrypted, log file validation
    │   VPC Flow Logs              │    365-day retention
    │   CloudWatch Alarms (4x)    │    Root login, SG changes, IAM changes,
    │   SNS Security Alerts        │    unauthorized API calls
    └──────────────────────────────┘
```

### Network Segmentation (3-tier)

| Tier | Subnet | Resources | Internet Access |
|---|---|---|---|
| **DMZ** | Public | ALB only | Inbound HTTPS, outbound to app tier |
| **App** | Private App | ECS Fargate tasks | Outbound via NAT (HTTPS only) |
| **Data** | Private Data | RDS PostgreSQL | **None** — fully isolated |

---

## Project Structure

```
yuno-cde-secure/
├── README.md                          ← You are here
├── THREAT_ANALYSIS.md                 ← Threat model, design decisions, PCI-DSS mapping
├── terraform/
│   ├── main.tf                        ← Root module wiring all modules together
│   ├── variables.tf                   ← Configurable inputs (region, instance class, etc.)
│   ├── outputs.tf                     ← Safe outputs (no secrets exposed)
│   ├── providers.tf                   ← AWS provider (NO hardcoded credentials)
│   ├── backend.tf                     ← S3 backend with encryption + DynamoDB locking
│   ├── versions.tf                    ← Provider version constraints
│   └── modules/
│       ├── kms/                       ← 4 customer-managed KMS keys (RDS, S3, EBS, Logs)
│       ├── networking/                ← VPC, 3-tier subnets, SGs, NACLs, VPC Flow Logs
│       ├── storage/                   ← S3 (encrypted, private), RDS (encrypted, private)
│       ├── iam/                       ← Least-privilege roles (zero wildcards)
│       ├── compute/                   ← ALB (HTTPS), ECS Fargate (hardened containers)
│       └── monitoring/                ← CloudTrail, CloudWatch, alarms, SNS
├── .github/workflows/
│   └── iac-security.yml               ← 5-stage CI/CD security pipeline
├── .pre-commit-config.yaml            ← Local shift-left hooks
├── .tflint.hcl                        ← TFLint configuration
├── policies/custom/
│   ├── cde_rds_encryption.py          ← CKV_YUNO_001: RDS must use KMS CMK
│   ├── cde_s3_public_access.py        ← CKV_YUNO_002: All 4 S3 public access flags
│   ├── cde_no_wildcard_iam.py         ← CKV_YUNO_003: No Action:*/Resource:*
│   └── cde_no_public_db.py            ← CKV_YUNO_004: No publicly accessible RDS
├── scripts/
│   └── pre-flight.sh                  ← One-command local validation (6 checks)
└── docs/                              ← Additional documentation
```

---

## Quick Start

### Prerequisites

```bash
# Required
brew install terraform           # >= 1.5.0
pip install checkov              # Policy engine
brew install tfsec               # Fast Terraform scanner

# Recommended (for local shift-left checks)
pip install pre-commit           # Pre-commit hook framework
brew install gitleaks            # Secrets detection
brew install trivy               # Multi-purpose scanner
```

### 1. Clone and Validate

```bash
git clone https://github.com/your-org/yuno-cde-secure.git
cd yuno-cde-secure

# Run the pre-flight validation script (6 checks in < 30s)
./scripts/pre-flight.sh
```

### 2. Set Up Pre-commit Hooks (Recommended)

```bash
pre-commit install

# Run against all files to verify clean baseline
pre-commit run --all-files
```

### 3. Initialize Terraform

```bash
cd terraform

# For local development (no remote backend):
terraform init -backend=false

# For production (with S3 backend):
terraform init

# Validate
terraform validate

# Plan (requires AWS credentials via IAM role or environment)
terraform plan -var="acm_certificate_arn=arn:aws:acm:sa-east-1:ACCOUNT:certificate/CERT-ID"
```

### 4. Run Security Scans Locally

```bash
# Quick scan (tfsec — fastest)
tfsec terraform/ --minimum-severity HIGH

# Full scan (Checkov with custom policies)
checkov -d terraform/ \
  --external-checks-dir policies/custom \
  --hard-fail-on CRITICAL,HIGH \
  --compact

# Cross-verification (Trivy)
trivy config terraform/
```

---

## CI/CD Pipeline

The pipeline runs automatically on every PR that touches `terraform/` or `policies/`:

```
┌─────────────────┐
│ Stage 1: Validate│ ← terraform fmt + validate (~15s)
└────────┬────────┘
         │
    ┌────┴─────────────────────────────────┐
    │         Parallel execution            │
    ├────────────┬─────────────┬────────────┤
    ▼            ▼             ▼            ▼
┌─────────┐┌──────────┐┌──────────┐┌───────────┐
│ Stage 2 ││ Stage 3  ││ Stage 4  ││ Stage 5   │
│ tfsec   ││ Checkov  ││ Trivy    ││ Gitleaks  │
│ (~30s)  ││ (~90s)   ││ (~30s)   ││ (~30s)    │
└────┬────┘└────┬─────┘└────┬─────┘└─────┬─────┘
     │          │           │             │
     └──────────┴─────┬─────┴─────────────┘
                      ▼
              ┌───────────────┐
              │ Security Gate │ ← Blocks merge if any stage fails
              └───────────────┘
```

**Total wall-clock time: ~2-3 minutes** (stages run in parallel)

### Severity Policy

| Severity | Pipeline Action | Rationale |
|---|---|---|
| **CRITICAL** | **Block merge** | Direct cardholder data exposure risk |
| **HIGH** | **Block merge** | Exploitable security misconfiguration |
| **MEDIUM** | **Warn** (visible in PR) | Important but not immediately exploitable |
| **LOW/INFO** | **Log only** | Awareness and continuous improvement |

---

## Custom Checkov Policies

| Policy ID | Name | What It Enforces | PCI-DSS Req |
|---|---|---|---|
| `CKV_YUNO_001` | CDE RDS Encryption with CMK | RDS must have `storage_encrypted = true` AND a `kms_key_id` specified | Req 3.4, 3.5 |
| `CKV_YUNO_002` | CDE S3 Full Public Access Block | All 4 `BlockPublicAccess` flags must be `true` | Req 3.4 |
| `CKV_YUNO_003` | CDE No Wildcard IAM | No policy may use `Action: *` with `Resource: *` together | Req 7.2 |
| `CKV_YUNO_004` | CDE No Public Database | `publicly_accessible` must be `false` on all RDS instances | Req 1.3 |

---

## Security Controls Summary

| Category | Control | PCI-DSS Req | Status |
|---|---|---|---|
| **Encryption at rest** | RDS: KMS CMK, S3: SSE-KMS, EBS: KMS CMK, Logs: KMS CMK | Req 3.4, 3.5 | ✅ |
| **Encryption in transit** | ALB: TLS 1.2+, RDS: `force_ssl`, S3: TLS-only policy | Req 4 | ✅ |
| **Network segmentation** | 3-tier VPC, SG references (not CIDRs), NACLs on data tier | Req 1 | ✅ |
| **Least privilege IAM** | Zero wildcard policies, scoped to specific resources | Req 7 | ✅ |
| **No public data access** | RDS private, S3 BlockPublicAccess, no public IPs on CDE | Req 1.3 | ✅ |
| **Secrets management** | Secrets Manager for DB password, no hardcoded credentials | Req 8 | ✅ |
| **Audit logging** | CloudTrail (multi-region), VPC Flow Logs, S3 access logs | Req 10 | ✅ |
| **Log protection** | KMS encryption, log file validation, 365-day retention | Req 10.5 | ✅ |
| **Security monitoring** | CloudWatch alarms: root login, SG changes, unauth API, IAM changes | Req 10.6 | ✅ |
| **Resource tagging** | All resources tagged: PCI_Scope, Environment, DataClassification | Compliance | ✅ |

---

## Design Decisions

See [`THREAT_ANALYSIS.md`](THREAT_ANALYSIS.md) for the full threat model, tool selection rationale, security vs. velocity trade-offs, residual risks, and detailed PCI-DSS compliance mapping.

Key decisions:
1. **ECS Fargate over EC2** — eliminates OS attack surface, no SSH, no IMDSv1
2. **Separate KMS keys per service** — limits blast radius if one key policy is misconfigured
3. **Block CRITICAL/HIGH, warn MEDIUM** — balances security rigor with 8-12 PRs/day velocity
4. **Data subnet has no internet route** — even compromised app tier can't exfiltrate directly from DB
5. **Multiple scanning tools** — defense in depth applies to detection, not just prevention

---

## What I'd Do Next (With More Time)

| Priority | Item | Why |
|---|---|---|
| 1 | **Runtime drift detection** (AWS Config + driftctl) | Detect console changes that bypass IaC |
| 2 | **Container image scanning** (Trivy in CI) | Extend security to application dependencies |
| 3 | **AWS WAF on ALB** | Rate limiting, OWASP Core Rule Set for payment API |
| 4 | **Terratest automated tests** | Validate security properties programmatically |
| 5 | **SIEM integration** (Datadog/Splunk) | 24/7 SOC monitoring for CDE events |
| 6 | **SCP enforcement** | Prevent console changes at the org level |
| 7 | **Policy exception workflow** | Approved exceptions with expiry and audit trail |

---

## License

This solution is provided as a DevSecOps challenge submission. All code is original.
