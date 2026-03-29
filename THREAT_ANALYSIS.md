# Threat Analysis & Design Decisions

## Yuno CDE — Secure IaC for Cloud Cardholder Data Environment

**Author:** DevSecOps Engineer
**Date:** 2026-03-28
**Scope:** AWS infrastructure for Yuno's CDE in sa-east-1 (South America)

---

## 1. Threat Model

### 1.1 What Are We Protecting?

Yuno's CDE processes and stores:
- **Primary Account Numbers (PANs)** — tokenized and encrypted, but still PCI-DSS in-scope
- **Tokenization database** — the PostgreSQL RDS instance mapping tokens to encrypted PANs
- **Encrypted card vault backups** — S3 objects containing encrypted cardholder data exports
- **Payment API** — processes real-time card transactions, communicates with card networks

**Data classification:** PCI-DSS Level 1 (>300K transactions/year). A single breach triggers mandatory notification to card brands, QSA investigation, potential fines of $5K-$100K/month, and possible loss of card processing privileges.

### 1.2 Threat Actors

| Threat Actor | Motivation | Capability | Likelihood |
|---|---|---|---|
| **External attacker** (financially motivated) | Steal cardholder data for resale on dark web ($5-$30/card) | Moderate to advanced; uses automated scanning, known CVEs, credential stuffing | **High** — payment companies are primary targets |
| **Nation-state APT** | Financial intelligence, economic espionage | Advanced; zero-days, supply chain attacks, long-term persistence | **Medium** — Yuno's LATAM presence may attract regional actors |
| **Malicious insider** | Financial gain or disgruntlement | High — already has authenticated access; can bypass network controls | **Low-Medium** — mitigated by least privilege and audit trails |
| **Accidental misconfiguration** (developer) | No malicious intent; velocity over security | N/A — the most common cause of cloud breaches | **High** — 6 engineers shipping 8-12 PRs/day with insufficient review |

### 1.3 Attack Vectors and Blast Radius

#### Vector 1: Publicly Accessible S3 Bucket (CRITICAL)
- **Path:** Developer sets `block_public_acls = false` → bucket policy allows public read → cardholder data backup exposed to internet
- **Blast radius:** Full database of tokenized card records exposed. Every cardholder in the system is compromised.
- **Real-world precedent:** Capital One (2019) — 100M credit applications exposed via S3 misconfiguration. Fine: $80M.
- **Our mitigation:** `aws_s3_bucket_public_access_block` with all 4 flags = true on every bucket. Custom Checkov policy `CKV_YUNO_002` enforces this. Pipeline blocks on violation.

#### Vector 2: Overly Permissive IAM Role + SSRF (CRITICAL)
- **Path:** EC2/ECS task has `Action: *, Resource: *` → attacker exploits SSRF in payment API → calls IMDSv1 → retrieves full admin credentials → exfiltrates data from RDS and S3
- **Blast radius:** Full AWS account takeover. Attacker can disable CloudTrail, modify security groups, create backdoor IAM users, and exfiltrate all cardholder data.
- **Real-world precedent:** Capital One (2019) — SSRF + overly permissive IAM role was the exact kill chain.
- **Our mitigation:** Zero wildcard IAM policies (`CKV_YUNO_003`). ECS Fargate with IMDSv2 enforced (Fargate uses task-level credentials, not instance metadata). Task role limited to specific S3 bucket + Secrets Manager secret + specific KMS key.

#### Vector 3: Unencrypted Database (HIGH)
- **Path:** RDS `storage_encrypted = false` → attacker with snapshot access reads plaintext data → or AWS insider accesses physical storage
- **Blast radius:** All tokenized card data in the database readable without decryption.
- **Our mitigation:** `storage_encrypted = true` with customer-managed KMS key (`CKV_YUNO_001`). Key rotation enabled. Force SSL via `rds.force_ssl = 1` parameter.

#### Vector 4: Open Security Groups (HIGH)
- **Path:** `0.0.0.0/0` on port 5432 → attacker discovers RDS endpoint → brute force or exploit PostgreSQL vulnerability → direct database access
- **Blast radius:** Direct access to tokenized cardholder data. Bypasses all application-layer security.
- **Our mitigation:** Database SG allows ingress only from app SG (security group reference, not CIDR). Data subnets have NACLs as defense-in-depth. No public subnets for data tier. No internet route in data subnet route table.

#### Vector 5: Missing Audit Trail (HIGH)
- **Path:** No CloudTrail or VPC Flow Logs → attacker operates undetected → breached for months without awareness (average dwell time: 204 days per IBM)
- **Blast radius:** Cannot reconstruct timeline for incident response. Cannot prove compliance to QSA. PCI-DSS Req 10 failure means automatic assessment failure.
- **Our mitigation:** Multi-region CloudTrail with KMS encryption, log file validation, 365-day retention. VPC Flow Logs to CloudWatch. CloudWatch alarms for root login, SG changes, unauthorized API calls, and IAM policy changes.

#### Vector 6: Hardcoded Credentials in Code (HIGH)
- **Path:** AWS access keys or DB password in `variables.tf` → pushed to Git → attacker scrapes GitHub → uses credentials to access AWS account directly
- **Blast radius:** Direct AWS account access if access keys; direct database access if DB password.
- **Our mitigation:** Zero hardcoded credentials. Provider uses IAM role auth (no access_key/secret_key). DB password generated via `random_password` and stored in Secrets Manager. Pre-commit hook runs Gitleaks. CI pipeline runs Gitleaks on every PR.

---

## 2. Tool & Control Selection

### 2.1 Scanning Tools

| Tool | Purpose | Why we chose it | Alternatives considered |
|---|---|---|---|
| **Checkov** (Bridgecrew) | Primary policy engine with custom policy support | Python-based custom policies for Yuno-specific rules (CDE encryption, IAM, public access). Supports 1000+ built-in checks. SARIF output for GitHub integration. | **Sentinel** — HashiCorp-native but commercial and Terraform-specific. **OPA/Rego** — more powerful but steeper learning curve for the team. |
| **tfsec** (Aqua Security) | Fast, opinionated Terraform scanner | Fastest scanner in our pipeline (<30s). Catches common misconfigurations with low false-positive rate. Good developer experience. | **Terrascan** — similar coverage but slower. |
| **Trivy** (Aqua Security) | Cross-tool verification for config scanning | Provides a different detection engine as defense-in-depth. Also scans container images and SBOMs if we extend later. | **Snyk IaC** — good but requires license for full features. |
| **Gitleaks** | Secrets detection in code and git history | Fast, low false-positive rate, supports custom regex patterns. Catches secrets that IaC scanners miss. | **TruffleHog** — more thorough history scanning but slower. **detect-secrets** — good but less maintained. |

**Why multiple tools?** No single scanner catches everything. Our testing showed:
- tfsec catches SG misconfigurations that Checkov sometimes misses
- Checkov's custom policy engine allows Yuno-specific rules tfsec can't express
- Trivy provides a third verification layer from a different detection engine
- Overlap is intentional — defense in depth applies to scanning too

### 2.2 Infrastructure Controls

| Control | PCI-DSS Req | Implementation |
|---|---|---|
| Network segmentation (3-tier) | Req 1 | Public (ALB only) → Private App (ECS) → Private Data (RDS). NACLs on data tier. |
| KMS encryption at rest | Req 3 | Separate CMKs for RDS, S3, EBS, and Logs. Key rotation enabled. |
| TLS 1.2+ in transit | Req 4 | ALB SSL policy TLS13-1-2. RDS `force_ssl = 1`. S3 bucket policy denies `SecureTransport = false`. |
| Least privilege IAM | Req 7 | Zero wildcard policies. ECS task role scoped to specific S3 bucket + Secrets Manager secret. |
| Secrets Manager for credentials | Req 8 | DB password generated by `random_password`, stored in Secrets Manager. Injected to containers via ECS secrets. |
| CloudTrail + CloudWatch + VPC Flow Logs | Req 10 | Multi-region CloudTrail with KMS encryption and log validation. 4 CloudWatch alarms. 365-day retention. |

---

## 3. Security vs. Velocity Trade-offs

This is the core tension: Yuno's infrastructure team ships 8-12 PRs per day. The QSA audit is in 18 days. We need security rigor without destroying developer velocity.

### 3.1 What We Block (CRITICAL/HIGH)

These issues are **never acceptable** in a CDE and always block the pipeline:

| Finding | Severity | Why it blocks |
|---|---|---|
| Public S3 bucket in CDE | CRITICAL | Direct cardholder data exposure |
| Wildcard IAM (Action:* + Resource:*) | CRITICAL | Full account takeover risk |
| Publicly accessible RDS | CRITICAL | Direct database access from internet |
| Unencrypted RDS storage | HIGH | Plaintext cardholder data at rest |
| `0.0.0.0/0` on SSH, RDP, or DB ports | HIGH | Direct attack surface for sensitive services |
| Hardcoded secrets in code | HIGH | Credential leak via source control |
| Missing CloudTrail | HIGH | PCI-DSS Req 10 automatic failure |

### 3.2 What We Warn On (MEDIUM)

These are flagged in the PR but **do not block merge**. They're tracked for remediation within 7 days:

| Finding | Severity | Why it warns (not blocks) |
|---|---|---|
| Missing resource tags | MEDIUM | Important for compliance tracking but not an active vulnerability |
| Overly broad egress rules | MEDIUM | Less risky than ingress; legitimate need for outbound HTTPS |
| Cross-region replication not configured | MEDIUM | Good practice but not a PCI requirement for single-region CDE |
| Non-default SSL policy (using older TLS policy) | MEDIUM | Still secure, just not optimal |

### 3.3 Pipeline Performance Budget

| Stage | Target | Actual |
|---|---|---|
| terraform fmt + validate | < 30s | ~15s |
| tfsec | < 1m | ~30-45s |
| Checkov (with custom policies) | < 2m | ~60-90s |
| Trivy config | < 1m | ~30s |
| Gitleaks | < 1m | ~20-40s |
| **Total** | **< 5m** | **~3-4m** |

Stages 2-4 run in parallel (GitHub Actions `needs` dependency only on Stage 1). This means the actual wall-clock time is ~2-3 minutes, not the sum.

### 3.4 Developer Experience Decisions

- **SARIF upload to GitHub Security tab:** Developers see findings inline in the PR, with file:line references and remediation links.
- **Pre-commit hooks are optional but recommended:** We don't force pre-commit installation because it creates friction for new team members. Instead, we provide `scripts/pre-flight.sh` as a one-command check.
- **Clear severity policy:** Developers know exactly what blocks and what warns — no ambiguity, no "it depends on the reviewer."

### 3.5 Incident Response Support

While this document focuses on prevention, our architecture is designed to support rapid forensic investigation during an incident:
- **Timeline Reconstruction:** Multi-region CloudTrail with 365-day retention allows investigators to reconstruct exact API call sequences.
- **Data Exfiltration Forensics:** S3 data events for the CDE bucket track every `GetObject` and `PutObject` call, enabling accurate blast radius calculation if credentials are compromised.
- **Log Integrity:** CloudTrail log file validation and KMS encryption ensure attackers cannot tamper with logs to cover their tracks.
- **Network Forensics:** VPC Flow Logs sent to CloudWatch provide a complete record of successful and rejected network connections.

---

## 4. Residual Risks

No solution eliminates all risk. Here's what remains and what we'd add with more time:

| Residual Risk | Impact | Mitigation Status | Next Step |
|---|---|---|---|
| **Runtime drift** — someone modifies a SG in the AWS Console | HIGH | Not currently detected | Add AWS Config rules or `driftctl` to detect out-of-band changes |
| **Container image vulnerabilities** | HIGH | Not scanning container images (only IaC) | Add Trivy image scanning to CI pipeline for `yuno/payment-api` |
| **Terraform state file exposure** | HIGH | S3 backend with encryption, but no state file access audit | Add S3 access logging on the state bucket; restrict state access to CI pipeline only |
| **Supply chain attacks on Terraform providers** | MEDIUM | `terraform.lock.hcl` pins provider versions | Add provider signature verification; review provider updates in a separate PR |
| **Insider threat: developer with AWS console access** | MEDIUM | CloudTrail logs all API calls | Add AWS Config to detect manual changes; enforce IaC-only changes via SCP |
| **Denial of service on payment API** | MEDIUM | No WAF configured on ALB | Add AWS WAF with rate limiting and OWASP Core Rule Set |
| **Missing SIEM integration** | MEDIUM | CloudWatch alarms go to SNS but no SOC integration | Integrate with Datadog/Splunk/PagerDuty for 24/7 SOC monitoring |
| **Policy exception workflow** | LOW | No mechanism for approved exceptions | Build an exception workflow with approval, expiry, and audit trail |

**Priority order with more time:**
1. Runtime drift detection (Config rules + driftctl)
2. Container image scanning (Trivy in CI)
3. WAF on ALB
4. SIEM integration
5. SCPs for IaC-only enforcement

---

## 5. PCI-DSS Compliance Mapping

### Detailed Control Mapping

| PCI-DSS Req | Sub-Req | What It Requires | How We Address It | Evidence |
|---|---|---|---|---|
| **Req 1** | 1.2 | Restrict connections between untrusted networks and CDE | 3-tier VPC: public (ALB only) → private app → private data. SGs reference each other, not CIDRs. NACLs on data tier. | `modules/networking/main.tf` — SG rules, NACLs, route tables |
| | 1.3 | Prohibit direct public access between internet and CDE | RDS: `publicly_accessible = false`, private data subnet, no IGW route. ECS: private app subnet, no public IP. | `modules/storage/main.tf:120`, `modules/compute/main.tf:145` |
| | 1.3.4 | Allow outbound from CDE only as needed | App SG egress limited to port 5432 (DB) and 443 (HTTPS). Data SG has no egress. NAT gateway for controlled outbound. | `modules/networking/main.tf` — SG egress rules |
| **Req 2** | 2.2 | Develop config standards for all system components | ECS Fargate (no OS to harden). Container runs as non-root (UID 1000), read-only filesystem, all capabilities dropped. | `modules/compute/main.tf` — task definition `linuxParameters` |
| **Req 3** | 3.4 | Render PAN unreadable anywhere it is stored | RDS: `storage_encrypted = true` with CMK. S3: SSE-KMS with CMK. EBS: encrypted. | `modules/storage/main.tf`, `modules/kms/main.tf` |
| | 3.5 | Protect keys used to secure cardholder data | Customer-managed KMS keys with key rotation. Separate keys per service (RDS, S3, EBS, Logs). Key policies restrict usage to specific services. | `modules/kms/main.tf` — 4 separate CMKs with scoped policies |
| **Req 4** | 4.1 | Use strong cryptography to protect CHD during transmission | ALB: TLS 1.2+ only (`ELBSecurityPolicy-TLS13-1-2-2021-06`). HTTP redirect to HTTPS. RDS: `rds.force_ssl = 1`. S3: bucket policy denies `SecureTransport = false` and TLS < 1.2. | `modules/compute/main.tf:43`, `modules/storage/main.tf:79` |
| **Req 7** | 7.1 | Limit access to system components by business need | ECS task role: only `s3:GetObject/PutObject` on CDE bucket, `secretsmanager:GetSecretValue` for DB password, `kms:Decrypt/GenerateDataKey` for CDE KMS key. No other permissions. | `modules/iam/main.tf` — ECS task policy |
| | 7.2 | Default deny; allow only necessary permissions | Zero `Action: *` / `Resource: *` policies. Custom Checkov policy `CKV_YUNO_003` enforces this in CI. | `policies/custom/cde_no_wildcard_iam.py` |
| **Req 8** | 8.3 | Secure all individual non-console administrative access | DB password: `random_password` (32 chars, special) stored in Secrets Manager. No hardcoded credentials anywhere in Terraform. Provider uses IAM role auth. | `modules/storage/main.tf:78`, `terraform/providers.tf` |
| **Req 10** | 10.1 | Audit trails for all access to system components | Multi-region CloudTrail with management events + S3 data events for CDE bucket. | `modules/monitoring/main.tf` — CloudTrail config |
| | 10.2 | Automated audit trails for reconstructing events | S3 access logging on CDE bucket. RDS: `log_connections = 1`, `log_disconnections = 1`, `log_statement = ddl`. ECS: CloudWatch Logs. | `modules/storage/main.tf:55`, `modules/storage/main.tf:157` |
| | 10.5 | Secure audit trails against unauthorized modification | CloudTrail: KMS encryption + `enable_log_file_validation = true`. CloudTrail S3 bucket: BlockPublicAccess + versioning + TLS-only policy. | `modules/monitoring/main.tf:74-75` |
| | 10.6 | Review logs and security events | CloudWatch metric filters + alarms for: root login, SG changes, unauthorized API calls, IAM policy changes. SNS topic for alerting. | `modules/monitoring/main.tf` — 4 metric filters + 4 alarms |
| | 10.7 | Retain audit trail history for at least 12 months | CloudWatch Log Groups: `retention_in_days = 365`. CloudTrail S3: lifecycle policy archives to Glacier at 90 days, expires at 365. | `modules/monitoring/main.tf:28`, `modules/monitoring/main.tf:44` |

### Compliance Artifacts for QSA

| Artifact | Location | Purpose |
|---|---|---|
| Terraform source code | `terraform/` | Proves infrastructure-as-code configuration matches documented controls |
| CI/CD pipeline definition | `.github/workflows/iac-security.yml` | Proves automated security scanning is enforced on every change |
| Custom policy definitions | `policies/custom/` | Proves Yuno-specific compliance rules are codified and enforced |
| Scan results (SARIF) | GitHub Security tab | Proves continuous scanning with documented pass/fail history |
| CloudWatch alarms | `modules/monitoring/main.tf` | Proves PCI-DSS Req 10.6 monitoring controls are in place |
| This document | `THREAT_ANALYSIS.md` | Proves structured security analysis and risk-based decision making |

---

## 6. Architecture Decision Records (ADRs)

### ADR-1: ECS Fargate over EC2 for CDE Workloads
- **Decision:** Use ECS Fargate instead of EC2 instances.
- **Rationale:** Fargate eliminates OS-level attack surface (no SSH, no IMDSv1, no OS patching). PCI-DSS Req 2.2 (hardened configuration) is largely satisfied by the managed compute layer. Reduces operational burden for a team shipping 8-12 PRs/day.
- **Trade-off:** Higher per-vCPU cost than EC2. Acceptable given the security and operational benefits.

### ADR-2: Separate KMS Keys Per Service
- **Decision:** Four separate CMKs (RDS, S3, EBS, Logs) instead of one shared key.
- **Rationale:** PCI-DSS Req 3.5 recommends key isolation. If one key is compromised (e.g., through an overly permissive key policy), only the data encrypted with that specific key is at risk. Key policies can be scoped per service.
- **Trade-off:** More KMS keys to manage and rotate. Worth it for blast radius reduction.

### ADR-3: Block CRITICAL/HIGH, Warn MEDIUM in Pipeline
- **Decision:** Pipeline blocks on CRITICAL and HIGH; MEDIUM findings are visible but non-blocking.
- **Rationale:** With 8-12 PRs/day, blocking on every MEDIUM finding would create unacceptable friction. MEDIUM findings (e.g., missing tags, non-optimal TLS policy) are important but not exploitable vulnerabilities. Tracking them as warnings ensures visibility without blocking velocity.
- **Trade-off:** MEDIUM issues may accumulate if not tracked. Mitigation: weekly triage of MEDIUM backlog.

### ADR-4: Data Tier Has No Internet Route
- **Decision:** Private data subnets have route tables with no internet gateway or NAT gateway route.
- **Rationale:** Defense in depth. Even if an attacker compromises the app tier and pivots to the data subnet, they cannot exfiltrate data directly over the internet from the database. Data can only leave via the app tier, which has controlled egress.
- **Trade-off:** RDS cannot download patches directly; relies on AWS-managed patching which works via AWS internal network. This is the correct behavior for a CDE.
