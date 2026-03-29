# The Terraform Wildfire: Secure IaC for Yuno's New Cloud CDE

## Scenario

It's Monday morning, and Yuno's infrastructure team just completed a rapid expansion into a new cloud region (AWS sa-east-2) to support exploding transaction volume in South America. The rollout happened fast—really fast. Over the past three weeks, six different engineers committed Terraform modules to provision the infrastructure for Yuno's new Cardholder Data Environment (CDE): the isolated cloud environment where sensitive payment card data is processed, stored, and transmitted.

This morning, your manager pulled you into a Slack huddle. The news: Yuno's QSA (Qualified Security Assessor—the third-party auditor for PCI-DSS compliance) ran a preliminary infrastructure scan over the weekend and flagged 23 security findings across the Terraform codebase. The findings range from critical (S3 buckets storing encrypted card vaults with public read access, overly permissive IAM roles that violate least privilege) to concerning (unencrypted RDS databases, security groups allowing 0.0.0.0/0 ingress on non-standard ports, missing VPC flow logs).

The problem: Yuno has a PCI-DSS Level 1 Service Provider assessment starting in 18 days. Infrastructure security issues in the CDE are automatic findings that can delay certification—and without PCI compliance, Yuno cannot process card transactions in the new region. Millions of dollars in revenue are on the line.

**Your mission:** You've been tasked with three things:

1. **Audit and remediate the insecure Terraform modules** — fix the findings so the infrastructure meets PCI-DSS requirements and security best practices.
2. **Build an automated IaC security scanning pipeline** — integrate scanning into the CI/CD workflow so vulnerabilities are caught before they reach production (shift left).
3. **Create prevention mechanisms** — add pre-commit hooks, policy-as-code checks, or other guardrails so these issues can't happen again.

The infrastructure team is moving fast and shipping multiple times per day. Your solution needs to balance two competing priorities: **security rigor** (the QSA won't tolerate misconfigured infrastructure in the CDE) and **developer velocity** (scans can't block every PR or add 20 minutes to the pipeline). How you navigate this trade-off will define your success.

---

## Domain Background

This section explains every payment, compliance, and security concept you'll need.

### Payment & Compliance Concepts

**PCI-DSS (Payment Card Industry Data Security Standard):**
A global security standard mandated by card brands (Visa, Mastercard, Amex) for any organization that stores, processes, or transmits cardholder data. It defines 12 high-level requirements covering network security, access control, encryption, monitoring, and policy. PCI-DSS Level 1 applies to service providers processing more than 300,000 transactions annually and requires an annual on-site audit by a QSA. Non-compliance can result in fines ($5,000–$100,000/month), loss of card processing privileges, and reputational damage.

**Key PCI-DSS requirements relevant to infrastructure:**

- **Requirement 1:** Install and maintain network security controls (firewalls, security groups, NACLs)
- **Requirement 2:** Apply secure configurations to all systems (no default credentials, disable unused services, harden OS/containers)
- **Requirement 3:** Protect stored cardholder data (encryption at rest, key management, tokenization)
- **Requirement 4:** Protect cardholder data in transit (TLS 1.2+, mTLS for internal services)
- **Requirement 7 & 8:** Restrict access by business need-to-know (least privilege IAM, no wildcard permissions)
- **Requirement 10:** Log and monitor all access to cardholder data (VPC flow logs, CloudTrail, audit trails)

**Cardholder Data Environment (CDE):**
The subset of an organization's IT infrastructure that stores, processes, or transmits cardholder data (card number, CVV, expiration date) or sensitive authentication data. The CDE must be logically or physically isolated from other systems (network segmentation). Everything inside the CDE falls under PCI-DSS scope; everything outside does not. Yuno's CDE includes: payment processing APIs, encrypted card vaults (tokenization database), payment gateway connectors, and HSMs (Hardware Security Modules) for cryptographic key storage. Reducing CDE scope (through tokenization, segmentation) is a key strategy to minimize compliance burden.

**QSA (Qualified Security Assessor):**
An independent third-party auditor certified by the PCI Security Standards Council to validate an organization's PCI-DSS compliance. The QSA conducts on-site assessments, reviews documentation, tests controls, and issues a Report on Compliance (ROC) and Attestation of Compliance (AOC).

### Infrastructure Security Concepts

**Infrastructure-as-Code (IaC) Security:**
The practice of scanning cloud infrastructure code (Terraform, CloudFormation, Pulumi) for security misconfigurations before resources are provisioned. Common issues: overly permissive IAM policies, unencrypted storage, publicly exposed resources, missing logging, insecure network rules. Tools like Checkov, tfsec, Trivy, Snyk IaC, and Terrascan can detect these issues statically.

**Shift Left:**
The philosophy of moving security checks earlier in the development lifecycle — from production monitoring → pre-production testing → CI/CD pipelines → developer workstations (pre-commit hooks). The earlier a vulnerability is caught, the cheaper and faster it is to fix. Shift-left for IaC means scanning Terraform during git commit, in pull request checks, and in CI/CD pipelines — not after `terraform apply`.

**Pre-commit Hooks:**
Scripts that run automatically on a developer's local machine when they run `git commit`. They can block commits that fail security checks (e.g., hardcoded secrets, Terraform files with critical misconfigurations). Frameworks like `pre-commit` (Python) make this easy to configure and share across teams.

**Policy-as-Code:**
Defining security, compliance, and operational policies as machine-readable code that can be automatically enforced. For IaC, this often means tools like:

- **Open Policy Agent (OPA)** with Rego policies
- **HashiCorp Sentinel** (commercial, Terraform-native)
- **Checkov custom policies** (Python-based)
- **Cloud Custodian** for runtime cloud resource policies

Example policy: *"All S3 buckets in the CDE must have BlockPublicAccess enabled and use AES256 or aws:kms encryption."*

**Least Privilege (IAM):**
The principle that every identity (user, service, role) should have the minimum permissions necessary to perform its job — and no more. In AWS, this means avoiding wildcard actions (`*`) and resources (`*`), granting permissions only on specific resources, and using conditions to further restrict access (e.g., "allow S3 access only from the CDE VPC").

**Defense in Depth:**
Layering multiple security controls so that if one fails, others provide backup protection. For cloud infrastructure: network segmentation (VPCs, subnets, NACLs) + security groups + IAM policies + encryption + logging + runtime monitoring.

**Supply Chain Security:**
Ensuring the integrity and provenance of dependencies. For IaC, this means:

- **SBOM (Software Bill of Materials):** A list of all Terraform modules, providers, and dependencies
- **Module Verification:** Using only trusted Terraform modules from verified sources (official HashiCorp registry, private registries with signing)
- **Terraform Lock Files:** `terraform.lock.hcl` pins provider versions to prevent supply chain attacks via malicious provider updates

---

## Requirements

You will produce a working solution that demonstrates secure Infrastructure-as-Code practices for Yuno's new CDE. Your solution must include:

### 1. Remediated Terraform Modules (Core Requirement)

Imagine the existing Terraform codebase provisions a simplified CDE with these resources (you'll create these modules yourself as part of the challenge):

- VPC with public and private subnets
- RDS PostgreSQL database for storing tokenized card vaults (encrypted PANs)
- S3 bucket for encrypted backups of cardholder data
- Application Load Balancer (ALB) for payment API traffic
- IAM roles and policies for EC2 instances or ECS tasks running payment services
- Security groups controlling network access
- CloudWatch log groups and/or VPC Flow Logs for audit trails

**Your task:**
Write or refactor Terraform modules that provision these resources in a PCI-DSS compliant and secure manner. Each resource must follow security best practices and address the types of issues the QSA flagged:

- **Encryption:** All data at rest must be encrypted (RDS, S3). Use KMS where appropriate.
- **Least privilege IAM:** No wildcard (`*`) actions or resources. Roles should have only the permissions needed.
- **Network security:** No public internet access to databases or internal services. Security groups should follow deny-by-default (no `0.0.0.0/0` on sensitive ports).
- **Logging:** VPC Flow Logs and CloudWatch Logs must be enabled for audit trails (PCI-DSS Requirement 10).
- **Public access controls:** S3 buckets must have BlockPublicAccess enabled.
- **Tagging:** Resources must be tagged to identify them as part of the CDE (e.g., `Environment = CDE`, `PCI_Scope = In-Scope`).

The Terraform code should be modular, reusable, and include variables for configurability (region, environment, etc.). It does NOT need to be deployed to a real AWS account — syntactic correctness and logical soundness are sufficient.

### 2. Automated IaC Security Scanning Pipeline (Core Requirement)

Build a CI/CD pipeline that scans Terraform code for security issues before it's merged or applied. The pipeline must:

- **Scan for misconfigurations:** Use at least one IaC security scanning tool (Checkov, tfsec, Trivy, Snyk IaC, or similar) to detect issues like unencrypted storage, overly permissive IAM, public exposure, missing logging, etc.
- **Fail on critical findings:** The pipeline should block PRs/deployments if critical or high-severity issues are found. Define what "critical" means in your context.
- **Provide actionable output:** Scan results should be easy for developers to understand and fix (line numbers, remediation advice, links to documentation).
- **Run in CI/CD:** Integrate scanning into a GitHub Actions, GitLab CI, CircleCI, or similar workflow. The pipeline definition should be included in your repo.

**The ambiguity you must navigate:**
The infrastructure team ships 8-12 pull requests per day. Scans must run fast enough that they don't bottleneck the team, but they must also be thorough enough to catch real issues before production. You need to balance scan coverage, speed, and developer experience. If you choose to allow some findings to pass as warnings instead of failures, document why and what risks remain.

### 3. Prevention Mechanisms (Core Requirement)

Implement at least one mechanism to prevent insecure Terraform code from being committed in the first place (shift further left). Options include:

- **Pre-commit hooks:** Configure a local git hook that scans Terraform files before commit and blocks commits with critical issues.
- **Custom policy enforcement:** Write at least one custom policy (OPA Rego, Checkov Python policy, or similar) that enforces a Yuno-specific rule (e.g., *"All RDS instances in the CDE must use `storage_encrypted = true` and KMS encryption"*).
- **Terraform validation scripts:** A script that runs `terraform validate`, `terraform fmt -check`, and security scans as a pre-flight check.

Provide clear setup instructions so other engineers can enable these checks on their local machines.

### 4. Threat Analysis & Design Decisions (Core Requirement)

Include a written document (Markdown, PDF, or section in your README) with:

- **Threat Model:** What are the attack vectors for misconfigured cloud infrastructure in a CDE? Who are the threat actors (external attackers, malicious insiders, accidental misconfigurations)? What's the blast radius if an S3 bucket with cardholder data is made public, or an IAM role is over-permissioned?
- **Tool & Control Selection:** Why did you choose the scanning tools, policy engines, and security controls you did? What alternatives did you consider?
- **Trade-offs:** How did you balance security strictness (e.g., failing the pipeline on every minor finding) versus developer velocity (e.g., fast feedback loops, minimal pipeline time)? Where did you draw the line between "block" and "warn"?
- **Residual Risks:** What security gaps remain in your solution? What would you add with more time (runtime security, drift detection, automated remediation, policy exceptions workflow)?
- **Compliance Mapping:** How does your solution address PCI-DSS Requirements 1, 2, 3, 4, 7, 8, and 10? Be specific.

This writeup is a **critical** part of the challenge. It demonstrates your security thinking and judgment, not just your ability to run tools.

---

## Stretch Goals (Optional — Partial Completion Expected)

If you complete the core requirements ahead of schedule, consider adding:

- **Terraform Module Testing:** Write automated tests (Terratest, terraform-compliance, or OPA tests) to verify your modules' security posture.
- **Drift Detection:** A mechanism to detect when cloud resources drift from the Terraform state (e.g., someone manually modifies a security group in the console).
- **Secrets Scanning:** Integrate a tool (Gitleaks, Trufflehog, detect-secrets) to scan for hardcoded secrets in Terraform files or variables.
- **Pipeline Visualization:** A summary dashboard or report that visualizes scan results, pass/fail trends, or remediation metrics.
- **Custom Remediation Scripts:** Automated scripts that fix common issues (e.g., add BlockPublicAccess to all S3 buckets, enable encryption on all RDS instances).

Partial completion of stretch goals is welcomed and demonstrates how you prioritize under time constraints.

---

## What Success Looks Like

A strong submission will include:

- **Clean, secure Terraform modules** that provision a CDE-representative infrastructure following AWS and PCI-DSS best practices.
- **A working CI/CD pipeline** (or pipeline definition) that meaningfully scans IaC for security issues, fails on critical findings, and provides clear output.
- **At least one shift-left prevention mechanism** (pre-commit hook, custom policy, validation script) with setup instructions.
- **A thoughtful written threat analysis and design decisions** document that explains your security reasoning, trade-offs, and residual risks.
- **Clear documentation** (README) explaining what you built, how to run it, what design decisions you made, and what you'd do next.

You are **NOT** expected to deploy this to a live AWS account — syntactically correct and logically sound code is sufficient. Focus on demonstrating DevSecOps thinking: automation, shift-left, least privilege, defense in depth, and compliance alignment.

---

## Constraints

- **Time:** 2 hours. You MAY use AI coding assistants (Claude, Cursor, Copilot, ChatGPT). Prioritize core requirements; stretch goals are optional.
- **Technology:** You may use any IaC tool (Terraform preferred, but Pulumi/CDK acceptable), any CI/CD platform (GitHub Actions, GitLab CI, CircleCI, etc.), and any scanning tools (Checkov, tfsec, Trivy, Snyk, etc.). Choose what you know best.
- **Scope:** This is a DEFENSIVE security challenge — you are building secure infrastructure and scanning tools, NOT exploiting vulnerabilities or writing attack code.
- **Real-world inspiration:** This scenario is inspired by actual PCI-DSS audit findings and IaC security incidents at payment companies. Treat it as a real production incident.

---

## Submission

Provide a public or private Git repository (GitHub, GitLab, Bitbucket) containing:

1. Terraform modules (or IaC of choice)
2. CI/CD pipeline configuration files
3. Pre-commit hook or policy-as-code files
4. Threat Analysis & Design Decisions document
5. README with setup instructions and design explanations

The repository should be well-organized, with a clear directory structure and meaningful commit messages. Code quality and documentation matter.

---

## Deliverables

- A Git repository containing Terraform modules for a secure CDE (VPC, RDS, S3, ALB, IAM, security groups, logging) following PCI-DSS and AWS security best practices
- CI/CD pipeline configuration file (GitHub Actions, GitLab CI, or equivalent) with IaC security scanning stages, clear pass/fail policy, and actionable output
- At least one shift-left prevention mechanism (pre-commit hook configuration, custom policy-as-code file, or validation script) with setup instructions
- Threat Analysis & Design Decisions document (Markdown or PDF) covering threat model, tool selection rationale, security vs. velocity trade-offs, residual risks, and PCI-DSS compliance mapping
- README with setup instructions, design decisions, what you built, how to run/test it, and next steps if you had more time

---

## Evaluation Criteria

### Infrastructure Security Controls (30 pts)

Terraform modules demonstrate encryption at rest (RDS, S3), least privilege IAM (no wildcard permissions), network segmentation (no public access to databases), logging enabled (VPC Flow Logs, CloudWatch), and S3 BlockPublicAccess configured.

| Score Range | Description |
|---|---|
| **0–12 pts** | Multiple critical misconfigurations remain (unencrypted storage, `0.0.0.0/0` on sensitive ports, overly permissive IAM). |
| **15–21 pts** | Most issues fixed, but some IAM permissions are broader than necessary or logging is incomplete. |
| **24–30 pts** | Infrastructure follows defense-in-depth and least privilege; all major PCI-DSS infrastructure requirements addressed; resources properly tagged. |

---

### Pipeline/Automation Quality (25 pts)

CI/CD pipeline integrates IaC scanning, defines clear pass/fail criteria, runs efficiently, and produces actionable output for developers.

| Score Range | Description |
|---|---|
| **0–10 pts** | Pipeline is incomplete, scans are ineffective or don't fail on critical issues, or output is unclear. |
| **12–17 pts** | Pipeline scans for misconfigurations and fails on some critical issues, but policy could be tighter or output could be more actionable. |
| **20–25 pts** | Pipeline is production-ready: scans are comprehensive, failures are well-justified, output includes remediation guidance, and scan time is reasonable (<5 min). |

---

### Threat Analysis & Design Decisions (20 pts)

Written document articulates threat model (attack vectors, threat actors, blast radius), tool selection rationale, security vs. velocity trade-offs, residual risks, and PCI-DSS compliance mapping.

| Score Range | Description |
|---|---|
| **0–8 pts** | Shallow or missing analysis; no threat model or trade-off discussion; generic statements. |
| **10–14 pts** | Competent analysis with a basic threat model and trade-offs mentioned, but lacks depth or specificity. |
| **16–20 pts** | Deep, nuanced analysis showing strong security thinking: specific threats identified, clear rationale for design choices, honest discussion of trade-offs and risks, and explicit PCI-DSS mapping. |

---

### Code Quality & Organization (15 pts)

Terraform modules are modular and reusable, code is clean and well-structured, repo is organized with clear directory structure, and README provides clear setup instructions.

| Score Range | Description |
|---|---|
| **0–6 pts** | Code is monolithic or hard to follow, minimal documentation, unclear how to run or test. |
| **7–10 pts** | Code is reasonably organized, modules exist, and README covers the basics. |
| **12–15 pts** | Code is production-quality: DRY, modular, well-commented, repo has clear structure, README is comprehensive, and setup instructions are easy to follow. |

---

### PCI-DSS/Compliance Alignment (10 pts)

Solution demonstrates awareness of PCI-DSS requirements relevant to infrastructure (Req 1, 2, 3, 4, 7, 8, 10) and how the controls map to compliance obligations.

| Score Range | Description |
|---|---|
| **0–4 pts** | Little to no consideration of PCI-DSS; resources are generically secure but not compliance-aware. |
| **5–7 pts** | Some compliance awareness (encryption, logging, least privilege) but mapping is vague or incomplete. |
| **8–10 pts** | Clear understanding of PCI-DSS infrastructure requirements, explicit mapping in documentation, and controls are designed with compliance in mind (tagging, segmentation, audit trails). |

---

### Total: 100 pts