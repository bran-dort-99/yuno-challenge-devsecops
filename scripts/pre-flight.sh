#!/usr/bin/env bash
# ============================================================
# Yuno CDE — Pre-flight Validation Script
#
# Run before terraform plan/apply to catch issues locally.
# Usage: ./scripts/pre-flight.sh [terraform_dir]
#
# Exit codes:
#   0 = all checks passed
#   1 = one or more checks failed (do not proceed to apply)
# ============================================================

set -euo pipefail

TF_DIR="${1:-terraform}"
POLICY_DIR="policies/custom"
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'
FAILED=0

echo "=============================================="
echo "  Yuno CDE — Pre-flight Security Validation"
echo "=============================================="
echo ""

# ── Step 1: Terraform Format ──────────────────────────────────
echo -n "[1/6] Checking terraform fmt..."
if terraform -chdir="$TF_DIR" fmt -check -recursive > /dev/null 2>&1; then
    echo -e " ${GREEN}PASSED${NC}"
else
    echo -e " ${RED}FAILED${NC} — run 'terraform fmt -recursive'"
    FAILED=1
fi

# ── Step 2: Terraform Validate ────────────────────────────────
echo -n "[2/6] Running terraform validate..."
if terraform -chdir="$TF_DIR" init -backend=false > /dev/null 2>&1 && \
   terraform -chdir="$TF_DIR" validate > /dev/null 2>&1; then
    echo -e " ${GREEN}PASSED${NC}"
else
    echo -e " ${RED}FAILED${NC} — fix HCL syntax errors"
    FAILED=1
fi

# ── Step 3: tfsec ─────────────────────────────────────────────
echo -n "[3/6] Running tfsec (CRITICAL/HIGH)..."
if command -v tfsec &> /dev/null; then
    if tfsec "$TF_DIR" --minimum-severity HIGH --concise-output > /dev/null 2>&1; then
        echo -e " ${GREEN}PASSED${NC}"
    else
        echo -e " ${RED}FAILED${NC} — CRITICAL/HIGH findings detected"
        tfsec "$TF_DIR" --minimum-severity HIGH --concise-output 2>&1 | tail -20
        FAILED=1
    fi
else
    echo -e " ${YELLOW}SKIPPED${NC} — tfsec not installed (brew install tfsec)"
fi

# ── Step 4: Checkov with custom policies ──────────────────────
echo -n "[4/6] Running checkov with CDE policies..."
if command -v checkov &> /dev/null; then
    if checkov -d "$TF_DIR" \
        --external-checks-dir "$POLICY_DIR" \
        --hard-fail-on CRITICAL,HIGH \
        --soft-fail-on MEDIUM,LOW \
        --compact --quiet > /dev/null 2>&1; then
        echo -e " ${GREEN}PASSED${NC}"
    else
        echo -e " ${RED}FAILED${NC} — policy violations detected"
        checkov -d "$TF_DIR" \
            --external-checks-dir "$POLICY_DIR" \
            --hard-fail-on CRITICAL,HIGH \
            --compact --quiet 2>&1 | grep -E "FAILED|CKV" | head -20
        FAILED=1
    fi
else
    echo -e " ${YELLOW}SKIPPED${NC} — checkov not installed (pip install checkov)"
fi

# ── Step 5: Secrets Scan ──────────────────────────────────────
echo -n "[5/6] Scanning for hardcoded secrets..."
if command -v gitleaks &> /dev/null; then
    if gitleaks detect --source . --no-git > /dev/null 2>&1; then
        echo -e " ${GREEN}PASSED${NC}"
    else
        echo -e " ${RED}FAILED${NC} — potential secrets detected!"
        FAILED=1
    fi
else
    # Fallback: basic pattern matching
    SECRETS_FOUND=$(grep -rn \
        -e "AKIA[0-9A-Z]\{16\}" \
        -e "-----BEGIN.*PRIVATE KEY-----" \
        -e "password\s*=\s*\"[^\"]\{8,\}\"" \
        "$TF_DIR" 2>/dev/null | grep -v "random_password" | wc -l)
    if [ "$SECRETS_FOUND" -gt 0 ]; then
        echo -e " ${RED}FAILED${NC} — potential secrets found in Terraform files"
        FAILED=1
    else
        echo -e " ${GREEN}PASSED${NC} (basic pattern scan)"
    fi
fi

# ── Step 6: Custom CDE Checks ────────────────────────────────
echo -n "[6/6] Verifying CDE-specific requirements..."
CDE_ISSUES=0

# Check: No publicly_accessible = true in any .tf file
if grep -rn "publicly_accessible\s*=\s*true" "$TF_DIR" > /dev/null 2>&1; then
    echo ""
    echo "  [FAIL] publicly_accessible = true found — PCI-DSS Req 1.3 violation"
    CDE_ISSUES=$((CDE_ISSUES + 1))
fi

# Check: No storage_encrypted = false
if grep -rn "storage_encrypted\s*=\s*false" "$TF_DIR" > /dev/null 2>&1; then
    echo ""
    echo "  [FAIL] storage_encrypted = false found — PCI-DSS Req 3.4 violation"
    CDE_ISSUES=$((CDE_ISSUES + 1))
fi

# Check: No 0.0.0.0/0 on non-443 ingress (rough check)
if grep -B5 "0\.0\.0\.0/0" "$TF_DIR"/modules/*/main.tf 2>/dev/null | \
   grep -E "from_port\s*=\s*(22|3306|5432|3389)" > /dev/null 2>&1; then
    echo ""
    echo "  [FAIL] 0.0.0.0/0 on sensitive port — PCI-DSS Req 1.2 violation"
    CDE_ISSUES=$((CDE_ISSUES + 1))
fi

if [ "$CDE_ISSUES" -eq 0 ]; then
    echo -e " ${GREEN}PASSED${NC}"
else
    echo -e " ${RED}FAILED${NC} — $CDE_ISSUES CDE-specific issues found"
    FAILED=1
fi

# ── Summary ───────────────────────────────────────────────────
echo ""
echo "=============================================="
if [ "$FAILED" -eq 0 ]; then
    echo -e "  ${GREEN}ALL CHECKS PASSED${NC} — safe to proceed with terraform plan"
else
    echo -e "  ${RED}CHECKS FAILED${NC} — fix issues before proceeding"
fi
echo "=============================================="

exit $FAILED
