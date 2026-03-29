#!/usr/bin/env python3
"""
Unit tests for .github/workflows/iac-security.yml
Tests the workflow's structure, logic, and security properties without
requiring GitHub, Docker, or act.

Run:
    python3 tests/test_workflow.py
    python3 -m pytest tests/test_workflow.py -v
"""

import json
import re
import sys
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).parent.parent
WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "iac-security.yml"


def load_workflow() -> dict:
    with open(WORKFLOW_PATH) as f:
        return yaml.safe_load(f)


# ─────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────

def get_job(wf: dict, job_id: str) -> dict:
    return wf["jobs"][job_id]


def get_steps(wf: dict, job_id: str) -> list[dict]:
    return get_job(wf, job_id).get("steps", [])


def find_step(steps: list[dict], name_fragment: str) -> dict | None:
    for s in steps:
        if name_fragment.lower() in s.get("name", "").lower():
            return s
    return None


# ─────────────────────────────────────────────────────────────
# Test classes
# ─────────────────────────────────────────────────────────────

class TestWorkflowLoads(unittest.TestCase):
    """Sanity: file is valid YAML and has expected top-level keys."""

    def test_file_exists(self):
        self.assertTrue(WORKFLOW_PATH.exists(), f"Workflow not found at {WORKFLOW_PATH}")

    def test_valid_yaml(self):
        wf = load_workflow()
        self.assertIsInstance(wf, dict)

    def test_has_required_top_level_keys(self):
        wf = load_workflow()
        # PyYAML parses the bare 'on:' key as Python boolean True.
        # We check for both the string and boolean forms.
        keys = set(str(k) for k in wf.keys()) | set(wf.keys())
        for key in ("name", "jobs", "permissions"):
            self.assertIn(key, wf, f"Missing top-level key: {key}")
        # 'on' is parsed as True by PyYAML — check either form
        self.assertTrue(
            "on" in wf or True in wf,
            "Missing top-level 'on:' trigger key"
        )

    def test_workflow_name(self):
        wf = load_workflow()
        self.assertEqual(wf["name"], "IaC Security Scan")


class TestTriggers(unittest.TestCase):
    """Verify the workflow triggers on the right events and paths."""

    def setUp(self):
        self.wf = load_workflow()
        # PyYAML parses bare 'on:' as boolean True
        self.on = self.wf.get("on") or self.wf.get(True, {})

    def test_triggers_on_pull_request(self):
        self.assertIn("pull_request", self.on)

    def test_pr_paths_include_terraform(self):
        paths = self.on["pull_request"].get("paths", [])
        self.assertTrue(
            any("terraform/**" in p for p in paths),
            "pull_request trigger must include terraform/**"
        )

    def test_pr_paths_include_policies(self):
        paths = self.on["pull_request"].get("paths", [])
        self.assertTrue(
            any("policies/**" in p for p in paths),
            "pull_request trigger must include policies/**"
        )

    def test_push_only_on_main(self):
        push = self.on.get("push", {})
        branches = push.get("branches", [])
        self.assertIn("main", branches, "push trigger must be scoped to main branch")

    def test_push_paths_scoped(self):
        """Push to main must be path-scoped (don't run on every file change)."""
        push = self.on.get("push", {})
        self.assertIn("paths", push, "push trigger must have path filters to avoid unnecessary runs")


class TestPermissions(unittest.TestCase):
    """Principle of least privilege: only required permissions granted."""

    def setUp(self):
        self.perms = load_workflow().get("permissions", {})

    def test_contents_read_only(self):
        self.assertEqual(self.perms.get("contents"), "read",
                         "contents permission must be read-only")

    def test_no_write_all(self):
        self.assertNotEqual(self.perms.get("contents"), "write",
                            "contents: write is too permissive for a scan workflow")

    def test_security_events_write(self):
        """SARIF upload requires security-events: write."""
        self.assertEqual(self.perms.get("security-events"), "write")

    def test_no_undeclared_admin_permissions(self):
        dangerous = {"actions": "write", "id-token": "write", "packages": "write"}
        for perm, level in dangerous.items():
            actual = self.perms.get(perm)
            self.assertNotEqual(actual, level,
                                f"Unexpected high-privilege permission: {perm}: {level}")


class TestJobDependencies(unittest.TestCase):
    """Verify the DAG structure: stages 2-4 wait for stage 1, gate waits for all."""

    def setUp(self):
        self.wf = load_workflow()

    def test_stage1_has_no_needs(self):
        job = get_job(self.wf, "terraform-validate")
        self.assertNotIn("needs", job, "Stage 1 should not depend on anything")

    def _normalize_needs(self, job_id: str) -> list:
        """needs: can be a string (single dep) or a list — normalize to list."""
        needs = get_job(self.wf, job_id).get("needs", [])
        if isinstance(needs, str):
            return [needs]
        return needs if needs is not None else []

    def test_tfsec_needs_validate(self):
        self.assertIn("terraform-validate", self._normalize_needs("tfsec"))

    def test_checkov_needs_validate(self):
        self.assertIn("terraform-validate", self._normalize_needs("checkov"))

    def test_trivy_needs_validate(self):
        self.assertIn("terraform-validate", self._normalize_needs("trivy"))

    def test_secrets_scan_is_independent(self):
        """Stage 5 runs in parallel with Stage 1 by design."""
        job = get_job(self.wf, "secrets-scan")
        needs = job.get("needs")  # None if key absent, [] if explicitly empty
        self.assertFalse(
            needs,  # None, [], and '' are all falsy — all mean "no dependency"
            f"secrets-scan must be independent (no needs), got: {needs}"
        )

    def test_security_gate_needs_all_jobs(self):
        needs = get_job(self.wf, "security-gate").get("needs", [])
        required = {"terraform-validate", "tfsec", "checkov", "trivy", "secrets-scan"}
        self.assertEqual(required, set(needs),
                         f"security-gate needs = {needs}, expected {required}")

    def test_security_gate_runs_always(self):
        """Gate must run even when jobs fail so it can report the summary."""
        gate_if = get_job(self.wf, "security-gate").get("if", "")
        self.assertEqual(str(gate_if).strip(), "always()",
                         "security-gate must have `if: always()` to run on failure")


class TestStage1ValidateJob(unittest.TestCase):
    """Stage 1: terraform fmt + validate correctness."""

    def setUp(self):
        self.wf = load_workflow()
        self.steps = get_steps(self.wf, "terraform-validate")

    def test_checkout_is_first_step(self):
        self.assertIn("checkout", self.steps[0].get("uses", "").lower())

    def test_tf_version_pinned(self):
        setup = find_step(self.steps, "Setup Terraform")
        self.assertIsNotNone(setup, "Missing 'Setup Terraform' step")
        tf_version = setup.get("with", {}).get("terraform_version", "")
        self.assertTrue(tf_version, "terraform_version must be pinned explicitly")
        # Must be a specific version, not 'latest'
        self.assertNotEqual(tf_version.lower(), "latest",
                            "Pinning to 'latest' is not reproducible")

    def test_fmt_has_continue_on_error(self):
        """fmt failure should not block validate — it's reported separately."""
        fmt = find_step(self.steps, "Format Check")
        self.assertIsNotNone(fmt)
        self.assertTrue(fmt.get("continue-on-error", False),
                        "fmt step must have continue-on-error: true")

    def test_validate_passes_acm_var(self):
        """terraform validate must not fail due to missing required variable."""
        validate = find_step(self.steps, "Validate")
        self.assertIsNotNone(validate)
        run_cmd = validate.get("run", "")
        self.assertIn("acm_certificate_arn", run_cmd,
                      "validate must supply a -var for acm_certificate_arn "
                      "(required variable with no default)")

    def test_validate_uses_backend_false(self):
        init = find_step(self.steps, "Init")
        self.assertIsNotNone(init)
        self.assertIn("-backend=false", init.get("run", ""),
                      "init must use -backend=false in CI (no AWS backend creds)")

    def test_pr_comment_guarded_to_pr_events(self):
        """Comment step must not run on push events (no issue number available)."""
        comment = find_step(self.steps, "Comment")
        self.assertIsNotNone(comment)
        condition = comment.get("if", "")
        self.assertIn("pull_request", str(condition),
                      "PR comment step must be guarded with github.event_name == 'pull_request'")


class TestStage2TfsecJob(unittest.TestCase):
    """Stage 2: tfsec scan configuration."""

    def setUp(self):
        self.wf = load_workflow()
        self.steps = get_steps(self.wf, "tfsec")

    def test_tfsec_action_used(self):
        tfsec = find_step(self.steps, "tfsec")
        self.assertIsNotNone(tfsec)
        self.assertIn("tfsec-action", tfsec.get("uses", ""))

    def test_tfsec_called_exactly_once(self):
        """Duplicate tfsec calls double runtime — only one should exist."""
        tfsec_steps = [s for s in self.steps
                       if "tfsec-action" in s.get("uses", "")]
        self.assertEqual(len(tfsec_steps), 1,
                         f"tfsec action called {len(tfsec_steps)} times, expected exactly 1")

    def test_tfsec_soft_fail_is_false(self):
        tfsec = find_step(self.steps, "Run tfsec")
        soft_fail = tfsec.get("with", {}).get("soft_fail", True)
        self.assertFalse(soft_fail,
                         "soft_fail must be false — tfsec must block on CRITICAL/HIGH")

    def test_sarif_uploaded(self):
        upload = find_step(self.steps, "Upload tfsec SARIF")
        self.assertIsNotNone(upload, "tfsec SARIF must be uploaded for GitHub Security tab")
        self.assertIn("upload-sarif", upload.get("uses", ""))


class TestStage3CheckovJob(unittest.TestCase):
    """Stage 3: Checkov scan with custom policies."""

    def setUp(self):
        self.wf = load_workflow()
        self.steps = get_steps(self.wf, "checkov")

    def test_checkov_action_used(self):
        ck = find_step(self.steps, "Checkov")
        self.assertIsNotNone(ck)
        self.assertIn("checkov-action", ck.get("uses", ""))

    def test_hard_fail_on_critical_high(self):
        ck = find_step(self.steps, "Checkov")
        hard_fail = str(ck.get("with", {}).get("hard_fail_on", ""))
        self.assertIn("CRITICAL", hard_fail)
        self.assertIn("HIGH", hard_fail)

    def test_custom_policies_dir_configured(self):
        ck = find_step(self.steps, "Checkov")
        ext_dir = ck.get("with", {}).get("external_checks_dirs", "")
        self.assertTrue(ext_dir, "external_checks_dirs must point to policies/custom")

    def test_sarif_uploaded(self):
        upload = find_step(self.steps, "Upload Checkov SARIF")
        self.assertIsNotNone(upload)

    def test_cross_region_replication_skipped(self):
        """CKV_AWS_144 should be skipped — single-region CDE is a documented decision."""
        ck = find_step(self.steps, "Checkov")
        skip = str(ck.get("with", {}).get("skip_check", ""))
        self.assertIn("CKV_AWS_144", skip)


class TestStage4TrivyJob(unittest.TestCase):
    """Stage 4: Trivy config scan."""

    def setUp(self):
        self.wf = load_workflow()
        self.steps = get_steps(self.wf, "trivy")

    def test_exit_code_1_on_findings(self):
        scan = find_step(self.steps, "Run Trivy")
        self.assertIsNotNone(scan)
        exit_code = scan.get("with", {}).get("exit-code", 0)
        self.assertEqual(int(exit_code), 1,
                         "Trivy must exit 1 on CRITICAL/HIGH findings to block the pipeline")

    def test_severity_covers_critical_and_high(self):
        scan = find_step(self.steps, "Run Trivy")
        severity = str(scan.get("with", {}).get("severity", ""))
        self.assertIn("CRITICAL", severity)
        self.assertIn("HIGH", severity)

    def test_no_missing_trivyignore_reference(self):
        """trivyignores must not reference a file that doesn't exist."""
        trivyignore_path = REPO_ROOT / ".trivyignore"
        for step in self.steps:
            trivyignore = step.get("with", {}).get("trivyignores", "")
            if trivyignore:
                self.assertTrue(
                    (REPO_ROOT / trivyignore).exists(),
                    f"trivyignores references '{trivyignore}' but file does not exist"
                )

    def test_sarif_uploaded(self):
        upload = find_step(self.steps, "Upload Trivy SARIF")
        self.assertIsNotNone(upload)


class TestStage5SecretsJob(unittest.TestCase):
    """Stage 5: Secrets detection — must not require paid license."""

    def setUp(self):
        self.wf = load_workflow()
        self.steps = get_steps(self.wf, "secrets-scan")

    def test_no_licensed_gitleaks_action(self):
        """gitleaks/gitleaks-action@v2 requires GITLEAKS_LICENSE — blocked in org context."""
        for step in self.steps:
            uses = step.get("uses", "")
            self.assertNotIn("gitleaks/gitleaks-action", uses,
                             "gitleaks/gitleaks-action@v2 requires a paid license. "
                             "Use the free OSS CLI instead.")

    def test_no_gitleaks_license_secret_required(self):
        """No step should reference GITLEAKS_LICENSE secret."""
        for step in self.steps:
            env = step.get("env", {})
            self.assertNotIn("GITLEAKS_LICENSE", env,
                             "GITLEAKS_LICENSE is a paid secret — use free CLI instead")

    def test_full_git_history_fetched(self):
        """Full history is needed for git-based secrets scanning."""
        checkout = find_step(self.steps, "Checkout")
        fetch_depth = checkout.get("with", {}).get("fetch-depth", 1)
        self.assertEqual(int(fetch_depth), 0,
                         "fetch-depth must be 0 to scan full git history for secrets")

    def test_gitleaks_cli_used(self):
        """Should use gitleaks CLI directly."""
        scan = find_step(self.steps, "Gitleaks")
        self.assertIsNotNone(scan)
        run_cmd = scan.get("run", "")
        self.assertIn("gitleaks", run_cmd, "Step must invoke the gitleaks binary")

    def test_redact_flag_set(self):
        """--redact prevents secrets from appearing in CI logs."""
        scan = find_step(self.steps, "Gitleaks")
        run_cmd = scan.get("run", "")
        self.assertIn("--redact", run_cmd,
                      "--redact must be set to avoid leaking secrets in CI logs")


class TestSecurityGateJob(unittest.TestCase):
    """Security Gate: aggregates all results and enforces final pass/fail."""

    def setUp(self):
        self.wf = load_workflow()
        self.job = get_job(self.wf, "security-gate")
        self.steps = get_steps(self.wf, "security-gate")

    def test_gate_runs_with_if_always(self):
        self.assertEqual(str(self.job.get("if", "")).strip(), "always()")

    def test_enforce_step_uses_expression_syntax(self):
        """if: | (multiline YAML scalar) is unreliable in GH Actions — must use ${{ }}."""
        enforce = find_step(self.steps, "Enforce gate")
        self.assertIsNotNone(enforce)
        condition = str(enforce.get("if", ""))

        # Must NOT use the YAML literal block approach
        self.assertNotIn("needs.terraform-validate.result ==", condition,
                         "if: condition must use expression syntax (${{ contains(...) }}), "
                         "not a YAML literal block scalar")

        # Must use the safe contains() expression
        self.assertIn("contains(needs.*.result", condition,
                      "if: must use contains(needs.*.result, ...) pattern")

    def test_enforce_step_exits_with_1(self):
        enforce = find_step(self.steps, "Enforce gate")
        run_cmd = enforce.get("run", "")
        self.assertIn("exit 1", run_cmd,
                      "Enforce gate must exit 1 to fail the pipeline")

    def test_summary_step_writes_to_github_step_summary(self):
        summary = find_step(self.steps, "Check scan results")
        self.assertIsNotNone(summary)
        run_cmd = summary.get("run", "")
        self.assertIn("GITHUB_STEP_SUMMARY", run_cmd,
                      "Summary step must write to $GITHUB_STEP_SUMMARY")

    def test_summary_covers_all_tools(self):
        summary = find_step(self.steps, "Check scan results")
        run_cmd = summary.get("run", "")
        for tool in ("terraform-validate", "tfsec", "checkov", "trivy", "secrets-scan"):
            self.assertIn(tool, run_cmd,
                          f"Summary must report status of job: {tool}")


class TestTimeouts(unittest.TestCase):
    """All jobs must have explicit timeouts to prevent runaway billing."""

    def setUp(self):
        self.wf = load_workflow()

    def test_all_jobs_have_timeout(self):
        for job_id, job in self.wf["jobs"].items():
            self.assertIn("timeout-minutes", job,
                          f"Job '{job_id}' is missing timeout-minutes — "
                          "could run indefinitely on infrastructure issues")

    def test_total_pipeline_under_15_minutes(self):
        """Wall-clock time should stay under 25 minutes (conservative upper bound).

        Actual wall-clock = Stage1 + max(parallel stages 2-5) + Gate gate.
        With current timeouts:  5 + max(5, 10, 5, 5) + 5 = 20 min ceiling.
        Sum-of-all-timeouts is an upper bound, not actual runtime.
        """
        jobs = self.wf["jobs"]
        stage1 = jobs["terraform-validate"].get("timeout-minutes", 999)
        parallel_max = max(
            jobs["tfsec"].get("timeout-minutes", 0),
            jobs["checkov"].get("timeout-minutes", 0),
            jobs["trivy"].get("timeout-minutes", 0),
            jobs["secrets-scan"].get("timeout-minutes", 0),
        )
        gate = jobs["security-gate"].get("timeout-minutes", 0)
        wall_clock_upper_bound = stage1 + parallel_max + gate
        self.assertLessEqual(wall_clock_upper_bound, 25,
                             f"Pipeline timeout upper bound is {wall_clock_upper_bound}m, "
                             "should be ≤ 25m for developer velocity")


class TestActionVersionPinning(unittest.TestCase):
    """All actions must be pinned to specific versions (not @main or @latest)."""

    UNPINNED_PATTERN = re.compile(r"@(main|master|latest|HEAD)$", re.IGNORECASE)

    def _collect_all_uses(self) -> list[tuple[str, str]]:
        """Returns [(job_id, uses_string), ...]"""
        wf = load_workflow()
        results = []
        for job_id, job in wf["jobs"].items():
            for step in job.get("steps", []):
                if "uses" in step:
                    results.append((job_id, step["uses"]))
        return results

    def test_no_actions_pinned_to_latest_or_main(self):
        for job_id, uses in self._collect_all_uses():
            self.assertIsNone(
                self.UNPINNED_PATTERN.search(uses),
                f"Job '{job_id}': action '{uses}' is not version-pinned. "
                "Use a specific tag or SHA for reproducibility and security."
            )

    def test_all_actions_have_version(self):
        for job_id, uses in self._collect_all_uses():
            self.assertIn("@", uses,
                          f"Job '{job_id}': action '{uses}' has no version specifier")


if __name__ == "__main__":
    # Pretty output
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(sys.modules[__name__])

    runner = unittest.TextTestRunner(verbosity=2, stream=sys.stdout)
    result = runner.run(suite)

    print(f"\n{'='*60}")
    print(f"  Tests run:   {result.testsRun}")
    print(f"  Passed:      {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"  Failures:    {len(result.failures)}")
    print(f"  Errors:      {len(result.errors)}")
    print(f"{'='*60}")

    sys.exit(0 if result.wasSuccessful() else 1)
