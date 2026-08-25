"""Hostile tests for the per-main-merge release contract."""

from __future__ import annotations

import base64
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
from unittest import mock
from pathlib import Path


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SPEC = importlib.util.spec_from_file_location("release_contract", HERE / "release_contract.py")
assert SPEC and SPEC.loader
RC = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = RC
SPEC.loader.exec_module(RC)


def snapshot(version: str) -> dict[str, str]:
    return {
        "VERSION": version + "\n",
        "chart/Chart.yaml": f"apiVersion: v2\nversion: {version}\nappVersion: \"{version}\"\n",
        "chart/values.yaml": f"image:\n  tag: v{version}\n",
        "CHANGELOG.md": f"# Changelog\n\n## [Unreleased]\n\n## [{version}] - 2026-08-13\n\n- release\n",
    }


def event(sha: str) -> dict[str, object]:
    return {
        "repository": {"full_name": "owner/site"},
        "workflow_run": {
            "name": "PR gate",
            "path": ".github/workflows/pr-gate.yml@refs/heads/main",
            "event": "push",
            "status": "completed",
            "conclusion": "success",
            "head_branch": "main",
            "head_sha": sha,
            "head_repository": {"full_name": "owner/site"},
        },
    }


def main_run_record(sha: str, run_id: int = 123) -> dict[str, object]:
    return {
        "id": run_id,
        "name": "PR gate",
        "path": ".github/workflows/pr-gate.yml",
        "event": "push",
        "status": "completed",
        "conclusion": "success",
        "head_branch": "main",
        "head_sha": sha,
        "repository": {"full_name": "owner/site"},
        "head_repository": {"full_name": "owner/site"},
    }


def codeql_run_record(sha: str, run_id: int = 456) -> dict[str, object]:
    record = main_run_record(sha, run_id)
    record["name"] = "CodeQL"
    record["path"] = ".github/workflows/codeql.yml"
    return record


def job_pages(workflow: str, run_id: int) -> list[dict[str, object]]:
    expected = {
        "pr-gate": RC.PR_GATE_MAIN_JOBS,
        "codeql": RC.CODEQL_MAIN_JOBS,
    }[workflow]
    jobs = [
        {
            "id": 1000 + index,
            "run_id": run_id,
            "name": name,
            "status": "completed",
            "conclusion": conclusion,
        }
        for index, (name, conclusion) in enumerate(expected.items())
    ]
    midpoint = max(1, len(jobs) // 2)
    return [
        {"total_count": len(jobs), "jobs": jobs[:midpoint]},
        {"total_count": len(jobs), "jobs": jobs[midpoint:]},
    ]


def spdx_document(marker: str) -> dict[str, object]:
    return {
        "SPDXID": "SPDXRef-DOCUMENT",
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "name": f"release-{marker}",
        "documentNamespace": f"https://example.invalid/sbom/{marker}",
        "creationInfo": {
            "created": "2026-08-14T00:00:00Z",
            "creators": ["Tool: buildkit-syft-scanner"],
        },
        "packages": [
            {"SPDXID": f"SPDXRef-Package-{marker}", "name": f"package-{marker}"}
        ],
    }


# The authoritative builder run these fixtures claim, and the shape BuildKit
# actually emits on GitHub Actions:
# <source>/actions/runs/<GITHUB_RUN_ID>/attempts/<GITHUB_RUN_ATTEMPT>. The
# fixture carried no /attempts segment until the run-ID binding landed, which
# made it unrepresentative of every real predicate this repository publishes.
BUILDER_RUN_ID = "123"


def embedded_predicate(
    source: str,
    revision: str,
    marker: str,
    *,
    builder_run_id: str = BUILDER_RUN_ID,
    attempt: str = "1",
) -> dict[str, object]:
    return {
        "buildDefinition": {
            "buildType": "https://mobyproject.org/buildkit@v1",
            "externalParameters": {"marker": marker},
            "internalParameters": {},
        },
        "runDetails": {
            "builder": {"id": f"{source}/actions/runs/{builder_run_id}/attempts/{attempt}"},
            "metadata": {"buildkit_metadata": {"vcs": {"source": source, "revision": revision}}},
        },
    }


def verified_record(statement: dict[str, object]) -> dict[str, str]:
    payload = base64.b64encode(json.dumps(statement, sort_keys=True).encode("utf-8")).decode("ascii")
    return {"payload": payload}


def exact_tag_records(tag: str, source: str, message: str, date: str) -> tuple[dict[str, object], dict[str, object]]:
    tag_object = "b" * 40
    return (
        {"ref": f"refs/tags/{tag}", "object": {"type": "tag", "sha": tag_object}},
        {
            "sha": tag_object,
            "tag": tag,
            "message": message,
            "object": {"type": "commit", "sha": source},
            "tagger": {
                "name": "github-actions[bot]",
                "email": "41898282+github-actions[bot]@users.noreply.github.com",
                "date": date,
            },
        },
    )


def release_manifest() -> dict[str, object]:
    return RC.build_release_manifest(
        # These are independent test oracles, not aliases of the production
        # constants that this fixture is expected to police.
        repository="snaraj/lidersea.com",
        source_sha="a" * 40,
        version=RC.Version.parse("0.1.10"),
        image="ghcr.io/snaraj/lidersea-com",
        image_digest="sha256:" + "d" * 64,
        chart="ghcr.io/snaraj/charts/lidersea-com",
        chart_digest="sha256:" + "e" * 64,
    )


def release_record(
    state: str, manifest: dict[str, object] | None = None
) -> tuple[dict[str, object], bytes, bytes | None]:
    manifest = manifest or release_manifest()
    raw = RC.canonical_json_bytes(manifest)
    assets: list[dict[str, object]] = []
    asset_bytes: bytes | None = None
    if state != "draft-empty":
        assets = [
            {
                "id": 123,
                "name": RC.RELEASE_MANIFEST_NAME,
                "state": "uploaded",
                "content_type": "application/json",
                "size": len(raw),
                "digest": "sha256:" + hashlib.sha256(raw).hexdigest(),
                "uploader": {
                    # Keep the evidence fixture independent of the production
                    # constants used by validate_release_record.
                    "login": "github-actions[bot]",
                    "id": 41898282,
                },
            }
        ]
        asset_bytes = raw
    if state == "draft-empty":
        draft, immutable = True, False
    elif state == "draft-ready":
        draft, immutable = True, False
    elif state == "exact":
        draft, immutable = False, True
    else:
        raise ValueError(f"unsupported fixture release state: {state}")
    return (
        {
            "tag_name": manifest["tag"],
            "name": "informational title is not artifact identity",
            "body": "informational notes may change\n",
            "author": {
                "login": "github-actions[bot]",
                "id": 41898282,
            },
            "draft": draft,
            "prerelease": False,
            "immutable": immutable,
            "assets": assets,
        },
        raw,
        asset_bytes,
    )


REQUIRED_CHECKS = (
    "analyze (go, manual)",
    "analyze (javascript-typescript, none)",
    "application",
    "chart",
    "container",
    "dependency-review",
    "security",
)


def settings_receipt() -> dict[str, object]:
    return {
        "repository": "owner/site",
        "branch": "main",
        "actions_enabled": True,
        "actions_allowed": "all",
        "actions_sha_pinning": True,
        "default_workflow_permissions": "read",
        "can_approve_pull_request_reviews": False,
        "code_coverage_max_drop": None,
        "code_coverage_minimum": 80,
        "code_quality_severity": "errors",
        "code_scanning_tools": [
            {
                "alerts_threshold": "errors",
                "security_alerts_threshold": "high_or_higher",
                "tool": "CodeQL",
            }
        ],
        "dismiss_stale_reviews_on_push": False,
        "merge_methods": ["rebase", "squash"],
        "required_status_checks": [
            {"context": context, "integration_id": 15368} for context in REQUIRED_CHECKS
        ],
        "strict_status_checks": True,
        "require_pull_request": True,
        "require_linear_history": True,
        "require_code_owner_review": False,
        "require_last_push_approval": False,
        "require_signatures": True,
        "required_approving_review_count": 0,
        "required_review_thread_resolution": True,
        "required_reviewers": [],
        "allow_force_pushes": False,
        "allow_deletions": False,
        "restrict_updates": False,
        "immutable_releases": True,
        "private_vulnerability_reporting": True,
        "secret_scanning": True,
        "secret_scanning_push_protection": True,
    }


def settings_api() -> dict[str, object]:
    ruleset_id = 42
    checks = [
        {"context": context, "integration_id": 15368} for context in REQUIRED_CHECKS
    ]
    return {
        "repos/owner/site": {
            "full_name": "owner/site",
            "default_branch": "main",
            "allow_merge_commit": False,
            "allow_rebase_merge": True,
            "allow_squash_merge": True,
            "security_and_analysis": {
                "secret_scanning": {"status": "enabled"},
                "secret_scanning_push_protection": {"status": "enabled"},
            },
        },
        "repos/owner/site/immutable-releases": {
            "enabled": True,
            "enforced_by_owner": False,
        },
        "repos/owner/site/actions/permissions": {
            "enabled": True,
            "allowed_actions": "all",
            "sha_pinning_required": True,
        },
        "repos/owner/site/actions/permissions/workflow": {
            "default_workflow_permissions": "read",
            "can_approve_pull_request_reviews": False,
        },
        "repos/owner/site/private-vulnerability-reporting": {"enabled": True},
        "repos/owner/site/rulesets": [
            {
                "id": ruleset_id,
                "name": "Protect-Main",
                "target": "branch",
                "source_type": "Repository",
                "source": "owner/site",
                "enforcement": "active",
            }
        ],
        f"repos/owner/site/rulesets/{ruleset_id}": {
            "id": ruleset_id,
            "name": "Protect-Main",
            "target": "branch",
            "source_type": "Repository",
            "source": "owner/site",
            "enforcement": "active",
            # No bypass_actors key: REST withholds the property from every
            # credential without write access to the ruleset, and the settings
            # jobs hold Administration read alone. This fixture is the exact
            # shape the CI credential observes.
            "conditions": {
                "ref_name": {"exclude": [], "include": ["refs/heads/main"]},
            },
            "rules": [
                {"type": "creation"},
                {"type": "deletion"},
                {"type": "non_fast_forward"},
                {"type": "required_linear_history"},
                {"type": "required_signatures"},
                {
                    "type": "code_scanning",
                    "parameters": {
                        "code_scanning_tools": [
                            {
                                "tool": "CodeQL",
                                "security_alerts_threshold": "high_or_higher",
                                "alerts_threshold": "errors",
                            }
                        ]
                    },
                },
                {"type": "code_quality", "parameters": {"severity": "errors"}},
                {
                    "type": "code_coverage",
                    "parameters": {"minimum_coverage": 80, "max_coverage_drop": None},
                },
                {
                    "type": "pull_request",
                    "parameters": {
                        "allowed_merge_methods": ["rebase", "squash"],
                        "dismiss_stale_reviews_on_push": False,
                        "require_code_owner_review": False,
                        "require_extra_approval_for_unattributed_changes": True,
                        "require_last_push_approval": False,
                        "required_approving_review_count": 0,
                        "required_review_thread_resolution": True,
                        "required_reviewers": [],
                    },
                },
                {
                    "type": "required_status_checks",
                    "parameters": {
                        "do_not_enforce_on_create": False,
                        "required_status_checks": checks,
                        "strict_required_status_checks_policy": True,
                    },
                },
            ],
        },
    }


class VersionTests(unittest.TestCase):
    def test_next_patch_is_arithmetic_not_decimal_concatenation(self):
        RC.require_next_patch(RC.Version.parse("0.1.9"), RC.Version.parse("0.1.10"))
        for wrong in ("0.0.20", "0.1.9", "0.1.11", "0.2.0", "1.0.0"):
            with self.subTest(wrong=wrong), self.assertRaises(RC.ContractError):
                RC.require_next_patch(RC.Version.parse("0.1.9"), RC.Version.parse(wrong))

    def test_source_locks_and_changelog_are_one_identity(self):
        self.assertEqual(RC.validate_snapshot(snapshot("0.1.10")).tag, "v0.1.10")
        extended = snapshot("0.1.10")
        extended["chart/Chart.yaml"] += "dependencies:\n  - name: database\n    version: 1.2.3\n"
        extended["chart/values.yaml"] += "sidecar:\n  tag: unrelated\n"
        self.assertEqual(RC.validate_snapshot(extended).tag, "v0.1.10")
        mutations = []
        for path, replacement in (
            ("chart/Chart.yaml", "apiVersion: v2\nversion: 0.1.9\nappVersion: \"0.1.10\"\n"),
            ("chart/Chart.yaml", "apiVersion: v2\nversion: 0.1.10\nappVersion: \"v0.1.10\"\n"),
            ("chart/Chart.yaml", "apiVersion: v2\nversion: vv0.1.10\nappVersion: \"v0.1.10\"\n"),
            ("chart/values.yaml", "image:\n  tag: vv0.1.10\n"),
            ("chart/values.yaml", "image:\n  tag: v0.1.10\n  tag: v0.1.10\n"),
            ("chart/values.yaml", "image:\n  tag: v0.0.20\n"),
            ("CHANGELOG.md", "# Changelog\n\n## [Unreleased]\n\n- not released\n"),
        ):
            changed = snapshot("0.1.10")
            changed[path] = replacement
            mutations.append(changed)
        for changed in mutations:
            with self.assertRaises(RC.ContractError):
                RC.validate_snapshot(changed)


class EventTests(unittest.TestCase):
    SHA = "a" * 40

    def test_exact_successful_main_push_is_accepted(self):
        self.assertEqual(RC.plan_workflow_run(event(self.SHA), "owner/site"), self.SHA)

    def test_event_branch_conclusion_sha_path_and_identity_mutants_fail(self):
        mutations = (
            ("repository", "full_name", "attacker/site"),
            ("workflow_run", "name", "PR Gate"),
            ("workflow_run", "path", ".github/workflows/other.yml"),
            ("workflow_run", "event", "pull_request"),
            ("workflow_run", "status", "in_progress"),
            ("workflow_run", "conclusion", "failure"),
            ("workflow_run", "head_branch", "release"),
            ("workflow_run", "head_sha", "1234567"),
        )
        for parent, key, value in mutations:
            payload = json.loads(json.dumps(event(self.SHA)))
            payload[parent][key] = value
            with self.subTest(parent=parent, key=key), self.assertRaises(RC.ContractError):
                RC.plan_workflow_run(payload, "owner/site")
        payload = event(self.SHA)
        payload["workflow_run"]["head_repository"]["full_name"] = "attacker/site"
        with self.assertRaises(RC.ContractError):
            RC.plan_workflow_run(payload, "owner/site")

    def test_two_and_three_rapid_merges_are_unique_even_out_of_order(self):
        versions = [RC.Version.parse(v) for v in ("0.1.10", "0.1.11", "0.1.12")]
        shas = [character * 40 for character in "abc"]
        intents = [RC.ReleaseIntent(sha, version) for sha, version in zip(shas, versions)]
        completion_order = [intents[2], intents[0], intents[1]]
        self.assertEqual({intent.tag for intent in completion_order}, {"v0.1.10", "v0.1.11", "v0.1.12"})
        self.assertEqual(len({intent.source_sha for intent in completion_order}), 3)
        self.assertEqual(RC.ReleaseIntent(shas[0], versions[0]), RC.ReleaseIntent(shas[0], versions[0]))


class StrictJsonBoundaryTests(unittest.TestCase):
    @staticmethod
    def invoke(arguments: list[str]) -> tuple[int, str]:
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(
            io.StringIO()
        ) as denied:
            status = RC.main(arguments)
        return status, denied.getvalue()

    def test_recursive_duplicates_and_nonfinite_values_have_exact_reasons(self):
        for raw, reason in (
            ('{"outer":{"member":1,"member":2}}', "duplicate JSON member 'member'"),
            ('{"value":NaN}', "non-finite JSON constant 'NaN' is forbidden"),
            ('{"value":Infinity}', "non-finite JSON constant 'Infinity' is forbidden"),
        ):
            with self.subTest(raw=raw), self.assertRaises(RC.ContractError) as denied:
                RC.parse_json(raw, "hostile boundary")
            self.assertEqual(str(denied.exception), reason)

    def test_event_tag_release_registry_and_buildx_boundaries_reject_duplicates(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cases = (
                (
                    "event.json",
                    '{"repository":{"full_name":"owner/site","full_name":"attacker/site"},"workflow_run":{}}',
                    ["workflow-run", "--event", "{path}", "--repository", "owner/site"],
                    "duplicate JSON member 'full_name'",
                ),
                (
                    "tag.json",
                    '{"ref":"refs/tags/v0.1.10","object":{"type":"tag","type":"commit","sha":"'
                    + "b" * 40
                    + '"}}',
                    ["tag-ref-object", "--ref-json", "{path}", "--tag", "v0.1.10"],
                    "duplicate JSON member 'type'",
                ),
                (
                    "release.json",
                    '{"assets":[{"id":1,"id":2}]}',
                    ["release-asset-id", "--release-json", "{path}"],
                    "duplicate JSON member 'id'",
                ),
                (
                    "token.json",
                    '{"token":"one","token":"two"}',
                    ["registry-token", "--token-json", "{path}"],
                    "duplicate JSON member 'token'",
                ),
                (
                    "buildx.json",
                    '{"linux/amd64":{"SLSA":{},"SLSA":{}}}',
                    ["json-keys", "--json", "{path}"],
                    "duplicate JSON member 'SLSA'",
                ),
            )
            for filename, raw, arguments, reason in cases:
                path = root / filename
                path.write_text(raw, encoding="utf-8")
                resolved = [str(path) if item == "{path}" else item for item in arguments]
                status, stderr = self.invoke(resolved)
                with self.subTest(filename=filename):
                    self.assertEqual(status, 1)
                    self.assertEqual(stderr, f"DENY: {reason}\n")

    def test_manifest_settings_and_cosign_boundaries_reject_nested_duplicates(self):
        with tempfile.TemporaryDirectory() as temporary:
            manifest = Path(temporary) / RC.RELEASE_MANIFEST_NAME
            manifest.write_text('{"artifacts":{"image":{"digest":1,"digest":2}}}', encoding="utf-8")
            with self.assertRaises(RC.ContractError) as denied:
                RC.read_release_manifest(manifest, require_mode=False)
            self.assertEqual(str(denied.exception), "duplicate JSON member 'digest'")

        response = subprocess.CompletedProcess(
            [], 0, stdout='{"security_and_analysis":{"status":1,"status":2}}', stderr=""
        )
        with mock.patch.object(RC.subprocess, "run", return_value=response), self.assertRaises(
            RC.ContractError
        ) as denied:
            RC._github_api_get("repos/owner/site")
        self.assertEqual(str(denied.exception), "duplicate JSON member 'status'")

        outer = '{"payload":"one","payload":"two"}'
        with self.assertRaises(RC.ContractError) as denied:
            RC._verified_statements(outer)
        self.assertEqual(str(denied.exception), "duplicate JSON member 'payload'")

        hostile_payload = base64.b64encode(
            b'{"predicate":{"buildDefinition":{},"buildDefinition":{}}}'
        ).decode("ascii")
        with self.assertRaises(RC.ContractError) as denied:
            RC._verified_statements(json.dumps({"payload": hostile_payload}))
        self.assertEqual(str(denied.exception), "duplicate JSON member 'buildDefinition'")


class GovernanceReceiptTests(unittest.TestCase):
    HEAD = "a" * 40

    @staticmethod
    def require_template_authority(template: str) -> None:
        for required in (
            "The author applies `requires-review`",
            "reviewer removes it when posting either verdict",
            "Only the coordinator may change",
            "Mutation audit:",
            "Claim audit:",
        ):
            if required not in template:
                raise ValueError(f"PR template governance handoff lost: {required}")
        if "Only the coordinator may apply\n`requires-review`" in template:
            raise ValueError("PR template inverted requires-review authority")

    @staticmethod
    def require_agents_review_contract(agents: str) -> str:
        collapsed = " ".join(agents.split())
        for required in (
            "`requires-review` is PR-head-only",
            "The author lane applies `requires-review` only when the exact PR head, "
            "body, commits, and evidence are author-complete",
            "The reviewer removes it when posting either verdict",
            "Never apply or interpret `requires-review` on an issue",
            "Use an explicit normal comment for issue-spec review",
        ):
            if required not in collapsed:
                raise ValueError(f"canonical AGENTS review contract lost: {required}")
        for forbidden in (
            "applies `requires-review` the moment a PR or issue is",
            "open agent-authored PR or issue",
            "On an issue it carries the same meaning",
            "Apply `requires-review` once the issue is",
            "Only the coordinator applies `requires-review`",
        ):
            if forbidden in collapsed:
                raise ValueError(f"canonical AGENTS issue/authority inversion: {forbidden}")
        match = re.search(
            r"\*\*Exact-head receipt\.\*\*.*?```text\n(.*?)\n```", agents, re.S
        )
        if match is None:
            raise ValueError("canonical AGENTS adversarial receipt sample is absent")
        return match.group(1)

    def test_agents_review_contract_is_pr_head_only_and_validator_valid(self):
        agents = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
        sample = self.require_agents_review_contract(agents)
        exact = (
            sample.replace("<40-lowercase-hex>", self.HEAD)
            .replace("APPROVE | REQUEST-CHANGES", "APPROVE")
            .replace(
                "<mutants attempted and killed, or explicit no-finding scope>",
                "paired governance mutants killed",
            )
            .replace(
                "<SUPPORTED / OVERSTATED results for every material claim>",
                "every material claim checked",
            )
            .replace("<distinct context>", "Independent Review")
        )
        for verdict in ("APPROVE", "REQUEST-CHANGES"):
            receipt = exact.replace("VERDICT: APPROVE", f"VERDICT: {verdict}")
            self.assertEqual(
                RC.validate_review_receipt(
                    receipt, expected_head=self.HEAD, role="adversarial"
                ),
                verdict,
            )

        contract_mutants = {
            "delete_pr_head_only": agents.replace(
                "`requires-review` is\n  PR-head-only.", "", 1
            ),
            "invert_author_authority": agents.replace(
                "The author lane applies `requires-review` only when",
                "Only the coordinator applies `requires-review` when",
                1,
            ),
            "restore_issue_interpretation": agents.replace(
                "Never apply or interpret `requires-review` on an issue",
                "Apply and interpret `requires-review` on an issue",
                1,
            ),
        }
        for name, mutant in contract_mutants.items():
            with self.subTest(contract_mutant=name), self.assertRaises(ValueError):
                self.require_agents_review_contract(mutant)

        receipt_mutants = {
            "delete_mutation_audit": exact.replace(
                "Mutation audit: paired governance mutants killed\n", "", 1
            ),
            "delete_claim_audit": exact.replace(
                "Claim audit: every material claim checked\n", "", 1
            ),
            "invalid_verdict_field": exact.replace(
                "VERDICT: APPROVE", "APPROVE", 1
            ),
            "duplicate_head": exact.replace(
                f"HEAD: {self.HEAD}", f"HEAD: {self.HEAD}\nHEAD: {self.HEAD}", 1
            ),
        }
        for name, mutant in receipt_mutants.items():
            with self.subTest(receipt_mutant=name), self.assertRaises(RC.ContractError):
                RC.validate_review_receipt(
                    mutant, expected_head=self.HEAD, role="adversarial"
                )

    def test_canonical_adversarial_verdict_syntax_and_head_binding(self):
        exact = (
            f"HEAD: {self.HEAD}\n"
            "VERDICT: APPROVE\n"
            "Mutation audit: paired authority mutants were killed.\n"
            "Claim audit: every material claim was checked.\n"
            "- Red Team (adversarial reviewer)"
        )
        for verdict in ("APPROVE", "REQUEST-CHANGES"):
            receipt = exact.replace("VERDICT: APPROVE", f"VERDICT: {verdict}")
            self.assertEqual(
                RC.validate_review_receipt(
                    receipt, expected_head=self.HEAD, role="adversarial"
                ),
                verdict,
            )
        mutants = (
            exact.replace("VERDICT: APPROVE", "APPROVE", 1),
            exact.replace(self.HEAD, "b" * 40, 1),
            exact.replace("VERDICT: APPROVE", "VERDICT: approve", 1),
            exact.replace(
                "VERDICT: APPROVE", "VERDICT: APPROVE\nVERDICT: APPROVE", 1
            ),
            exact.replace("Mutation audit: paired authority mutants were killed.\n", "", 1),
            exact.replace("Claim audit: every material claim was checked.\n", "", 1),
            exact.replace("Red Team", "Agent", 1),
            exact.replace("- Red Team (adversarial reviewer)", "- Red Team", 1),
        )
        for index, receipt in enumerate(mutants):
            with self.subTest(index=index), self.assertRaises(RC.ContractError):
                RC.validate_review_receipt(
                    receipt, expected_head=self.HEAD, role="adversarial"
                )

    def test_main_worker_role_is_retired(self):
        """Issue #124: the validator accepts no receipt role but adversarial."""
        formerly_valid = (
            f"HEAD: {self.HEAD}\n"
            "ROLE: MAIN-WORKER\n"
            "VERDICT: PASS\n"
            "SCOPE: architecture,merge-order,authority,settings,base-freshness,required-checks\n"
            "- Architecture Control (Main Worker)"
        )
        for role in ("main-worker", "coordinator", ""):
            with self.subTest(role=role), self.assertRaises(RC.ContractError):
                RC.validate_review_receipt(
                    formerly_valid, expected_head=self.HEAD, role=role
                )
        self.assertFalse(hasattr(RC, "MAIN_WORKER_SCOPE"))

    def test_governance_docs_pin_receipts_milestone_parity_and_generic_owner_wording(self):
        agents = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
        template = (ROOT / ".github/PULL_REQUEST_TEMPLATE.md").read_text(
            encoding="utf-8"
        )
        for text in (agents, template):
            for token in (
                "HEAD: <40-lowercase-hex>",
                "VERDICT: APPROVE | REQUEST-CHANGES",
            ):
                self.assertIn(token, text)
        self.require_template_authority(template)
        for mutant in (
            template.replace(
                "The author applies `requires-review`",
                "Only the coordinator applies `requires-review`",
                1,
            ),
            template.replace("reviewer removes it when posting either verdict", "", 1),
            template.replace("Mutation audit:", "Evidence:", 1),
            template.replace("Claim audit:", "Summary:", 1),
        ):
            with self.assertRaises(ValueError):
                self.require_template_authority(mutant)

        adversarial_match = re.search(
            r"Adversarial reviewer receipt.*?```text\n(.*?)\n```", template, re.S
        )
        self.assertIsNotNone(adversarial_match)
        adversarial = (
            adversarial_match.group(1)
            .replace("<40-lowercase-hex>", self.HEAD)
            .replace("APPROVE | REQUEST-CHANGES", "APPROVE")
            .replace(
                "<mutants attempted and killed, or explicit no-finding scope>",
                "paired authority mutants killed",
            )
            .replace(
                "<SUPPORTED / OVERSTATED results for every material claim>",
                "all material claims SUPPORTED",
            )
            .replace("<distinct context>", "Independent Review")
        )
        self.assertEqual(
            RC.validate_review_receipt(
                adversarial, expected_head=self.HEAD, role="adversarial"
            ),
            "APPROVE",
        )

        self.assertIn("Issue milestone: `vX.Y.Z`", template)
        self.assertIn("PR milestone: `vX.Y.Z`", template)
        self.assertIn("must equal the issue milestone and next patch", template)
        self.assertIn("the repository owner alone merges", agents)
        governance = (ROOT / "docs/release-governance.md").read_text(encoding="utf-8")
        self.assertIn("The repository owner alone chooses squash or rebase", governance)
        self.assertIn("the repository owner alone merges", governance)
        # Issue #124: the Ready flip needs adversarial approval plus green
        # checks, nothing else — and the retired Main Worker ceremony must
        # not resurface in any governance document.
        self.assertIn("After review, Ready.", agents)
        self.assertIn("No third distinct-context pass is required", agents)
        self.assertIn(
            "no further distinct-context receipt is required",
            " ".join(governance.split()),
        )
        for retired in ("ROLE: MAIN-WORKER", "(Main Worker)", "Main Worker receipt"):
            for name, text in (
                ("agents", agents),
                ("template", template),
                ("governance", governance),
            ):
                with self.subTest(retired=retired, doc=name):
                    self.assertNotIn(retired, text)

        actual = {
            path: (ROOT / path).read_text(encoding="utf-8")
            for path in ("VERSION", "chart/Chart.yaml", "chart/values.yaml", "CHANGELOG.md")
        }
        raw_version = (ROOT / "VERSION").read_bytes().decode("utf-8")
        self.assertRegex(raw_version, r"\A(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\n\Z")
        self.assertEqual(RC.validate_snapshot(actual).tag, f"v{raw_version[:-1]}")


class MainRunBindingTests(unittest.TestCase):
    SHA = "a" * 40

    @staticmethod
    def invoke(record: dict[str, object], *, run_id: int = 123, source_sha: str | None = None) -> int:
        with tempfile.TemporaryDirectory() as temporary:
            run_json = Path(temporary) / "main-run.json"
            run_json.write_text(json.dumps(record), encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                return RC.main(
                    [
                        "main-run-record",
                        "--run-json",
                        str(run_json),
                        "--run-id",
                        str(run_id),
                        "--repository",
                        "owner/site",
                        "--source-sha",
                        source_sha or MainRunBindingTests.SHA,
                    ]
                )

    def test_exact_authoritative_successful_main_run_is_accepted(self):
        exact = main_run_record(self.SHA)
        self.assertEqual(
            RC.validate_main_run_record(
                exact,
                expected_repository="owner/site",
                expected_run_id=123,
                expected_source_sha=self.SHA,
            ),
            self.SHA,
        )
        self.assertEqual(self.invoke(exact), 0)

    def test_ordinary_manual_unmerged_dispatch_is_executable_denial(self):
        unmerged = main_run_record(self.SHA)
        unmerged["event"] = "pull_request"
        unmerged["head_branch"] = "ci/unmerged-source"
        self.assertEqual(self.invoke(unmerged), 1)

    def test_foreign_failed_stale_path_identity_and_id_mutants_fail(self):
        exact = main_run_record(self.SHA)
        mutations: list[dict[str, object]] = []
        for path, value in (
            (("id",), 124),
            (("name",), "PR Gate"),
            (("path",), ".github/workflows/other.yml"),
            (("event",), "pull_request"),
            (("status",), "in_progress"),
            (("conclusion",), "failure"),
            (("head_branch",), "release"),
            (("head_sha",), "b" * 40),
            (("repository", "full_name"), "attacker/site"),
            (("head_repository", "full_name"), "attacker/site"),
        ):
            changed = copy.deepcopy(exact)
            parent = changed
            for key in path[:-1]:
                parent = parent[key]
            parent[path[-1]] = value
            mutations.append(changed)
        for index, changed in enumerate(mutations):
            with self.subTest(record_mutation=index):
                self.assertEqual(self.invoke(changed), 1)
        self.assertEqual(self.invoke(exact, run_id=124), 1)
        self.assertEqual(self.invoke(exact, source_sha="b" * 40), 1)


class SuccessfulMainInventoryTests(unittest.TestCase):
    SHA = "a" * 40

    def test_exact_paginated_pr_gate_and_codeql_jobs_are_required(self):
        self.assertEqual(
            RC.validate_workflow_job_inventory(
                job_pages("pr-gate", 123), workflow="pr-gate", expected_run_id=123
            ),
            len(RC.PR_GATE_MAIN_JOBS),
        )
        self.assertEqual(
            RC.validate_workflow_job_inventory(
                job_pages("codeql", 456), workflow="codeql", expected_run_id=456
            ),
            len(RC.CODEQL_MAIN_JOBS),
        )

    def test_absent_pending_skipped_failed_duplicate_and_foreign_jobs_fail(self):
        exact = job_pages("pr-gate", 123)
        flattened = [copy.deepcopy(job) for page in exact for job in page["jobs"]]
        mutants: list[list[dict[str, object]]] = []
        for name, key, value in (
            ("security", "status", "in_progress"),
            ("security", "conclusion", "skipped"),
            ("application", "conclusion", "failure"),
            ("chart", "run_id", 999),
            ("container", "name", "foreign"),
            # Both PR-only jobs must be denied a `success` on a main push: that
            # conclusion is the signature of a dropped `pull_request` condition
            # and a duplicate post-merge build of an already-built tree.
            ("container", "conclusion", "success"),
            ("coverage-badges", "conclusion", "skipped"),
            ("dependency-review", "conclusion", "success"),
        ):
            changed = copy.deepcopy(flattened)
            next(job for job in changed if job["name"] == name)[key] = value
            mutants.append([{"total_count": len(changed), "jobs": changed}])
        missing = copy.deepcopy(flattened[:-1])
        mutants.append([{"total_count": len(missing), "jobs": missing}])
        duplicated = copy.deepcopy(flattened)
        duplicated.append(copy.deepcopy(duplicated[0]))
        mutants.append([{"total_count": len(duplicated), "jobs": duplicated}])
        inconsistent = copy.deepcopy(exact)
        inconsistent[1]["total_count"] = len(flattened) + 1
        mutants.append(inconsistent)
        for index, pages in enumerate(mutants):
            with self.subTest(index=index), self.assertRaises(RC.ContractError):
                RC.validate_workflow_job_inventory(
                    pages, workflow="pr-gate", expected_run_id=123
                )

        codeql = [copy.deepcopy(job) for page in job_pages("codeql", 456) for job in page["jobs"]]
        for name in RC.CODEQL_MAIN_JOBS:
            changed = copy.deepcopy(codeql)
            next(job for job in changed if job["name"] == name)["conclusion"] = "skipped"
            with self.subTest(codeql_skip=name), self.assertRaises(RC.ContractError):
                RC.validate_workflow_job_inventory(
                    [{"total_count": len(changed), "jobs": changed}],
                    workflow="codeql",
                    expected_run_id=456,
                )

    def test_codeql_poll_is_exact_sha_bounded_state_not_aggregate_inference(self):
        exact = codeql_run_record(self.SHA)
        self.assertEqual(
            RC.select_codeql_main_run(
                [{"total_count": 0, "workflow_runs": []}],
                expected_repository="owner/site",
                expected_source_sha=self.SHA,
            ),
            ("absent", None),
        )
        pending = copy.deepcopy(exact)
        pending["status"] = "in_progress"
        pending["conclusion"] = None
        self.assertEqual(
            RC.select_codeql_main_run(
                [{"total_count": 1, "workflow_runs": [pending]}],
                expected_repository="owner/site",
                expected_source_sha=self.SHA,
            ),
            ("pending", 456),
        )
        self.assertEqual(
            RC.select_codeql_main_run(
                [{"total_count": 1, "workflow_runs": [exact]}],
                expected_repository="owner/site",
                expected_source_sha=self.SHA,
            ),
            ("success", 456),
        )
        self.assertEqual(
            RC.validate_codeql_run_record(
                exact,
                expected_repository="owner/site",
                expected_run_id=456,
                expected_source_sha=self.SHA,
            ),
            self.SHA,
        )

        mutants: list[list[dict[str, object]]] = []
        for path, value in (
            (("head_sha",), "b" * 40),
            (("head_branch",), "topic"),
            (("event",), "pull_request"),
            (("path",), ".github/workflows/foreign.yml"),
            (("name",), "Foreign"),
            (("repository", "full_name"), "attacker/site"),
            (("head_repository", "full_name"), "attacker/site"),
            (("conclusion",), "failure"),
            (("conclusion",), "skipped"),
        ):
            changed = copy.deepcopy(exact)
            parent = changed
            for key in path[:-1]:
                parent = parent[key]
            parent[path[-1]] = value
            mutants.append([{"total_count": 1, "workflow_runs": [changed]}])
        pending_with_conclusion = copy.deepcopy(pending)
        pending_with_conclusion["conclusion"] = "success"
        mutants.append([{"total_count": 1, "workflow_runs": [pending_with_conclusion]}])
        mutants.append(
            [{"total_count": 2, "workflow_runs": [exact, copy.deepcopy(exact)]}]
        )
        for index, pages in enumerate(mutants):
            with self.subTest(index=index), self.assertRaises(RC.ContractError):
                RC.select_codeql_main_run(
                    pages,
                    expected_repository="owner/site",
                    expected_source_sha=self.SHA,
                )


class SettingsReceiptTests(unittest.TestCase):
    @staticmethod
    def require_documented_contract(text: str) -> None:
        for token in (
            "Release-control readiness receipt",
            '"actions_allowed": "all"',
            '"actions_enabled": true',
            '"actions_sha_pinning": true',
            '"can_approve_pull_request_reviews": false',
            '"code_coverage_max_drop": null',
            '"code_coverage_minimum": 80',
            '"code_quality_severity": "errors"',
            '"default_workflow_permissions": "read"',
            '"dismiss_stale_reviews_on_push": false',
            '"immutable_releases": true',
            '"merge_methods": ["rebase", "squash"]',
            '"context": "security", "integration_id": 15368',
            '"context": "dependency-review", "integration_id": 15368',
            '"strict_status_checks": true',
            '"require_pull_request": true',
            '"require_linear_history": true',
            '"require_code_owner_review": false',
            '"require_last_push_approval": false',
            '"require_signatures": true',
            '"required_approving_review_count": 0',
            '"required_review_thread_resolution": true',
            '"required_reviewers": []',
            # The unattributed-change approval is pinned at the rule and carries no
            # receipt field, so this prose line is the only place the runbook states
            # it — and therefore the only place it could be quietly dropped.
            "require_extra_approval_for_unattributed_changes: true",
            '"private_vulnerability_reporting": true',
            '"secret_scanning": true',
            '"secret_scanning_push_protection": true',
            '"allow_force_pushes": false',
            '"allow_deletions": false',
            '"restrict_updates": false',
            # bypass_actors left the receipt with the CI-credential fix; these
            # tokens pin the replacement contract instead, so the owner column
            # cannot be quietly dropped from the runbook.
            "## Which column proves which invariant",
            "**`Protect-Main` has zero bypass actors** | **Owner preflight**",
            "only returned if the user making the API request has write access",
            "It must print exactly `[]`",
            "settings-preflight",
            "settings-receipt",
            "platform-release",
            "PLATFORM_RELEASE_APP_ID",
            "PLATFORM_RELEASE_APP_PRIVATE_KEY",
            "bcd2ba49218906704ab6c1aa796996da409d3eb1",
            "permission-administration: read",
            "ordinary `GITHUB_TOKEN` is the sole credential",
            "mutable aliases",
            "same-SHA main CodeQL run",
            "both paginated job inventories",
            "concurrent retargets fail",
            "--include-dev-deps",
            "snaraj/lidersea.com",
            "ghcr.io/snaraj/lidersea-com",
            "ghcr.io/snaraj/charts/lidersea-com",
            "explicit, non-derived package identities",
            "sole manifest-asset uploader",
            "`github-actions[bot]` and numeric ID `41898282`",
            "Only-Owner-Push",
            "must remain Draft",
        ):
            if token not in text:
                raise ValueError(f"release settings contract lost: {token}")

    # Renamed from test_only_the_exact_immutable_no_bypass_receipt_is_ready: the
    # CI receipt no longer carries a bypass field, so a name claiming it proves
    # no-bypass would overstate what this suite checks.
    def test_only_the_exact_immutable_receipt_is_ready(self):
        exact = settings_receipt()
        RC.validate_settings_receipt(exact, "owner/site")
        mutations: list[dict[str, object]] = []
        for key, value in (
            ("repository", "other/site"),
            ("branch", "release"),
            ("actions_enabled", False),
            ("actions_allowed", "unknown"),
            ("actions_allowed", "selected"),
            ("actions_allowed", "local_only"),
            ("actions_sha_pinning", False),
            ("default_workflow_permissions", "write"),
            ("can_approve_pull_request_reviews", True),
            ("code_coverage_max_drop", 1),
            ("code_coverage_minimum", 79),
            ("code_quality_severity", "warnings"),
            ("code_scanning_tools", []),
            ("dismiss_stale_reviews_on_push", True),
            ("merge_methods", ["squash"]),
            ("merge_methods", ["merge", "rebase", "squash"]),
            ("merge_methods", ["rebase", "rebase", "squash"]),
            ("strict_status_checks", False),
            ("require_pull_request", False),
            ("require_linear_history", False),
            ("require_code_owner_review", True),
            ("require_last_push_approval", True),
            ("require_signatures", False),
            ("required_approving_review_count", 1),
            ("required_review_thread_resolution", False),
            ("required_reviewers", [{"present": True}]),
            ("allow_force_pushes", True),
            ("allow_deletions", True),
            ("restrict_updates", True),
            # bypass_actors is no longer a receipt field, so this entry INSERTS a
            # foreign key rather than mutating a value. It is retained because the
            # closed field set must reject the removed field rather than tolerate
            # a dangling copy of it.
            ("bypass_actors", ["present"]),
            ("immutable_releases", False),
            ("private_vulnerability_reporting", False),
            ("secret_scanning", False),
            ("secret_scanning_push_protection", False),
        ):
            changed = copy.deepcopy(exact)
            changed[key] = value
            mutations.append(changed)
        checks = copy.deepcopy(exact["required_status_checks"])
        for replacement in (
            checks[:-1],
            [*checks, {"context": "foreign", "integration_id": 15368}],
            [*checks, copy.deepcopy(checks[0])],
            [{**check, "integration_id": 1} for check in checks],
            [{"context": check["context"]} for check in checks],
        ):
            changed = copy.deepcopy(exact)
            changed["required_status_checks"] = replacement
            mutations.append(changed)
        for index, changed in enumerate(mutations):
            with self.subTest(mutation=index), self.assertRaises(RC.ContractError):
                RC.validate_settings_receipt(changed, "owner/site")
        for key in exact:
            changed = copy.deepcopy(exact)
            del changed[key]
            with self.subTest(missing=key), self.assertRaises(RC.ContractError):
                RC.validate_settings_receipt(changed, "owner/site")
        changed = copy.deepcopy(exact)
        changed["ruleset_id"] = 42
        with self.assertRaises(RC.ContractError):
            RC.validate_settings_receipt(changed, "owner/site")

    @staticmethod
    def observe(records: dict[str, object]) -> dict[str, object]:
        with mock.patch.object(
            RC,
            "_github_api_get",
            side_effect=lambda endpoint, **_options: records[endpoint],
        ) as getter:
            receipt = RC.observe_live_settings("owner/site")
        self_calls = [call.args[0] for call in getter.call_args_list]
        if self_calls != [
            "repos/owner/site",
            "repos/owner/site/immutable-releases",
            "repos/owner/site/actions/permissions",
            "repos/owner/site/actions/permissions/workflow",
            "repos/owner/site/private-vulnerability-reporting",
            "repos/owner/site/rulesets",
            "repos/owner/site/rulesets/42",
        ]:
            raise AssertionError(f"unexpected settings endpoints: {self_calls}")
        if getter.call_args_list[5].kwargs != {"paginate": True}:
            raise AssertionError("ruleset inventory must use exhaustive pagination")
        if any(call.kwargs for index, call in enumerate(getter.call_args_list) if index != 5):
            raise AssertionError("only the list endpoint should paginate")
        return receipt

    def test_authoritative_raw_preflight_rejects_every_control_mutant(self):
        exact = settings_api()
        self.assertEqual(self.observe(copy.deepcopy(exact)), settings_receipt())

        # The repository record's merge-method booleans are deliberately absent
        # from this matrix: REST withholds them from the Administration-read-only
        # credential this path runs under, so no assertion may depend on them.
        # test_merge_methods_come_from_the_ruleset_not_the_repository_record
        # carries the merge-method mutants against their authoritative source.
        mutations: list[dict[str, object]] = []
        for endpoint, path, value in (
            ("repos/owner/site", ("default_branch",), "release"),
            ("repos/owner/site", ("security_and_analysis", "secret_scanning", "status"), "disabled"),
            ("repos/owner/site", ("security_and_analysis", "secret_scanning_push_protection", "status"), "disabled"),
            ("repos/owner/site/immutable-releases", ("enabled",), False),
            ("repos/owner/site/actions/permissions", ("sha_pinning_required",), False),
            ("repos/owner/site/actions/permissions/workflow", ("default_workflow_permissions",), "write"),
            ("repos/owner/site/actions/permissions/workflow", ("can_approve_pull_request_reviews",), True),
            ("repos/owner/site/private-vulnerability-reporting", ("enabled",), False),
            ("repos/owner/site/rulesets/42", ("enforcement",), "disabled"),
            ("repos/owner/site/rulesets/42", ("conditions", "ref_name", "include"), ["~ALL"]),
            # The ruleset's bypass_actors mutant is deliberately absent for the
            # same reason as the repository merge booleans above: REST returns
            # bypass_actors only to credentials with write access to the ruleset,
            # and this path holds Administration read alone, so the mutant asserts
            # a response shape the credential can never receive. It is a NARROW,
            # NAMED removal, not a weakening — the invariant it expressed moved to
            # the owner-preflight column in docs/release-governance.md, and
            # test_bypass_actors_are_never_read_under_the_ci_credential pins that
            # neither an empty nor a populated list can move the CI receipt.
        ):
            changed = copy.deepcopy(exact)
            parent = changed[endpoint]
            for key in path[:-1]:
                parent = parent[key]
            parent[path[-1]] = value
            mutations.append(changed)

        detail = exact["repos/owner/site/rulesets/42"]
        rules = detail["rules"]
        for rule_type in (
            "creation",
            "code_coverage",
            "code_quality",
            "code_scanning",
            "deletion",
            "non_fast_forward",
            "required_linear_history",
            "required_signatures",
            "pull_request",
            "required_status_checks",
        ):
            changed = copy.deepcopy(exact)
            changed["repos/owner/site/rulesets/42"]["rules"] = [
                rule for rule in rules if rule["type"] != rule_type
            ]
            mutations.append(changed)
        changed = copy.deepcopy(exact)
        changed["repos/owner/site/rulesets/42"]["rules"].append({"type": "update"})
        mutations.append(changed)
        changed = copy.deepcopy(exact)
        changed["repos/owner/site/rulesets/42"]["rules"].append(
            {"type": "foreign_rule"}
        )
        mutations.append(changed)
        for rule_type, parameters in (
            (
                "code_scanning",
                {
                    "code_scanning_tools": [
                        {
                            "tool": "CodeQL",
                            "security_alerts_threshold": "medium_or_higher",
                            "alerts_threshold": "errors",
                        }
                    ]
                },
            ),
            ("code_quality", {"severity": "warnings"}),
            ("code_coverage", {"minimum_coverage": 79, "max_coverage_drop": None}),
            ("code_coverage", {"minimum_coverage": 80, "max_coverage_drop": 1}),
        ):
            changed = copy.deepcopy(exact)
            rule = next(
                item
                for item in changed["repos/owner/site/rulesets/42"]["rules"]
                if item["type"] == rule_type
            )
            rule["parameters"] = parameters
            mutations.append(changed)

        for field, value in (
            ("allowed_merge_methods", ["merge", "rebase", "squash"]),
            ("allowed_merge_methods", ["squash"]),
            ("dismiss_stale_reviews_on_push", True),
            ("require_code_owner_review", True),
            ("require_extra_approval_for_unattributed_changes", False),
            ("require_last_push_approval", True),
            ("required_approving_review_count", 1),
            ("required_review_thread_resolution", False),
            ("required_reviewers", [{"reviewer": "foreign"}]),
        ):
            changed = copy.deepcopy(exact)
            pull = next(
                rule
                for rule in changed["repos/owner/site/rulesets/42"]["rules"]
                if rule["type"] == "pull_request"
            )
            pull["parameters"][field] = value
            mutations.append(changed)
        changed = copy.deepcopy(exact)
        pull = next(
            rule
            for rule in changed["repos/owner/site/rulesets/42"]["rules"]
            if rule["type"] == "pull_request"
        )
        pull["parameters"]["foreign"] = False
        mutations.append(changed)
        for field, value in (
            ("strict_required_status_checks_policy", False),
            ("do_not_enforce_on_create", True),
        ):
            changed = copy.deepcopy(exact)
            status = next(
                rule
                for rule in changed["repos/owner/site/rulesets/42"]["rules"]
                if rule["type"] == "required_status_checks"
            )
            status["parameters"][field] = value
            mutations.append(changed)
        changed = copy.deepcopy(exact)
        status = next(
            rule
            for rule in changed["repos/owner/site/rulesets/42"]["rules"]
            if rule["type"] == "required_status_checks"
        )
        status["parameters"]["foreign"] = False
        mutations.append(changed)
        for replacement in (
            [{"context": context, "integration_id": 15368} for context in REQUIRED_CHECKS[:-1]],
            [
                *[{"context": context, "integration_id": 15368} for context in REQUIRED_CHECKS],
                {"context": "foreign", "integration_id": 15368},
            ],
            [{"context": context, "integration_id": 1} for context in REQUIRED_CHECKS],
        ):
            changed = copy.deepcopy(exact)
            status = next(
                rule
                for rule in changed["repos/owner/site/rulesets/42"]["rules"]
                if rule["type"] == "required_status_checks"
            )
            status["parameters"]["required_status_checks"] = replacement
            mutations.append(changed)
        changed = copy.deepcopy(exact)
        changed["repos/owner/site/rulesets"].append(copy.deepcopy(changed["repos/owner/site/rulesets"][0]))
        mutations.append(changed)

        for index, changed in enumerate(mutations):
            with self.subTest(raw_mutation=index), self.assertRaises(RC.ContractError):
                self.observe(changed)

    def test_merge_methods_come_from_the_ruleset_not_the_repository_record(self):
        # The settings jobs mint a repository-scoped App token whose ONLY grant is
        # Administration read, and REST returns allow_merge_commit /
        # allow_rebase_merge / allow_squash_merge only to credentials that also
        # hold Contents write. The receipt must therefore build from the
        # Protect-Main ruleset's allowed_merge_methods alone — and must still fail
        # closed on every shape and value that is not exactly squash plus rebase.
        credential_shape = copy.deepcopy(settings_api())
        for boolean in ("allow_merge_commit", "allow_rebase_merge", "allow_squash_merge"):
            del credential_shape["repos/owner/site"][boolean]
        self.assertEqual(self.observe(credential_shape), settings_receipt())

        # The repository record cannot influence the receipt in either direction:
        # booleans that disagree with the ruleset are ignored, not reconciled.
        for booleans in (
            {"allow_merge_commit": True, "allow_rebase_merge": True, "allow_squash_merge": True},
            {"allow_merge_commit": False, "allow_rebase_merge": False, "allow_squash_merge": False},
            {"allow_merge_commit": "yes", "allow_rebase_merge": None, "allow_squash_merge": 1},
        ):
            disagreeing = copy.deepcopy(settings_api())
            disagreeing["repos/owner/site"].update(booleans)
            with self.subTest(repository_booleans=booleans):
                self.assertEqual(self.observe(disagreeing), settings_receipt())

        for value in (
            ["merge", "rebase", "squash"],
            ["merge"],
            ["squash"],
            ["rebase"],
            [],
            ["rebase", "rebase", "squash"],
            ["rebase", "squash", ""],
            ["rebase", "squash", "merge_queue"],
            ["rebase", 1],
            ["rebase", None],
            ["rebase", ["squash"]],
            "rebase,squash",
            {"rebase": True, "squash": True},
            None,
            True,
        ):
            changed = copy.deepcopy(settings_api())
            pull = next(
                rule
                for rule in changed["repos/owner/site/rulesets/42"]["rules"]
                if rule["type"] == "pull_request"
            )
            pull["parameters"]["allowed_merge_methods"] = value
            with self.subTest(allowed_merge_methods=value), self.assertRaises(RC.ContractError):
                self.observe(changed)

        absent = copy.deepcopy(settings_api())
        pull = next(
            rule
            for rule in absent["repos/owner/site/rulesets/42"]["rules"]
            if rule["type"] == "pull_request"
        )
        del pull["parameters"]["allowed_merge_methods"]
        with self.assertRaises(RC.ContractError):
            self.observe(absent)

        # The downstream receipt validator remains the exact-set gate regardless
        # of how the receipt was produced.
        for receipt_value in (["squash"], ["rebase"], ["merge", "rebase", "squash"], [], "rebase"):
            changed = settings_receipt()
            changed["merge_methods"] = receipt_value
            with self.subTest(receipt_merge_methods=receipt_value), self.assertRaises(RC.ContractError):
                RC.validate_settings_receipt(changed, "owner/site")

    def test_unattributed_change_approval_is_pinned_true_and_stays_rule_level(self):
        # GitHub added require_extra_approval_for_unattributed_changes to the live
        # Protect-Main pull_request rule after v0.1.18 shipped. The closed field set
        # did exactly what it exists to do — it denied publication rather than
        # accepting an unreviewed settings surface — so the remedy is a deliberate
        # re-anchor on the live value, which is also the stricter one, never a
        # relaxation of the closed set. This battery pins all four directions.
        field = "require_extra_approval_for_unattributed_changes"

        def parameters(records: dict[str, object]) -> dict[str, object]:
            return next(
                rule
                for rule in records["repos/owner/site/rulesets/42"]["rules"]
                if rule["type"] == "pull_request"
            )["parameters"]

        # The corrected live shape is green, and the fixture really does carry the
        # pinned value rather than passing by omission.
        exact = copy.deepcopy(settings_api())
        self.assertIs(parameters(exact)[field], True)
        self.assertEqual(self.observe(exact), settings_receipt())

        # An absent field is red: a pinned control that silently disappears from the
        # authoritative surface must deny, not default.
        absent = copy.deepcopy(settings_api())
        del parameters(absent)[field]
        with self.assertRaises(RC.ContractError):
            self.observe(absent)

        # Every non-True value is red, including the falsy and non-boolean shapes an
        # identity comparison is there to catch.
        for value in (False, None, 0, 1, "true", [], {}):
            changed = copy.deepcopy(settings_api())
            parameters(changed)[field] = value
            with self.subTest(unattributed_value=value), self.assertRaises(
                RC.ContractError
            ):
                self.observe(changed)

        # A FURTHER foreign field is still red: re-anchoring on this one name did not
        # open the set to the next one GitHub adds.
        extra = copy.deepcopy(settings_api())
        parameters(extra)["require_extra_approval_for_unreviewed_changes"] = True
        with self.assertRaises(RC.ContractError):
            self.observe(extra)

        # The pin is rule-level only. It does not enter the value-only receipt — the
        # same split do_not_enforce_on_create already sits on — and the receipt's own
        # closed field set still rejects the name as foreign, so no dangling copy can
        # be smuggled past the offline revalidation either.
        receipt = self.observe(copy.deepcopy(settings_api()))
        self.assertNotIn(field, receipt)
        smuggled = settings_receipt()
        smuggled[field] = True
        with self.assertRaises(RC.ContractError):
            RC.validate_settings_receipt(smuggled, "owner/site")

    def test_bypass_actors_are_never_read_under_the_ci_credential(self):
        # REST documents the withholding in the "Get a repository ruleset"
        # contract: "To prevent leaking sensitive information, the bypass_actors
        # property is only returned if the user making the API request has write
        # access to the ruleset."
        # (https://docs.github.com/en/rest/repos/rules) The settings jobs mint a
        # repository-scoped App token whose ONLY grant is Administration read, so
        # the property is absent from every response this path can ever observe.
        # The receipt must therefore build without it and must not carry it; the
        # no-bypass invariant is proven by the owner preflight instead, and
        # docs/release-governance.md records which column proves what.
        credential_shape = settings_api()
        self.assertNotIn(
            "bypass_actors", credential_shape["repos/owner/site/rulesets/42"]
        )
        receipt = self.observe(copy.deepcopy(credential_shape))
        self.assertEqual(receipt, settings_receipt())
        self.assertNotIn("bypass_actors", receipt)

        # An owner credential DOES receive the property. It must not influence the
        # receipt in either direction: an empty list may not make the receipt
        # stronger and a populated one may not make it weaker, so the control's
        # strength never varies with who is holding the credential.
        for actors in (
            [],
            [{"actor_type": "RepositoryRole", "actor_id": 5, "bypass_mode": "always"}],
            [{"actor_type": "OrganizationAdmin", "actor_id": 1, "bypass_mode": "pull_request"}],
            [{"actor_type": "Integration", "actor_id": 15368, "bypass_mode": "always"}],
            "present",
            None,
            True,
            {},
        ):
            visible = copy.deepcopy(settings_api())
            visible["repos/owner/site/rulesets/42"]["bypass_actors"] = actors
            with self.subTest(bypass_actors=actors):
                observed = self.observe(visible)
                self.assertEqual(observed, settings_receipt())
                self.assertNotIn("bypass_actors", observed)

        # The receipt field set stays closed, so a bypass_actors key is now
        # foreign rather than silently tolerated. Without this the removal could
        # leave a dangling field that no code writes and no check reads.
        changed = settings_receipt()
        changed["bypass_actors"] = []
        with self.assertRaises(RC.ContractError):
            RC.validate_settings_receipt(changed, "owner/site")

        # Everything the ruleset detail DOES expose to this credential stays
        # enforced on BOTH sides of where the bypass read used to sit — the
        # removal site is the "bypass_actors is deliberately NOT read here"
        # block in release_contract.py. Measured by capturing which guard each
        # mutant actually trips: the first TWO deny BEFORE that point —
        # enforcement raises "Protect-Main ruleset identity or enforcement is
        # not exact" and conditions.ref_name.include raises "Protect-Main must
        # target only refs/heads/main" — so they prove the guards ahead of the
        # removal still fire. The last TWO deny AFTER it — rules: [] raises
        # "Protect-Main rule types are missing or foreign" and rules: None
        # fails the array read with "Protect-Main rules must be a JSON array" —
        # so only those two prove the rules parsing behind the removal is still
        # reached. All four kill; do not drop the rules pair believing
        # enforcement covers the same ground, because it runs before the
        # removal and proves nothing past it.
        for path, value in (
            (("enforcement",), "disabled"),
            (("conditions", "ref_name", "include"), ["~ALL"]),
            (("rules",), []),
            (("rules",), None),
        ):
            mutated = copy.deepcopy(settings_api())
            parent = mutated["repos/owner/site/rulesets/42"]
            for key in path[:-1]:
                parent = parent[key]
            parent[path[-1]] = value
            with self.subTest(ruleset_mutant=path), self.assertRaises(RC.ContractError):
                self.observe(mutated)

    def test_github_settings_reader_is_get_only_and_fails_closed(self):
        completed = subprocess.CompletedProcess([], 0, stdout='{"enabled": true}', stderr="")
        with mock.patch.object(RC.subprocess, "run", return_value=completed) as run:
            self.assertEqual(RC._github_api_get("repos/owner/site/immutable-releases"), {"enabled": True})
        command = run.call_args.args[0]
        self.assertEqual(command[:4], ["gh", "api", "--method", "GET"])
        self.assertIn("X-GitHub-Api-Version: 2026-03-10", command)
        self.assertNotIn("POST", command)
        self.assertNotIn("PUT", command)
        self.assertNotIn("PATCH", command)
        self.assertNotIn("DELETE", command)
        pages = subprocess.CompletedProcess(
            [],
            0,
            stdout='[[{"id": 1}], [{"id": 2}]]',
            stderr="",
        )
        with mock.patch.object(RC.subprocess, "run", return_value=pages) as run:
            self.assertEqual(RC._github_api_get("repos/owner/site/rulesets", paginate=True), [{"id": 1}, {"id": 2}])
        paginated_command = run.call_args.args[0]
        self.assertIn("--paginate", paginated_command)
        self.assertIn("--slurp", paginated_command)
        for result in (
            subprocess.CompletedProcess([], 1, stdout="", stderr="denied"),
            subprocess.CompletedProcess([], 0, stdout="not-json", stderr=""),
        ):
            with mock.patch.object(RC.subprocess, "run", return_value=result), self.assertRaises(
                RC.ContractError
            ):
                RC._github_api_get("repos/owner/site/immutable-releases")

    def test_settings_cli_and_runbook_are_load_bearing(self):
        with tempfile.TemporaryDirectory() as temporary:
            receipt = Path(temporary) / "settings.json"
            receipt.write_text(json.dumps(settings_receipt()), encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(
                    RC.main(
                        [
                            "settings-receipt",
                            "--receipt",
                            str(receipt),
                            "--repository",
                            "owner/site",
                        ]
                    ),
                    0,
                )
            self.assertEqual(output.getvalue().strip(), "exact")
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(
                    RC.main(
                        [
                            "settings-receipt",
                            "--receipt",
                            str(receipt),
                            "--repository",
                            "other/site",
                        ]
                    ),
                    1,
                )

        runbook = (ROOT / "docs" / "release-governance.md").read_text(encoding="utf-8")
        self.require_documented_contract(runbook)
        tokens = (
            "Release-control readiness receipt",
            '"actions_allowed": "all"',
            '"actions_sha_pinning": true',
            '"default_workflow_permissions": "read"',
            '"immutable_releases": true',
            '"merge_methods": ["rebase", "squash"]',
            '"context": "security", "integration_id": 15368',
            '"strict_status_checks": true',
            '"require_pull_request": true',
            '"require_linear_history": true',
            '"require_signatures": true',
            '"required_review_thread_resolution": true',
            '"required_approving_review_count": 0',
            "require_extra_approval_for_unattributed_changes: true",
            '"code_coverage_minimum": 80',
            '"private_vulnerability_reporting": true',
            '"secret_scanning": true',
            '"secret_scanning_push_protection": true',
            '"allow_force_pushes": false',
            '"allow_deletions": false',
            '"restrict_updates": false',
            # bypass_actors left the receipt with the CI-credential fix; these
            # tokens pin the replacement contract instead, so the owner column
            # cannot be quietly dropped from the runbook.
            "## Which column proves which invariant",
            "**`Protect-Main` has zero bypass actors** | **Owner preflight**",
            "only returned if the user making the API request has write access",
            "It must print exactly `[]`",
            "settings-preflight",
            "settings-receipt",
            "platform-release",
            "PLATFORM_RELEASE_APP_ID",
            "PLATFORM_RELEASE_APP_PRIVATE_KEY",
            "bcd2ba49218906704ab6c1aa796996da409d3eb1",
            "permission-administration: read",
            "ordinary `GITHUB_TOKEN` is the sole credential",
            "mutable aliases",
            "same-SHA main CodeQL run",
            "both paginated job inventories",
            "concurrent retargets fail",
            "--include-dev-deps",
            "snaraj/lidersea.com",
            "ghcr.io/snaraj/lidersea-com",
            "ghcr.io/snaraj/charts/lidersea-com",
            "explicit, non-derived package identities",
            "sole manifest-asset uploader",
            "`github-actions[bot]` and numeric ID `41898282`",
            "Only-Owner-Push",
            "must remain Draft",
        )
        for token in tokens:
            with self.subTest(deletion=token), self.assertRaises(ValueError):
                self.require_documented_contract(runbook.replace(token, ""))
        for old, new in (
            ('"immutable_releases": true', '"immutable_releases": false'),
            ('"actions_sha_pinning": true', '"actions_sha_pinning": false'),
            ('"strict_status_checks": true', '"strict_status_checks": false'),
            ('"require_signatures": true', '"require_signatures": false'),
            ('"required_review_thread_resolution": true', '"required_review_thread_resolution": false'),
            ('"required_approving_review_count": 0', '"required_approving_review_count": 1'),
            (
                "require_extra_approval_for_unattributed_changes: true",
                "require_extra_approval_for_unattributed_changes: false",
            ),
            ('"code_coverage_minimum": 80', '"code_coverage_minimum": 79'),
            ('"private_vulnerability_reporting": true', '"private_vulnerability_reporting": false'),
            ('"secret_scanning": true', '"secret_scanning": false'),
            ('"secret_scanning_push_protection": true', '"secret_scanning_push_protection": false'),
            ('"allow_force_pushes": false', '"allow_force_pushes": true'),
            ('"allow_deletions": false', '"allow_deletions": true'),
            ('"restrict_updates": false', '"restrict_updates": true'),
        ):
            with self.subTest(inversion=old), self.assertRaises(ValueError):
                self.require_documented_contract(runbook.replace(old, new, 1))


class ArtifactStateTests(unittest.TestCase):
    def test_absent_complete_and_every_partial_state(self):
        self.assertEqual(RC.classify_artifact(present=False, source_match=False, signature_match=False, evidence_count=0, expected_evidence=2), "absent")
        self.assertEqual(RC.classify_artifact(present=True, source_match=True, signature_match=True, evidence_count=2, expected_evidence=2), "complete")
        for source, signed, count in ((False, True, 2), (True, False, 2), (True, True, 0), (True, True, 1), (True, True, 3)):
            with self.subTest(source=source, signed=signed, count=count):
                self.assertEqual(RC.classify_artifact(present=True, source_match=source, signature_match=signed, evidence_count=count, expected_evidence=2), "burned")
        with self.assertRaises(RC.ContractError):
            RC.classify_artifact(present=False, source_match=True, signature_match=False, evidence_count=0, expected_evidence=2)

    def test_only_an_authoritative_404_means_absent(self):
        self.assertEqual(RC.classify_registry_response(200), "present")
        self.assertEqual(RC.classify_registry_response(404), "absent")
        for status in (0, 301, 401, 403, 408, 409, 429, 500, 502, 503, 504):
            with self.subTest(status=status), self.assertRaises(RC.ContractError):
                RC.classify_registry_response(status)

    def test_registry_alias_body_header_and_expected_digest_are_one_identity(self):
        body = b'{"mediaType":"application/vnd.oci.image.index.v1+json","schemaVersion":2}'
        digest = "sha256:" + hashlib.sha256(body).hexdigest()
        headers = f"HTTP/2 200\r\ndocker-content-digest: {digest}\r\n"
        self.assertEqual(
            RC.validate_registry_manifest_response(
                200, body, headers, expected_digest=digest
            ),
            digest,
        )
        mutants = (
            (404, body, headers, digest),
            (200, body + b" ", headers, digest),
            (200, body, headers + f"Docker-Content-Digest: {digest}\r\n", digest),
            (200, body, headers, "sha256:" + "e" * 64),
            (200, b'{"schemaVersion":2,"schemaVersion":2}', headers, digest),
            (200, b"null", headers, digest),
        )
        for index, (status, changed_body, changed_headers, expected) in enumerate(mutants):
            with self.subTest(index=index), self.assertRaises(RC.ContractError):
                RC.validate_registry_manifest_response(
                    status, changed_body, changed_headers, expected_digest=expected
                )


class TrivySourceCoverageTests(unittest.TestCase):
    DEPENDENCIES = {
        "@sveltejs/vite-plugin-svelte": "7.3.0",
        "svelte": "5.56.8",
        "svelte-check": "4.7.5",
        "typescript": "6.0.3",
        "vite": "8.2.1",
    }

    @staticmethod
    def require_exact_trivy_version_claim(installer: str, contract: str) -> None:
        for source, required in (
            (installer, "TRIVY_VERSION=v0.73.0"),
            (
                installer,
                "TRIVY_SHA256=2edd39da482bb4e9831962487b68f68e3928ec3137794757f54d00383d79547b",
            ),
            (contract, "Trivy v0.73.0 identifies `trivy fs ... .` JSON"),
        ):
            if required not in source:
                raise ValueError(f"Trivy version/checksum claim drifted: {required}")

    def test_exact_scanner_version_claim_matches_checksum_pinned_installer(self):
        installer = (ROOT / "scripts/ci/install-tools.sh").read_text(encoding="utf-8")
        contract = (ROOT / "scripts/ci/release_contract.py").read_text(encoding="utf-8")
        self.require_exact_trivy_version_claim(installer, contract)
        for changed_installer, changed_contract in (
            (installer.replace("v0.73.0", "v0.72.0", 1), contract),
            (installer, contract.replace("v0.73.0", "v0.72", 1)),
            (
                installer.replace("v0.73.0", "v0.74.0", 1),
                contract.replace("v0.73.0", "v0.74.0", 1),
            ),
        ):
            with self.assertRaises(ValueError):
                self.require_exact_trivy_version_claim(
                    changed_installer, changed_contract
                )

    def report(self) -> dict[str, object]:
        return {
            "SchemaVersion": 2,
            "ArtifactName": ".",
            "ArtifactType": "repository",
            "Results": [
                {
                    "Target": "frontend/package-lock.json",
                    "Class": "lang-pkgs",
                    "Type": "npm",
                    "Packages": [
                        {"Name": name, "Version": version, "Relationship": "direct"}
                        for name, version in self.DEPENDENCIES.items()
                    ],
                    "Vulnerabilities": [],
                },
                {
                    "Target": "go.mod",
                    "Class": "lang-pkgs",
                    "Type": "gomod",
                    "Packages": [],
                    "Vulnerabilities": [],
                },
            ],
        }

    def test_exact_frontend_dev_build_graph_is_present(self):
        self.assertEqual(
            RC.validate_trivy_source_report(
                self.report(), {"devDependencies": self.DEPENDENCIES}
            ),
            len(self.DEPENDENCIES),
        )

    def test_high_or_critical_frontend_build_dependency_has_exact_denial(self):
        for severity in ("HIGH", "CRITICAL"):
            report = self.report()
            report["Results"][0]["Vulnerabilities"] = [
                {
                    "VulnerabilityID": f"CVE-2026-{1 if severity == 'HIGH' else 2:04d}",
                    "PkgName": "vite",
                    "Severity": severity,
                }
            ]
            expected = (
                f"Trivy source scan found {severity} "
                f"CVE-2026-{1 if severity == 'HIGH' else 2:04d} "
                "in frontend build dependency vite"
            )
            with self.subTest(severity=severity), self.assertRaisesRegex(
                RC.ContractError, re.escape(expected)
            ):
                RC.validate_trivy_source_report(
                    report, {"devDependencies": self.DEPENDENCIES}
                )

    def test_suppressed_missing_duplicate_and_foreign_frontend_inventory_fail(self):
        mutants = []
        wrong_schema = self.report()
        wrong_schema["SchemaVersion"] = 1
        mutants.append(wrong_schema)
        wrong_name = self.report()
        wrong_name["ArtifactName"] = "frontend"
        mutants.append(wrong_name)
        wrong_artifact = self.report()
        wrong_artifact["ArtifactType"] = "filesystem"
        mutants.append(wrong_artifact)
        missing = self.report()
        missing["Results"] = missing["Results"][1:]
        mutants.append(missing)
        wrong_target = self.report()
        wrong_target["Results"][0]["Target"] = "package-lock.json"
        mutants.append(wrong_target)
        wrong_type = self.report()
        wrong_type["Results"][0]["Type"] = "gomod"
        mutants.append(wrong_type)
        omitted = self.report()
        omitted["Results"][0]["Packages"] = omitted["Results"][0]["Packages"][:-1]
        mutants.append(omitted)
        transitive = self.report()
        transitive["Results"][0]["Packages"][0]["Relationship"] = "indirect"
        mutants.append(transitive)
        duplicated = self.report()
        duplicated["Results"].insert(0, copy.deepcopy(duplicated["Results"][0]))
        mutants.append(duplicated)
        for index, report in enumerate(mutants):
            with self.subTest(index=index), self.assertRaises(RC.ContractError):
                RC.validate_trivy_source_report(
                    report, {"devDependencies": self.DEPENDENCIES}
                )


class PublisherBindingTests(unittest.TestCase):
    SHA = "a" * 40

    @staticmethod
    def require_canonical_production_authority(
        repository: str, image: str, chart: str, publisher: str
    ) -> None:
        # This oracle deliberately repeats the reviewed external identities.
        # It must not derive a package path from RC constants or workflow env.
        expected = (
            "snaraj/lidersea.com",
            "ghcr.io/snaraj/lidersea-com",
            "ghcr.io/snaraj/charts/lidersea-com",
        )
        if (repository, image, chart) != expected:
            raise ValueError("production repository/package authority is not canonical")
        for destination in (
            "IMAGE: ghcr.io/snaraj/lidersea-com",
            "CHART: ghcr.io/snaraj/charts/lidersea-com",
        ):
            if destination not in publisher:
                raise ValueError(f"publisher destination escaped canonical authority: {destination}")

    def test_production_package_authority_is_an_independent_literal_oracle(self):
        publisher = (ROOT / ".github/workflows/release-publisher.yml").read_text(
            encoding="utf-8"
        )
        self.require_canonical_production_authority(
            RC.EXPECTED_REPOSITORY,
            RC.EXPECTED_IMAGE,
            RC.EXPECTED_CHART,
            publisher,
        )
        paired_mutant = publisher.replace(
            "IMAGE: ghcr.io/snaraj/lidersea-com",
            "IMAGE: ghcr.io/snaraj/foreign-image",
            1,
        ).replace(
            "CHART: ghcr.io/snaraj/charts/lidersea-com",
            "CHART: ghcr.io/snaraj/charts/foreign-chart",
            1,
        )
        with self.assertRaises(ValueError):
            self.require_canonical_production_authority(
                "snaraj/lidersea.com",
                "ghcr.io/snaraj/foreign-image",
                "ghcr.io/snaraj/charts/foreign-chart",
                paired_mutant,
            )

    def test_source_sha_ref_event_and_snapshot_checks_are_executable(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name, contents in snapshot("0.1.10").items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(contents, encoding="utf-8")
            workflow_ref = (
                "snaraj/lidersea.com/.github/workflows/"
                "release-publisher.yml@refs/heads/main"
            )
            intent = RC.validate_publisher(
                root,
                self.SHA,
                self.SHA,
                "refs/heads/main",
                "workflow_dispatch",
                "snaraj/lidersea.com",
                workflow_ref,
                "ghcr.io/snaraj/lidersea-com",
                "ghcr.io/snaraj/charts/lidersea-com",
            )
            self.assertEqual(intent, RC.ReleaseIntent(self.SHA, RC.Version.parse("0.1.10")))
            exact = (
                self.SHA,
                self.SHA,
                "refs/heads/main",
                "workflow_dispatch",
                "snaraj/lidersea.com",
                workflow_ref,
                "ghcr.io/snaraj/lidersea-com",
                "ghcr.io/snaraj/charts/lidersea-com",
            )
            mutants = (
                ("b" * 40, *exact[1:]),
                (exact[0], "b" * 40, *exact[2:]),
                (*exact[:2], "refs/tags/v0.1.10", *exact[3:]),
                (*exact[:3], "push", *exact[4:]),
                (*exact[:4], "snaraj/lidersea-com", *exact[5:]),
                (
                    *exact[:5],
                    "snaraj/lidersea.com/.github/workflows/"
                    "release-publisher.yml@refs/tags/v0.1.10",
                    *exact[6:],
                ),
                (*exact[:6], "ghcr.io/snaraj/lidersea.com", exact[7]),
                (*exact[:7], "ghcr.io/snaraj/charts/lidersea.com"),
            )
            for (
                source,
                checkout,
                ref,
                event_name,
                repository,
                selected_workflow,
                image,
                chart,
            ) in mutants:
                with self.subTest(
                    source=source,
                    checkout=checkout,
                    ref=ref,
                    event=event_name,
                    repository=repository,
                    workflow=selected_workflow,
                    image=image,
                    chart=chart,
                ), self.assertRaises(RC.ContractError):
                    RC.validate_publisher(
                        root,
                        source,
                        checkout,
                        ref,
                        event_name,
                        repository,
                        selected_workflow,
                        image,
                        chart,
                    )

    def test_real_dotted_repository_and_hyphenated_packages_are_cli_exact(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / RC.RELEASE_MANIFEST_NAME
            exact = [
                "release-manifest",
                "--output",
                str(output),
                "--repository",
                "snaraj/lidersea.com",
                "--source-sha",
                self.SHA,
                "--version",
                "0.1.10",
                "--image",
                "ghcr.io/snaraj/lidersea-com",
                "--image-digest",
                "sha256:" + "d" * 64,
                "--chart",
                "ghcr.io/snaraj/charts/lidersea-com",
                "--chart-digest",
                "sha256:" + "e" * 64,
            ]
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(RC.main(exact), 0)
            manifest, _raw = RC.read_release_manifest(
                output, expected_repository="snaraj/lidersea.com", require_mode=False
            )
            self.assertEqual(
                manifest["artifacts"]["image"]["registry"],
                "ghcr.io/snaraj/lidersea-com",
            )
            self.assertEqual(
                manifest["artifacts"]["chart"]["registry"],
                "ghcr.io/snaraj/charts/lidersea-com",
            )

            for flag, wrong in (
                ("--repository", "snaraj/lidersea-com"),
                ("--image", "ghcr.io/snaraj/lidersea.com"),
                ("--chart", "ghcr.io/snaraj/charts/lidersea.com"),
            ):
                mutant = list(exact)
                mutant[mutant.index("--output") + 1] = str(
                    Path(temporary) / f"wrong-{flag[2:]}.json"
                )
                mutant[mutant.index(flag) + 1] = wrong
                with self.subTest(flag=flag), contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(RC.main(mutant), 1)
                    self.assertFalse(Path(mutant[2]).exists())


class ImmutableMetadataTests(unittest.TestCase):
    TAG = "v0.1.10"
    SOURCE = "a" * 40
    MESSAGE = f"Release {TAG} from {SOURCE}"
    DATE = "2026-08-13T15:21:32Z"

    def test_annotated_tag_type_target_message_and_tagger_are_exact(self):
        ref, tag = exact_tag_records(self.TAG, self.SOURCE, self.MESSAGE, self.DATE)
        RC.validate_tag_record(
            ref,
            tag,
            tag=self.TAG,
            source_sha=self.SOURCE,
            message=self.MESSAGE,
            tagger_name="github-actions[bot]",
            tagger_email="41898282+github-actions[bot]@users.noreply.github.com",
            tagger_date="2026-08-13T08:21:32-07:00",
        )
        mutations: list[tuple[dict[str, object], dict[str, object]]] = []
        for target, path, value in (
            ("ref", ("ref",), "refs/tags/v0.1.11"),
            ("ref", ("object", "type"), "commit"),
            ("ref", ("object", "sha"), "c" * 40),
            ("tag", ("tag",), "v0.1.11"),
            ("tag", ("message",), self.MESSAGE + " foreign"),
            ("tag", ("object", "type"), "tree"),
            ("tag", ("object", "sha"), "d" * 40),
            ("tag", ("tagger", "name"), "snaraj"),
            ("tag", ("tagger", "email"), "foreign@example.invalid"),
            ("tag", ("tagger", "date"), "2026-08-13T15:21:33Z"),
        ):
            changed_ref, changed_tag = copy.deepcopy(ref), copy.deepcopy(tag)
            changed = changed_ref if target == "ref" else changed_tag
            parent = changed
            for key in path[:-1]:
                parent = parent[key]
            parent[path[-1]] = value
            mutations.append((changed_ref, changed_tag))
        for index, (changed_ref, changed_tag) in enumerate(mutations):
            with self.subTest(index=index), self.assertRaises(RC.ContractError):
                RC.validate_tag_record(
                    changed_ref,
                    changed_tag,
                    tag=self.TAG,
                    source_sha=self.SOURCE,
                    message=self.MESSAGE,
                    tagger_name="github-actions[bot]",
                    tagger_email="41898282+github-actions[bot]@users.noreply.github.com",
                    tagger_date=self.DATE,
                )

    def test_manifest_asset_is_the_exact_immutable_release_identity(self):
        manifest = release_manifest()
        exact, raw, asset = release_record("exact", manifest)
        self.assertEqual(
            RC.validate_release_record(
                exact,
                manifest=manifest,
                manifest_bytes=raw,
                asset_bytes=asset,
            ),
            "exact",
        )

        # Human-readable title and notes are deliberately informational. The
        # sole canonical manifest asset is the release identity.
        changed_notes = copy.deepcopy(exact)
        changed_notes["name"] = "different informational title"
        changed_notes["body"] = "different informational notes\n"
        self.assertEqual(
            RC.validate_release_record(
                changed_notes,
                manifest=manifest,
                manifest_bytes=raw,
                asset_bytes=asset,
            ),
            "exact",
        )

        mutations: list[dict[str, object]] = []
        for path, value in (
            (("tag_name",), "v0.1.11"),
            (("author", "login"), "owner"),
            (("author", "id"), 1),
            (("author", "id"), None),
            (("draft",), True),
            (("prerelease",), True),
            (("immutable",), False),
            (("immutable",), None),
            (("assets",), []),
            (("assets",), [*exact["assets"], copy.deepcopy(exact["assets"][0])]),
            (("assets", 0, "name"), "foreign.json"),
            (("assets", 0, "state"), "new"),
            (("assets", 0, "content_type"), "application/octet-stream"),
            (("assets", 0, "uploader", "login"), "owner"),
            (("assets", 0, "uploader", "id"), 1),
            (("assets", 0, "uploader"), None),
            (("assets", 0, "size"), len(raw) + 1),
            (("assets", 0, "digest"), "sha256:" + "f" * 64),
        ):
            changed = copy.deepcopy(exact)
            parent = changed
            for key in path[:-1]:
                parent = parent[key]
            parent[path[-1]] = value
            mutations.append(changed)
        for index, changed in enumerate(mutations):
            with self.subTest(index=index), self.assertRaises(RC.ContractError):
                RC.validate_release_record(
                    changed,
                    manifest=manifest,
                    manifest_bytes=raw,
                    asset_bytes=asset,
                )
        for wrong_asset in (None, raw + b" ", raw[:-1]):
            with self.subTest(asset_bytes=wrong_asset), self.assertRaises(RC.ContractError):
                RC.validate_release_record(
                    exact,
                    manifest=manifest,
                    manifest_bytes=raw,
                    asset_bytes=wrong_asset,
                )

    def test_manifest_schema_bytes_and_mode_are_closed_and_deterministic(self):
        manifest = release_manifest()
        self.assertEqual(RC.validate_release_manifest(manifest), manifest)
        canonical = RC.canonical_json_bytes(manifest)
        self.assertEqual(canonical, RC.canonical_json_bytes(copy.deepcopy(manifest)))
        mutations: list[dict[str, object]] = []
        for path, value in (
            (("repository",), "attacker/site"),
            (("tag",), "v0.1.11"),
            (("workflow_identity",), "https://example.invalid/workflow"),
            (("artifacts", "image", "alias"), "ghcr.io/owner/site:v0.1.11"),
            (("artifacts", "image", "digest"), "sha256:" + "f" * 64),
            (("artifacts", "chart", "digest_reference"), "foreign"),
            (("artifacts", "image", "signature", "required"), False),
            (("artifacts", "image", "sbom", "platforms"), ["linux/amd64"]),
        ):
            changed = copy.deepcopy(manifest)
            parent = changed
            for key in path[:-1]:
                parent = parent[key]
            parent[path[-1]] = value
            mutations.append(changed)
        extra = copy.deepcopy(manifest)
        extra["foreign"] = True
        mutations.append(extra)
        for index, changed in enumerate(mutations):
            with self.subTest(index=index), self.assertRaises(RC.ContractError):
                RC.validate_release_manifest(changed)

        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / RC.RELEASE_MANIFEST_NAME
            RC.write_release_manifest(path, manifest)
            parsed, raw = RC.read_release_manifest(
                path,
                expected_repository=RC.EXPECTED_REPOSITORY,
                require_mode=os.name != "nt",
            )
            self.assertEqual(parsed, manifest)
            self.assertEqual(raw, canonical)
            if os.name != "nt":
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            path.write_bytes(json.dumps(manifest, indent=2).encode("utf-8"))
            with self.assertRaises(RC.ContractError):
                RC.read_release_manifest(path, require_mode=False)


class PublicationTransactionTests(unittest.TestCase):
    TAG = "v0.1.10"
    SOURCE = "a" * 40
    MESSAGE = f"Release {TAG} from {SOURCE}"
    DATE = "2026-08-13T15:21:32Z"

    def tag_expected(self) -> dict[str, str]:
        return {
            "tag": self.TAG,
            "source_sha": self.SOURCE,
            "message": self.MESSAGE,
            "tagger_name": "github-actions[bot]",
            "tagger_email": "41898282+github-actions[bot]@users.noreply.github.com",
            "tagger_date": self.DATE,
        }

    def test_absent_create_verify_and_concurrent_retry_need_no_local_tag_ref(self):
        ref, tag = exact_tag_records(self.TAG, self.SOURCE, self.MESSAGE, self.DATE)
        # Both racers can observe absence. The winner creates the exact REST
        # records; the loser re-queries those records after its create fails.
        self.assertEqual(RC.classify_tag_state(404, None, None, **self.tag_expected()), "absent")
        self.assertEqual(RC.classify_tag_state(404, None, None, **self.tag_expected()), "absent")
        self.assertEqual(RC.classify_tag_state(200, ref, tag, **self.tag_expected()), "exact")
        self.assertEqual(RC.classify_tag_state(200, ref, tag, **self.tag_expected()), "exact")

        manifest = release_manifest()
        expected_release, raw, asset = release_record("exact", manifest)
        for _racer in range(2):
            self.assertEqual(
                RC.classify_release_state(
                    404,
                    None,
                    manifest=manifest,
                    manifest_bytes=raw,
                    asset_bytes=None,
                ),
                "absent",
            )
        for _retry in range(2):
            self.assertEqual(
                RC.classify_release_state(
                    200,
                    expected_release,
                    manifest=manifest,
                    manifest_bytes=raw,
                    asset_bytes=asset,
                ),
                "exact",
            )

    def test_draft_upload_publish_state_machine_is_exact_and_resumable(self):
        manifest = release_manifest()
        for expected in ("draft-empty", "draft-ready", "exact"):
            record, raw, asset = release_record(expected, manifest)
            self.assertEqual(
                RC.classify_release_state(
                    200,
                    record,
                    manifest=manifest,
                    manifest_bytes=raw,
                    asset_bytes=asset,
                ),
                expected,
            )
        # A published mutable Release and an "immutable" draft are burned
        # states; neither can be retried into the required state.
        for draft, immutable in ((False, False), (True, True)):
            record, raw, asset = release_record("draft-ready", manifest)
            record["draft"], record["immutable"] = draft, immutable
            with self.subTest(draft=draft, immutable=immutable), self.assertRaises(
                RC.ContractError
            ):
                RC.classify_release_state(
                    200,
                    record,
                    manifest=manifest,
                    manifest_bytes=raw,
                    asset_bytes=asset,
                )

    def test_missing_records_conflicts_and_non_authoritative_absence_fail_closed(self):
        ref, tag = exact_tag_records(self.TAG, self.SOURCE, self.MESSAGE, self.DATE)
        manifest = release_manifest()
        exact_release, raw, asset = release_record("exact", manifest)
        for status in (0, 301, 401, 403, 409, 422, 429, 500, 503):
            with self.subTest(kind="tag-status", status=status), self.assertRaises(RC.ContractError):
                RC.classify_tag_state(status, None, None, **self.tag_expected())
            with self.subTest(kind="release-status", status=status), self.assertRaises(RC.ContractError):
                RC.classify_release_state(
                    status,
                    None,
                    manifest=manifest,
                    manifest_bytes=raw,
                    asset_bytes=None,
                )
        for changed_ref, changed_tag in ((None, tag), (ref, None)):
            with self.assertRaises(RC.ContractError):
                RC.classify_tag_state(200, changed_ref, changed_tag, **self.tag_expected())
        with self.assertRaises(RC.ContractError):
            RC.classify_tag_state(404, ref, tag, **self.tag_expected())
        with self.assertRaises(RC.ContractError):
            RC.classify_release_state(
                404,
                exact_release,
                manifest=manifest,
                manifest_bytes=raw,
                asset_bytes=asset,
            )
        with self.assertRaises(RC.ContractError):
            RC.classify_release_state(
                200,
                None,
                manifest=manifest,
                manifest_bytes=raw,
                asset_bytes=None,
            )

    def test_exact_shell_state_assertions_kill_deletion_and_inversion_mutants(self):
        for state in ("absent", "draft-empty", "draft-ready", "exact"):
            self.assertEqual(RC.require_publication_state(state, state), state)
        for actual, required in (
            ("absent", "exact"),
            ("draft-empty", "draft-ready"),
            ("draft-ready", "exact"),
            ("exact", "absent"),
            ("foreign", "exact"),
        ):
            with self.subTest(actual=actual, required=required), self.assertRaises(RC.ContractError):
                RC.require_publication_state(actual, required)

    def test_cli_require_flag_is_load_bearing_for_tag_and_release_transactions(self):
        def invoke(arguments: list[str]) -> int:
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                return RC.main(arguments)

        tag_args = [
            "tag-state",
            "--http-status",
            "404",
            "--tag",
            self.TAG,
            "--source-sha",
            self.SOURCE,
            "--message",
            self.MESSAGE,
            "--tagger-name",
            "github-actions[bot]",
            "--tagger-email",
            "41898282+github-actions[bot]@users.noreply.github.com",
            "--tagger-date",
            self.DATE,
        ]
        self.assertEqual(invoke([*tag_args, "--require", "absent"]), 0)
        self.assertEqual(invoke([*tag_args, "--require", "exact"]), 1)

        with tempfile.TemporaryDirectory() as temporary:
            manifest_path = Path(temporary) / RC.RELEASE_MANIFEST_NAME
            RC.write_release_manifest(manifest_path, release_manifest())
            release_args = [
                "release-state",
                "--http-status",
                "404",
                "--manifest",
                str(manifest_path),
                "--repository",
                RC.EXPECTED_REPOSITORY,
            ]
            self.assertEqual(invoke([*release_args, "--require", "absent"]), 0)
            self.assertEqual(invoke([*release_args, "--require", "exact"]), 1)

            record, _raw, asset = release_record("exact")
            release_json = Path(temporary) / "release.json"
            asset_path = Path(temporary) / RC.RELEASE_MANIFEST_NAME
            release_json.write_text(json.dumps(record), encoding="utf-8")
            self.assertIsNotNone(asset)
            exact_args = [
                "release-state",
                "--http-status",
                "200",
                "--release-json",
                str(release_json),
                "--manifest",
                str(manifest_path),
                "--asset-content",
                str(asset_path),
                "--repository",
                RC.EXPECTED_REPOSITORY,
            ]
            self.assertEqual(invoke([*exact_args, "--require", "exact"]), 0)
            self.assertEqual(invoke([*exact_args, "--require", "draft-ready"]), 1)


class AttestationSetTests(unittest.TestCase):
    IMAGE = "ghcr.io/owner/site"
    DIGEST = "sha256:" + "d" * 64
    SOURCE = "https://github.com/owner/site"
    REVISION = "a" * 40
    PLATFORMS = ("linux/amd64", "linux/arm64")

    def expected(self) -> dict[str, dict[str, object]]:
        return {
            platform: RC.build_attestation_statement(
                embedded_predicate(self.SOURCE, self.REVISION, platform),
                image=self.IMAGE,
                digest=self.DIGEST,
                source=self.SOURCE,
                revision=self.REVISION,
                platform=platform,
                builder_run_id=BUILDER_RUN_ID,
            )
            for platform in self.PLATFORMS
        }

    def encode(self, statements) -> str:
        return "\n".join(json.dumps(verified_record(statement)) for statement in statements)

    def test_exact_authenticated_subject_predicate_and_platform_set(self):
        expected = self.expected()
        self.assertEqual(RC.validate_attestation_set(self.encode(expected.values()), expected), 2)

    def test_authentic_plus_foreign_missing_duplicate_and_inverted_bindings_fail(self):
        expected = self.expected()
        amd = expected["linux/amd64"]
        foreign = copy.deepcopy(expected["linux/arm64"])
        foreign["predicate"]["buildDefinition"]["internalParameters"]["release"]["source"] = "https://github.com/attacker/site"
        wrong_subject = copy.deepcopy(expected["linux/arm64"])
        wrong_subject["subject"][0]["digest"]["sha256"] = "e" * 64
        wrong_type = copy.deepcopy(expected["linux/arm64"])
        wrong_type["predicateType"] = "https://example.invalid/foreign"
        for statements in (
            [amd],
            [amd, amd],
            [amd, foreign],
            [amd, wrong_subject],
            [amd, wrong_type],
            [*expected.values(), foreign],
        ):
            with self.subTest(count=len(statements)), self.assertRaises(RC.ContractError):
                RC.validate_attestation_set(self.encode(statements), expected)

    def test_embedded_source_revision_builder_and_reserved_binding_mutants_fail(self):
        base = embedded_predicate(self.SOURCE, self.REVISION, "linux/amd64")
        mutations = []
        for path, value in (
            (("runDetails", "builder", "id"), "https://github.com/attacker/site/actions/runs/1/attempts/1"),
            (("runDetails", "metadata", "buildkit_metadata", "vcs", "source"), "https://github.com/attacker/site"),
            (("runDetails", "metadata", "buildkit_metadata", "vcs", "revision"), "b" * 40),
            (("buildDefinition", "internalParameters", "release"), {"platform": "linux/amd64"}),
        ):
            changed = copy.deepcopy(base)
            parent = changed
            for key in path[:-1]:
                parent = parent[key]
            parent[path[-1]] = value
            mutations.append(changed)
        for index, predicate in enumerate(mutations):
            with self.subTest(index=index), self.assertRaises(RC.ContractError):
                RC.build_attestation_statement(
                    predicate,
                    image=self.IMAGE,
                    digest=self.DIGEST,
                    source=self.SOURCE,
                    revision=self.REVISION,
                    platform="linux/amd64",
                    builder_run_id=BUILDER_RUN_ID,
                )


class BuilderRunIdentityTests(unittest.TestCase):
    """The SLSA builder must name ONE exact Actions run, not any run.

    Before issue #111 the builder identity was checked with
    ``builder["id"].startswith(source + "/actions/runs/")``, which every run
    of every workflow in this repository satisfies forever. These tests are
    written so that restoring that prefix check turns them red: each denied
    input below starts with exactly that prefix.
    """

    IMAGE = "ghcr.io/owner/site"
    DIGEST = "sha256:" + "d" * 64
    SOURCE = "https://github.com/owner/site"
    REVISION = "a" * 40
    PLATFORM = "linux/amd64"

    def build(self, predicate, run_id=BUILDER_RUN_ID):
        return RC.build_attestation_statement(
            predicate,
            image=self.IMAGE,
            digest=self.DIGEST,
            source=self.SOURCE,
            revision=self.REVISION,
            platform=self.PLATFORM,
            builder_run_id=run_id,
        )

    def test_the_authoritative_run_with_its_buildkit_attempt_suffix_is_accepted(self):
        # The exact shape measured on every published image of this
        # repository: <source>/actions/runs/<run>/attempts/<n>.
        statement = self.build(embedded_predicate(self.SOURCE, self.REVISION, self.PLATFORM))
        self.assertEqual(
            statement["predicate"]["runDetails"]["builder"]["id"],
            f"{self.SOURCE}/actions/runs/{BUILDER_RUN_ID}/attempts/1",
        )
        # A LATER attempt of the SAME run is the same authoritative run:
        # GitHub's re-run recovery keeps GITHUB_RUN_ID and increments only
        # the attempt, so denying it would deny a legitimate release.
        self.assertEqual(
            self.build(
                embedded_predicate(self.SOURCE, self.REVISION, self.PLATFORM, attempt="7")
            )["predicate"]["runDetails"]["builder"]["id"],
            f"{self.SOURCE}/actions/runs/{BUILDER_RUN_ID}/attempts/7",
        )

    def test_a_different_run_in_this_same_repository_is_denied(self):
        # THE mutant that survived the prefix check: a stale, cancelled, or
        # unrelated run of this very repository.
        for foreign_run in ("124", "12", "1234", "9" * 18):
            with self.subTest(run=foreign_run), self.assertRaises(RC.ContractError):
                self.build(
                    embedded_predicate(
                        self.SOURCE, self.REVISION, self.PLATFORM, builder_run_id=foreign_run
                    )
                )

    def test_unexpected_builder_id_suffixes_are_denied(self):
        base = f"{self.SOURCE}/actions/runs/{BUILDER_RUN_ID}"
        for builder_id in (
            base,  # no attempt segment: not a shape BuildKit emits here
            base + "/attempts/",
            base + "/attempts/0",
            base + "/attempts/01",
            base + "/attempts/one",
            base + "/attempts/1/",
            base + "/attempts/1/jobs/9",
            base + "/attempts/1#fragment",
            base + "/../../999/attempts/1",
            base + "4/attempts/1",  # run 1234 riding on run 123's prefix
            f"{self.SOURCE}/actions/runs/{BUILDER_RUN_ID}%2f/attempts/1",
        ):
            predicate = embedded_predicate(self.SOURCE, self.REVISION, self.PLATFORM)
            predicate["runDetails"]["builder"]["id"] = builder_id
            with self.subTest(builder_id=builder_id), self.assertRaises(RC.ContractError):
                self.build(predicate)

    def test_a_malformed_builder_run_argument_is_refused_before_any_comparison(self):
        predicate = embedded_predicate(self.SOURCE, self.REVISION, self.PLATFORM)
        for run_id in ("", " ", "0", "0123", "12 3", "12a", "-1", "+1", "1\n", "1/attempts/1", ".*"):
            with self.subTest(run_id=run_id), self.assertRaises(RC.ContractError) as failure:
                self.build(predicate, run_id=run_id)
            self.assertIn("positive decimal Actions run ID", str(failure.exception))

    def test_a_non_string_builder_id_is_denied_rather_than_crashing(self):
        for value in (None, 123, ["x"], {"id": "x"}):
            predicate = embedded_predicate(self.SOURCE, self.REVISION, self.PLATFORM)
            predicate["runDetails"]["builder"]["id"] = value
            with self.subTest(value=value), self.assertRaises(RC.ContractError):
                self.build(predicate)

    def test_recovering_the_builder_run_returns_the_exact_run_and_denies_foreign_shapes(self):
        predicate = embedded_predicate(
            self.SOURCE, self.REVISION, self.PLATFORM, builder_run_id="32698930902", attempt="3"
        )
        self.assertEqual(
            RC.read_attestation_builder_run(predicate, source=self.SOURCE), "32698930902"
        )
        # Recovery is bound to the SAME anchored shape the comparison uses:
        # a builder ID this cannot parse can never become an accepted run.
        for builder_id in (
            f"{self.SOURCE}/actions/runs/123",
            f"{self.SOURCE}/actions/runs/123/attempts/0",
            "https://github.com/attacker/site/actions/runs/123/attempts/1",
            f"{self.SOURCE}/actions/runs/abc/attempts/1",
        ):
            broken = copy.deepcopy(predicate)
            broken["runDetails"]["builder"]["id"] = builder_id
            with self.subTest(builder_id=builder_id), self.assertRaises(RC.ContractError):
                RC.read_attestation_builder_run(broken, source=self.SOURCE)

    def test_a_run_recovered_from_one_platform_denies_a_second_platform_naming_another_run(self):
        # The reuse and audit paths recover the run from the first platform
        # and reuse it for every other one, so a multi-architecture image
        # whose two predicates disagree fails instead of passing twice.
        amd = embedded_predicate(self.SOURCE, self.REVISION, "linux/amd64", builder_run_id="777")
        arm = embedded_predicate(self.SOURCE, self.REVISION, "linux/arm64", builder_run_id="778")
        recovered = RC.read_attestation_builder_run(amd, source=self.SOURCE)
        self.assertEqual(recovered, "777")
        self.build(amd, run_id=recovered)
        with self.assertRaises(RC.ContractError):
            RC.build_attestation_statement(
                arm,
                image=self.IMAGE,
                digest=self.DIGEST,
                source=self.SOURCE,
                revision=self.REVISION,
                platform="linux/arm64",
                builder_run_id=recovered,
            )


class SbomAttestationTests(unittest.TestCase):
    IMAGE = "ghcr.io/owner/site"
    DIGEST = "sha256:" + "d" * 64

    def documents(self) -> dict[str, dict[str, object]]:
        return {
            "linux/amd64": spdx_document("amd64"),
            "linux/arm64": spdx_document("arm64"),
        }

    def platform_map(self) -> dict[str, object]:
        return {
            platform: {"SPDX": document}
            for platform, document in self.documents().items()
        }

    def expected(self) -> dict[str, dict[str, object]]:
        return {
            platform: RC.build_sbom_statement(
                document,
                image=self.IMAGE,
                digest=self.DIGEST,
                platform=platform,
            )
            for platform, document in self.documents().items()
        }

    @staticmethod
    def encode(statements) -> str:
        return "\n".join(json.dumps(verified_record(statement)) for statement in statements)

    def test_exact_non_null_platform_payloads_and_signed_set_are_required(self):
        self.assertEqual(RC.validate_sbom_platform_map(self.platform_map()), self.documents())
        expected = self.expected()
        self.assertEqual(
            RC.validate_sbom_attestation_set(self.encode(expected.values()), expected), 2
        )

    def test_disabled_missing_null_empty_duplicate_foreign_and_malformed_sboms_fail(self):
        exact = self.platform_map()
        mutants = []
        for platform, value in (
            ("linux/amd64", None),
            ("linux/amd64", {}),
            ("linux/amd64", {"SPDX": None}),
            ("linux/amd64", {"SPDX": {}}),
            ("linux/amd64", {"SPDX": spdx_document("amd64"), "foreign": {}}),
        ):
            changed = copy.deepcopy(exact)
            changed[platform] = value
            mutants.append(changed)
        missing = copy.deepcopy(exact)
        del missing["linux/arm64"]
        mutants.append(missing)
        foreign = copy.deepcopy(exact)
        foreign["linux/s390x"] = {"SPDX": spdx_document("s390x")}
        mutants.append(foreign)
        empty_packages = copy.deepcopy(exact)
        empty_packages["linux/arm64"]["SPDX"]["packages"] = []
        mutants.append(empty_packages)
        for index, value in enumerate(mutants):
            with self.subTest(index=index), self.assertRaises(RC.ContractError):
                RC.validate_sbom_platform_map(value)

        expected = self.expected()
        amd64 = expected["linux/amd64"]
        # cosign generates the subject itself from the CLI target, so it
        # carries no platform: both platforms' expected subjects are the
        # bare image and the same digest. A wrong SUBJECT is therefore a
        # foreign digest or a foreign image, mirroring
        # AttestationSetTests — not a platform string, which the subject no
        # longer encodes.
        wrong_subject = copy.deepcopy(expected["linux/arm64"])
        wrong_subject["subject"][0]["digest"]["sha256"] = "e" * 64
        wrong_image = copy.deepcopy(expected["linux/arm64"])
        wrong_image["subject"][0]["name"] = "ghcr.io/attacker/site"
        wrong_payload = copy.deepcopy(expected["linux/arm64"])
        wrong_payload["predicate"]["name"] = "foreign"
        malformed = copy.deepcopy(expected["linux/arm64"])
        malformed["predicate"]["packages"] = []
        for statements in (
            [amd64],
            [amd64, amd64],
            [amd64, wrong_subject],
            [amd64, wrong_image],
            [amd64, wrong_payload],
            [amd64, malformed],
            [*expected.values(), copy.deepcopy(amd64)],
        ):
            with self.subTest(count=len(statements)), self.assertRaises(RC.ContractError):
                RC.validate_sbom_attestation_set(self.encode(statements), expected)

    def test_sbom_cli_rejects_recursive_duplicate_members(self):
        with tempfile.TemporaryDirectory() as temporary:
            sbom = Path(temporary) / "sbom.json"
            sbom.write_text(
                '{"linux/amd64":{"SPDX":{"SPDXID":"one","SPDXID":"two"}},'
                '"linux/arm64":null}',
                encoding="utf-8",
            )
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(
                    RC.main(["sbom-platforms", "--json", str(sbom)]), 1
                )


class AttestationStatementCLITests(unittest.TestCase):
    """CLI-level oracles for the `attestation-statement` subcommand.

    AttestationSetTests above builds its expectations with
    RC.build_attestation_statement and then re-wraps those SAME objects as
    the "verified" cosign records, so `_type` is only ever compared against
    itself and no input can turn that comparison red. These tests instead
    drive the real subcommand end to end through RC.main and pin the
    on-disk contract against literals independent of the module under
    test, so a reverted INTOTO_STATEMENT_TYPE, a --predicate-output that
    writes the wrong object, an optional --predicate-output, or a deleted
    write each turn a specific test here red.
    """

    IMAGE = "ghcr.io/owner/site"
    DIGEST = "sha256:" + "f" * 64
    SOURCE = "https://github.com/owner/site"
    REVISION = "c" * 40
    PLATFORM = "linux/amd64"

    def invoke(
        self,
        temporary: str,
        *,
        include_predicate_output: bool = True,
        include_builder_run_id: bool = True,
        builder_run_id: str = BUILDER_RUN_ID,
        predicate_run_id: str = BUILDER_RUN_ID,
    ) -> tuple[int, Path, Path]:
        predicate_path = Path(temporary) / "predicate.json"
        predicate_path.write_text(
            json.dumps(
                embedded_predicate(
                    self.SOURCE, self.REVISION, self.PLATFORM, builder_run_id=predicate_run_id
                )
            ),
            encoding="utf-8",
        )
        output_path = Path(temporary) / "statement.json"
        predicate_output_path = Path(temporary) / "modified-predicate.json"
        arguments = [
            "attestation-statement",
            "--predicate", str(predicate_path),
            "--output", str(output_path),
        ]
        if include_predicate_output:
            arguments += ["--predicate-output", str(predicate_output_path)]
        arguments += [
            "--image", self.IMAGE,
            "--digest", self.DIGEST,
            "--source", self.SOURCE,
            "--revision", self.REVISION,
            "--platform", self.PLATFORM,
        ]
        if include_builder_run_id:
            arguments += ["--builder-run-id", builder_run_id]
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            code = RC.main(arguments)
        return code, output_path, predicate_output_path

    def test_missing_builder_run_id_flag_exits_two(self):
        # The argument is REQUIRED: dropping it from a caller cannot degrade
        # into an unchecked builder identity, it stops the release.
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(SystemExit) as failure:
                self.invoke(temporary, include_builder_run_id=False)
            self.assertEqual(failure.exception.code, 2)

    def test_cli_accepts_the_named_run_and_denies_another_run_of_this_repository(self):
        with tempfile.TemporaryDirectory() as temporary:
            self.assertEqual(self.invoke(temporary)[0], 0)
        with tempfile.TemporaryDirectory() as temporary:
            errors = io.StringIO()
            predicate_path = Path(temporary) / "predicate.json"
            predicate_path.write_text(
                json.dumps(
                    embedded_predicate(
                        self.SOURCE, self.REVISION, self.PLATFORM, builder_run_id="999"
                    )
                ),
                encoding="utf-8",
            )
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(errors):
                code = RC.main(
                    [
                        "attestation-statement",
                        "--predicate", str(predicate_path),
                        "--output", str(Path(temporary) / "statement.json"),
                        "--predicate-output", str(Path(temporary) / "predicate-out.json"),
                        "--image", self.IMAGE,
                        "--digest", self.DIGEST,
                        "--source", self.SOURCE,
                        "--revision", self.REVISION,
                        "--platform", self.PLATFORM,
                        "--builder-run-id", BUILDER_RUN_ID,
                    ]
                )
            self.assertEqual(code, 1)
            self.assertIn(f"DENY: embedded predicate builder is not Actions run {BUILDER_RUN_ID}", errors.getvalue())
            self.assertFalse((Path(temporary) / "statement.json").exists())

    def test_cli_recovers_the_builder_run_and_denies_a_foreign_predicate(self):
        with tempfile.TemporaryDirectory() as temporary:
            predicate_path = Path(temporary) / "predicate.json"
            predicate_path.write_text(
                json.dumps(
                    embedded_predicate(
                        self.SOURCE, self.REVISION, self.PLATFORM, builder_run_id="4242", attempt="2"
                    )
                ),
                encoding="utf-8",
            )
            output = io.StringIO()
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
                code = RC.main(
                    [
                        "attestation-builder-run",
                        "--predicate", str(predicate_path),
                        "--source", self.SOURCE,
                    ]
                )
            self.assertEqual(code, 0)
            self.assertEqual(output.getvalue().strip(), "4242")
            errors = io.StringIO()
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(errors):
                foreign = RC.main(
                    [
                        "attestation-builder-run",
                        "--predicate", str(predicate_path),
                        "--source", "https://github.com/attacker/site",
                    ]
                )
            self.assertEqual(foreign, 1)
            self.assertIn("DENY: embedded predicate builder is not an Actions run", errors.getvalue())

    def test_statement_type_literal_is_the_pinned_in_toto_v01_uri(self):
        # Hardcoded here rather than read from RC.INTOTO_STATEMENT_TYPE: this
        # is the exact literal release_contract.py carried before the 0.1.16
        # fix (CHANGELOG [0.1.16]) -- a mutant that reverts the module
        # constant back to it must turn THIS literal comparison red.
        # Comparing against the module's own constant would be
        # self-referential and vacuous, exactly AttestationSetTests' gap.
        with tempfile.TemporaryDirectory() as temporary:
            code, output_path, _ = self.invoke(temporary)
            self.assertEqual(code, 0)
            statement = json.loads(output_path.read_text(encoding="utf-8"))
        self.assertEqual(statement["_type"], "https://in-toto.io/Statement/v0.1")

    def test_predicate_output_file_is_exactly_and_only_the_statement_predicate(self):
        with tempfile.TemporaryDirectory() as temporary:
            code, output_path, predicate_output_path = self.invoke(temporary)
            self.assertEqual(code, 0)
            statement = json.loads(output_path.read_text(encoding="utf-8"))
            modified_predicate = json.loads(predicate_output_path.read_text(encoding="utf-8"))
        # Exactly the predicate member -- kills a mutant that writes some
        # other object to --predicate-output.
        self.assertEqual(modified_predicate, statement["predicate"])
        # A strict subset of --output's content, never the whole statement:
        # a mutant that writes the whole statement to --predicate-output
        # would fail the equality above, and would also carry every one of
        # the statement's own envelope keys, which the real predicate
        # object never does.
        self.assertNotEqual(modified_predicate, statement)
        for envelope_key in statement:
            self.assertNotIn(envelope_key, modified_predicate)

    def test_missing_predicate_output_flag_exits_two(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(SystemExit) as failure:
                self.invoke(temporary, include_predicate_output=False)
            self.assertEqual(failure.exception.code, 2)

    def test_predicate_output_file_exists_and_is_non_empty_after_success(self):
        with tempfile.TemporaryDirectory() as temporary:
            code, _, predicate_output_path = self.invoke(temporary)
            self.assertEqual(code, 0)
            self.assertTrue(predicate_output_path.exists())
            self.assertGreater(predicate_output_path.stat().st_size, 0)


class SbomStatementCLITests(unittest.TestCase):
    """CLI-level oracles for the `sbom-statement` subcommand.

    SbomAttestationTests above builds its expectations with
    RC.build_sbom_statement and then re-wraps those SAME objects as the
    "verified" cosign records, so `_type` and `predicateType` are only ever
    compared against themselves and no input can turn either comparison
    red. These tests instead drive the real subcommand end to end through
    RC.main and pin the on-disk contract against literals independent of
    the module under test, mirroring AttestationStatementCLITests above for
    the SPDX path.
    """

    IMAGE = "ghcr.io/owner/site"
    DIGEST = "sha256:" + "f" * 64
    PLATFORM = "linux/amd64"

    def invoke(self, temporary: str, *, include_predicate_output: bool = True) -> tuple[int, Path, Path]:
        spdx_path = Path(temporary) / "sbom.json"
        spdx_path.write_text(json.dumps(spdx_document("amd64")), encoding="utf-8")
        output_path = Path(temporary) / "statement.json"
        predicate_output_path = Path(temporary) / "modified-predicate.json"
        arguments = [
            "sbom-statement",
            "--spdx", str(spdx_path),
            "--output", str(output_path),
        ]
        if include_predicate_output:
            arguments += ["--predicate-output", str(predicate_output_path)]
        arguments += [
            "--image", self.IMAGE,
            "--digest", self.DIGEST,
            "--platform", self.PLATFORM,
        ]
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            code = RC.main(arguments)
        return code, output_path, predicate_output_path

    def test_statement_type_literal_is_the_pinned_in_toto_v01_uri(self):
        # Hardcoded rather than read from RC.INTOTO_STATEMENT_TYPE, for the
        # same reason as AttestationStatementCLITests: SbomAttestationTests
        # compares _type only against the module's own constant, so a
        # mutant that changes the constant survives it undetected.
        with tempfile.TemporaryDirectory() as temporary:
            code, output_path, _ = self.invoke(temporary)
            self.assertEqual(code, 0)
            statement = json.loads(output_path.read_text(encoding="utf-8"))
        self.assertEqual(statement["_type"], "https://in-toto.io/Statement/v0.1")

    def test_predicate_type_literal_is_the_pinned_spdx_document_uri(self):
        # Hardcoded rather than read from RC.SPDX_PREDICATE_TYPE: the SPDX
        # path's own analogous constant, with the same self-referential gap
        # in SbomAttestationTests -- a mutant that changes it must turn
        # THIS comparison red, not one derived from the same constant.
        with tempfile.TemporaryDirectory() as temporary:
            code, output_path, _ = self.invoke(temporary)
            self.assertEqual(code, 0)
            statement = json.loads(output_path.read_text(encoding="utf-8"))
        self.assertEqual(statement["predicateType"], "https://spdx.dev/Document")

    def test_predicate_output_file_is_exactly_and_only_the_statement_predicate(self):
        with tempfile.TemporaryDirectory() as temporary:
            code, output_path, predicate_output_path = self.invoke(temporary)
            self.assertEqual(code, 0)
            statement = json.loads(output_path.read_text(encoding="utf-8"))
            modified_predicate = json.loads(predicate_output_path.read_text(encoding="utf-8"))
        self.assertEqual(modified_predicate, statement["predicate"])
        self.assertNotEqual(modified_predicate, statement)
        for envelope_key in statement:
            self.assertNotIn(envelope_key, modified_predicate)

    def test_missing_predicate_output_flag_exits_two(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(SystemExit) as failure:
                self.invoke(temporary, include_predicate_output=False)
            self.assertEqual(failure.exception.code, 2)

    def test_predicate_output_file_exists_and_is_non_empty_after_success(self):
        with tempfile.TemporaryDirectory() as temporary:
            code, _, predicate_output_path = self.invoke(temporary)
            self.assertEqual(code, 0)
            self.assertTrue(predicate_output_path.exists())
            self.assertGreater(predicate_output_path.stat().st_size, 0)


class GitTransitionTests(unittest.TestCase):
    def git(self, root: Path, *args: str) -> str:
        return subprocess.run(["git", "-C", str(root), *args], check=True, text=True, stdout=subprocess.PIPE).stdout.strip()

    def commit(self, root: Path, version: str) -> str:
        files = snapshot(version)
        for name, contents in files.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(contents, encoding="utf-8")
        self.git(root, "add", ".")
        self.git(root, "-c", "user.name=Release Test", "-c", "user.email=release@example.invalid", "commit", "-m", version)
        return self.git(root, "rev-parse", "HEAD")

    def metadata_commit(self, root: Path, marker: str) -> str:
        (root / "README.md").write_text(marker + "\n", encoding="utf-8")
        self.git(root, "add", "README.md")
        self.git(root, "-c", "user.name=Release Test", "-c", "user.email=release@example.invalid", "commit", "-m", marker)
        return self.git(root, "rev-parse", "HEAD")

    def test_three_sequential_main_commits_and_stale_base_rejection(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.git(root, "init", "-q")
            self.git(root, "branch", "-m", "main")
            commits = [self.commit(root, version) for version in ("0.1.9", "0.1.10", "0.1.11", "0.1.12")]
            for index in range(1, len(commits)):
                intent = RC.validate_transition(root, commits[index - 1], commits[index], first_parent=True)
                self.assertEqual(intent.tag, f"v0.1.{9 + index}")
            with self.assertRaises(RC.ContractError):
                RC.validate_transition(root, commits[1], commits[3], first_parent=True)
            with self.assertRaises(RC.ContractError):
                RC.validate_transition(root, commits[2], commits[1], first_parent=True)

            # GitHub's enabled rebase merge can land several linear commits in
            # one push. The exact base -> final-tree patch step is the release
            # intent even when an earlier commit in the same atomic push has
            # not updated the locks yet; the final SHA is the one released.
            self.git(root, "checkout", "-q", "-b", "rebase-range", commits[0])
            intermediate = self.metadata_commit(root, "unreleased change")
            final_head = self.commit(root, "0.1.10")
            intent = RC.validate_transition(root, commits[0], final_head, first_parent=True)
            self.assertEqual(intent, RC.ReleaseIntent(final_head, RC.Version.parse("0.1.10")))
            window = RC.discover_transition_window(root, final_head)
            self.assertEqual(window.base_sha, intermediate)
            self.assertEqual(window.intent, intent)
            self.assertNotEqual(intermediate, final_head)

            # A later metadata commit that preserves the final release locks
            # is also one exact rebase-merge intent and remains discoverable.
            preserved_head = self.metadata_commit(root, "post-bump repair")
            preserved = RC.validate_transition(root, commits[0], preserved_head, first_parent=True)
            self.assertEqual(preserved, RC.ReleaseIntent(preserved_head, RC.Version.parse("0.1.10")))
            preserved_window = RC.discover_transition_window(root, preserved_head)
            self.assertEqual(preserved_window.base_sha, intermediate)
            self.assertEqual(preserved_window.intent, preserved)

            # A second patch in the same integration would collapse two
            # release intents into one tag and is rejected at the endpoint.
            self.git(root, "checkout", "-q", "-b", "double-bump", commits[0])
            self.commit(root, "0.1.10")
            double_head = self.commit(root, "0.1.11")
            with self.assertRaises(RC.ContractError):
                RC.validate_transition(root, commits[0], double_head, first_parent=True)

            self.git(root, "checkout", "-q", "-b", "stale", commits[0])
            stale_head = self.commit(root, "0.1.12")
            with self.assertRaises(RC.ContractError):
                RC.validate_transition(root, commits[2], stale_head, first_parent=False)

    def test_real_two_parent_commit_is_denied_in_pr_and_main_modes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.git(root, "init", "-q")
            self.git(root, "branch", "-m", "main")
            base = self.commit(root, "0.1.9")
            self.git(root, "checkout", "-q", "-b", "topic", base)
            self.commit(root, "0.1.10")
            self.git(root, "checkout", "-q", "main")
            self.metadata_commit(root, "independent main change")
            self.git(
                root,
                "-c",
                "user.name=Release Test",
                "-c",
                "user.email=release@example.invalid",
                "merge",
                "--no-ff",
                "topic",
                "-m",
                "two-parent mutant",
            )
            merge_head = self.git(root, "rev-parse", "HEAD")
            self.assertEqual(
                len(self.git(root, "rev-list", "--parents", "-n", "1", merge_head).split()),
                3,
            )
            for first_parent in (False, True):
                with self.subTest(first_parent=first_parent), self.assertRaises(RC.ContractError):
                    RC.validate_transition(root, base, merge_head, first_parent=first_parent)

    def test_every_intermediate_version_state_rejects_skip_reversion_and_future(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.git(root, "init", "-q")
            self.git(root, "branch", "-m", "main")
            base = self.commit(root, "0.1.9")

            self.git(root, "checkout", "-q", "-b", "skip", base)
            skip = self.commit(root, "0.1.11")
            for operation in (
                lambda: RC.validate_transition(root, base, skip, first_parent=False),
                lambda: RC.discover_transition_window(root, skip),
            ):
                with self.assertRaises(RC.ContractError) as denied:
                    operation()
                self.assertIn("VERSION skip or future value", str(denied.exception))
                self.assertIn("0.1.9 -> 0.1.11; expected 0.1.10", str(denied.exception))

            self.git(root, "checkout", "-q", "-b", "reversion", base)
            self.commit(root, "0.1.10")
            reverted = self.commit(root, "0.1.9")
            repaired = self.commit(root, "0.1.10")
            for head in (reverted, repaired):
                for operation in (
                    lambda head=head: RC.validate_transition(
                        root, base, head, first_parent=False
                    ),
                    lambda head=head: RC.discover_transition_window(root, head),
                ):
                    with self.assertRaises(RC.ContractError) as denied:
                        operation()
                    self.assertIn("VERSION reversion", str(denied.exception))
                    self.assertIn("0.1.10 -> 0.1.9", str(denied.exception))

            self.git(root, "checkout", "-q", "-b", "transient-future", base)
            self.commit(root, "0.1.10")
            future = self.commit(root, "0.1.12")
            repaired_future = self.commit(root, "0.1.11")
            for head in (future, repaired_future):
                for operation in (
                    lambda head=head: RC.validate_transition(
                        root, base, head, first_parent=True
                    ),
                    lambda head=head: RC.discover_transition_window(root, head),
                ):
                    with self.assertRaises(RC.ContractError) as denied:
                        operation()
                    self.assertIn("VERSION skip or future value", str(denied.exception))
                    self.assertIn("0.1.10 -> 0.1.12; expected 0.1.11", str(denied.exception))

            # Two sequential one-patch main releases are valid recovery
            # history, but can never be collapsed into one PR/push boundary.
            self.git(root, "checkout", "-q", "-b", "two-releases", base)
            first = self.commit(root, "0.1.10")
            second = self.commit(root, "0.1.11")
            with self.assertRaises(RC.ContractError) as denied:
                RC.validate_transition(root, base, second, first_parent=True)
            self.assertIn("exactly 1 one-patch boundary; found 2", str(denied.exception))
            window = RC.discover_transition_window(root, second)
            self.assertEqual(window.base_sha, first)
            self.assertEqual(window.intent, RC.ReleaseIntent(second, RC.Version.parse("0.1.11")))

    def test_recovery_validates_preinitialization_and_version_disappearance(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.git(root, "init", "-q")
            self.git(root, "branch", "-m", "main")
            self.metadata_commit(root, "before VERSION existed")
            initialized = self.commit(root, "0.1.9")
            released = self.commit(root, "0.1.10")
            window = RC.discover_transition_window(root, released)
            self.assertEqual(window.base_sha, initialized)
            self.assertEqual(window.intent.tag, "v0.1.10")

            (root / "VERSION").unlink()
            self.git(root, "add", "-u")
            self.git(
                root,
                "-c",
                "user.name=Release Test",
                "-c",
                "user.email=release@example.invalid",
                "commit",
                "-m",
                "remove VERSION",
            )
            disappeared = self.git(root, "rev-parse", "HEAD")
            with self.assertRaises(RC.ContractError) as denied:
                RC.discover_transition_window(root, disappeared)
            self.assertIn("VERSION disappeared after initialization", str(denied.exception))


class NoArtifactClassTests(unittest.TestCase):
    """The documentation-only class must fail closed in every direction."""

    def git(self, root: Path, *args: str) -> str:
        return subprocess.run(["git", "-C", str(root), *args], check=True, text=True, stdout=subprocess.PIPE).stdout.strip()

    def release_commit(self, root: Path, version: str) -> str:
        files = snapshot(version)
        for name, contents in files.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(contents, encoding="utf-8")
        self.git(root, "add", ".")
        self.git(root, "-c", "user.name=Release Test", "-c", "user.email=release@example.invalid", "commit", "-m", version)
        return self.git(root, "rev-parse", "HEAD")

    def paths_commit(self, root: Path, files: dict[str, str | None], marker: str) -> str:
        for name, contents in files.items():
            path = root / name
            if contents is None:
                path.unlink()
                self.git(root, "rm", "-q", "--cached", name)
                continue
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(contents, encoding="utf-8")
            self.git(root, "add", name)
        self.git(root, "-c", "user.name=Release Test", "-c", "user.email=release@example.invalid", "commit", "-m", marker)
        return self.git(root, "rev-parse", "HEAD")

    def repo(self, temporary: str) -> tuple[Path, str]:
        root = Path(temporary)
        self.git(root, "init", "-q")
        self.git(root, "branch", "-m", "main")
        return root, self.release_commit(root, "0.1.9")

    def test_documentation_path_table_is_closed_in_both_directions(self):
        for path, expected in (
            ("AGENTS.md", True),
            ("README.md", True),
            (".gitignore", True),
            ("docs/guide.md", True),
            ("docs/deep/nested.md", True),
            ("CHANGELOG.md", False),
            ("VERSION", False),
            ("LICENSE", False),
            ("chart/Chart.yaml", False),
            ("chart/values.yaml", False),
            ("scripts/ci/release_contract.py", False),
            (".github/workflows/pr-gate.yml", False),
            (".github/dependabot.yml", False),
            ("docs/tool.py", False),
            ("docs/README", False),
            ("app/.gitignore", False),
            ("readme.md", False),
            ("main.go", False),
            ("", False),
        ):
            with self.subTest(path=path):
                self.assertIs(RC.is_documentation_path(path), expected)

    def test_docs_only_single_commit_classifies_no_artifact(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, base = self.repo(temporary)
            head = self.paths_commit(root, {"AGENTS.md": "agents contract\n"}, "docs")
            verdict = RC.classify_transition(root, base, head, first_parent=True)
            self.assertEqual(
                verdict,
                {
                    "class": "no-artifact",
                    "base_sha": base,
                    "source_sha": head,
                    "version": "0.1.9",
                    "tag": "v0.1.9",
                    "commits": 1,
                },
            )

    def test_docs_only_add_edit_delete_range_classifies_no_artifact(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, base = self.repo(temporary)
            self.paths_commit(root, {"docs/guide.md": "guide\n", ".gitignore": "*.tmp\n"}, "add")
            self.paths_commit(root, {"README.md": "edited readme\n"}, "edit")
            head = self.paths_commit(root, {"docs/guide.md": None}, "delete")
            verdict = RC.classify_transition(root, base, head, first_parent=True)
            self.assertEqual(verdict["class"], "no-artifact")
            self.assertEqual(verdict["commits"], 3)
            self.assertEqual(verdict["tag"], "v0.1.9")

    def test_mixed_range_without_release_patch_denies_naming_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, base = self.repo(temporary)
            self.paths_commit(root, {"AGENTS.md": "docs edit\n"}, "docs")
            head = self.paths_commit(root, {"main.go": "package main\n"}, "code")
            with self.assertRaises(RC.ContractError) as denied:
                RC.classify_transition(root, base, head, first_parent=True)
            self.assertIn("without one exact release patch", str(denied.exception))
            self.assertIn("main.go", str(denied.exception))

    def test_artifact_only_range_without_release_patch_denies(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, base = self.repo(temporary)
            head = self.paths_commit(root, {"main.go": "package main\n"}, "code")
            with self.assertRaises(RC.ContractError):
                RC.classify_transition(root, base, head, first_parent=True)

    def test_changelog_only_edit_denies(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, base = self.repo(temporary)
            changed = (root / "CHANGELOG.md").read_text(encoding="utf-8") + "\n- stray claim\n"
            head = self.paths_commit(root, {"CHANGELOG.md": changed}, "stray")
            with self.assertRaises(RC.ContractError) as denied:
                RC.classify_transition(root, base, head, first_parent=True)
            self.assertIn("CHANGELOG.md", str(denied.exception))

    def test_docs_range_with_full_release_patch_stays_artifact(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, base = self.repo(temporary)
            files = dict(snapshot("0.1.10"))
            files["AGENTS.md"] = "agents contract\n"
            head = self.paths_commit(root, files, "release with docs")
            verdict = RC.classify_transition(root, base, head, first_parent=True)
            self.assertEqual(verdict["class"], "artifact")
            self.assertEqual(verdict["tag"], "v0.1.10")
            self.assertEqual(verdict["source_sha"], head)
            intent = RC.validate_transition(root, base, head, first_parent=True)
            self.assertEqual(intent, RC.ReleaseIntent(head, RC.Version.parse("0.1.10")))

    def test_touch_then_revert_inside_range_denies(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, base = self.repo(temporary)
            self.paths_commit(root, {"main.go": "package main\n"}, "touch")
            self.paths_commit(root, {"main.go": None}, "revert")
            head = self.paths_commit(root, {"AGENTS.md": "docs edit\n"}, "docs")
            with self.assertRaises(RC.ContractError) as denied:
                RC.classify_transition(root, base, head, first_parent=True)
            self.assertIn("main.go", str(denied.exception))

    def test_symlink_swap_at_documentation_path_denies(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, base = self.repo(temporary)
            os.symlink("AGENTS.md", root / "README.md")
            self.git(root, "add", "README.md")
            self.git(root, "-c", "user.name=Release Test", "-c", "user.email=release@example.invalid", "commit", "-m", "symlink add")
            added = self.git(root, "rev-parse", "HEAD")
            with self.assertRaises(RC.ContractError):
                RC.classify_transition(root, base, added, first_parent=True)

            seeded = self.paths_commit(root, {"docs/real.md": "real file\n"}, "seed doc")
            (root / "docs/real.md").unlink()
            os.symlink("../CHANGELOG.md", root / "docs/real.md")
            self.git(root, "add", "docs/real.md")
            self.git(root, "-c", "user.name=Release Test", "-c", "user.email=release@example.invalid", "commit", "-m", "typechange")
            swapped = self.git(root, "rev-parse", "HEAD")
            with self.assertRaises(RC.ContractError):
                RC.classify_transition(root, seeded, swapped, first_parent=True)

    def test_executable_bit_on_markdown_remains_documentation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, _ = self.repo(temporary)
            base = self.paths_commit(root, {"README.md": "# readme\n"}, "seed readme")
            os.chmod(root / "README.md", 0o755)
            self.git(root, "add", "README.md")
            self.git(root, "-c", "user.name=Release Test", "-c", "user.email=release@example.invalid", "commit", "-m", "chmod")
            head = self.git(root, "rev-parse", "HEAD")
            verdict = RC.classify_transition(root, base, head, first_parent=True)
            self.assertEqual(verdict["class"], "no-artifact")

    def test_rename_decomposes_and_denies_only_across_the_allowlist_boundary(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, _ = self.repo(temporary)
            base = self.paths_commit(root, {"docs/old.md": "content\n"}, "seed")
            self.git(root, "mv", "docs/old.md", "docs/new.md")
            self.git(root, "-c", "user.name=Release Test", "-c", "user.email=release@example.invalid", "commit", "-m", "inside rename")
            inside = self.git(root, "rev-parse", "HEAD")
            verdict = RC.classify_transition(root, base, inside, first_parent=True)
            self.assertEqual(verdict["class"], "no-artifact")

            self.git(root, "mv", "docs/new.md", "escaped.txt")
            self.git(root, "-c", "user.name=Release Test", "-c", "user.email=release@example.invalid", "commit", "-m", "crossing rename")
            crossing = self.git(root, "rev-parse", "HEAD")
            with self.assertRaises(RC.ContractError) as denied:
                RC.classify_transition(root, inside, crossing, first_parent=True)
            self.assertIn("escaped.txt", str(denied.exception))

    def test_tree_identical_range_classifies_no_artifact(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, base = self.repo(temporary)
            self.git(root, "-c", "user.name=Release Test", "-c", "user.email=release@example.invalid", "commit", "--allow-empty", "-m", "no-op")
            head = self.git(root, "rev-parse", "HEAD")
            verdict = RC.classify_transition(root, base, head, first_parent=True)
            self.assertEqual(verdict["class"], "no-artifact")

    def test_two_parent_commit_denies_in_both_classes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, base = self.repo(temporary)
            self.git(root, "checkout", "-q", "-b", "topic", base)
            self.paths_commit(root, {"AGENTS.md": "topic docs\n"}, "topic docs")
            self.git(root, "checkout", "-q", "main")
            self.paths_commit(root, {"README.md": "main docs\n"}, "main docs")
            self.git(root, "-c", "user.name=Release Test", "-c", "user.email=release@example.invalid", "merge", "--no-ff", "topic", "-m", "merge")
            head = self.git(root, "rev-parse", "HEAD")
            with self.assertRaises(RC.ContractError):
                RC.classify_transition(root, base, head, first_parent=True)

    def test_cli_transition_emits_both_verdicts_and_denies_mixed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, base = self.repo(temporary)
            docs_head = self.paths_commit(root, {"AGENTS.md": "docs edit\n"}, "docs")
            stream = io.StringIO()
            with contextlib.redirect_stdout(stream):
                code = RC.main(["transition", "--repository", str(root), "--base", base, "--head", docs_head, "--first-parent"])
            self.assertEqual(code, 0)
            verdict = json.loads(stream.getvalue())
            self.assertEqual(verdict["class"], "no-artifact")
            self.assertEqual(verdict["source_sha"], docs_head)

            release_head = self.release_commit(root, "0.1.10")
            stream = io.StringIO()
            with contextlib.redirect_stdout(stream):
                code = RC.main(["transition", "--repository", str(root), "--base", docs_head, "--head", release_head, "--first-parent"])
            self.assertEqual(code, 0)
            verdict = json.loads(stream.getvalue())
            self.assertEqual(verdict["class"], "artifact")
            self.assertEqual(verdict["tag"], "v0.1.10")

            mixed_head = self.paths_commit(root, {"main.go": "package main\n"}, "code only")
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = RC.main(["transition", "--repository", str(root), "--base", release_head, "--head", mixed_head, "--first-parent"])
            self.assertEqual(code, 1)
            self.assertTrue(err.getvalue().startswith("DENY: "))

    def test_discovery_still_recovers_boundary_past_trailing_docs_merges(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, base = self.repo(temporary)
            release_head = self.release_commit(root, "0.1.10")
            docs_head = self.paths_commit(root, {"AGENTS.md": "post-release docs\n"}, "docs")
            window = RC.discover_transition_window(root, docs_head)
            self.assertEqual(window.intent.version, RC.Version.parse("0.1.10"))
            self.assertEqual(window.intent.source_sha, docs_head)
            cumulative = RC.classify_transition(root, release_head, docs_head, first_parent=True)
            self.assertEqual(cumulative["class"], "no-artifact")
            self.assertEqual(cumulative["tag"], "v0.1.10")


    def test_gitlink_entry_denies_even_under_an_allowlisted_path(self):
        # A submodule records mode 160000, outside the regular-file mode
        # set. The path MUST be allowlisted (docs/*.md) or this test is
        # decorative: with a non-allowlisted path the PATH guard denies and
        # the mode guard is never reached, so adding 160000 to
        # _DOCUMENTATION_DIFF_MODES would leave the suite green while a
        # gitlink at an allowlisted path classified no-artifact. That is
        # exactly the defect an adversarial review found in the first
        # version of this test.
        with tempfile.TemporaryDirectory() as temporary:
            root, base = self.repo(temporary)
            pointer = self.git(root, "rev-parse", "HEAD")
            self.git(root, "update-index", "--add", "--cacheinfo", f"160000,{pointer},docs/vendored.md")
            self.git(root, "-c", "user.name=Release Test", "-c", "user.email=release@example.invalid", "commit", "-m", "gitlink")
            head = self.git(root, "rev-parse", "HEAD")
            with self.assertRaises(RC.ContractError) as denied:
                RC.classify_transition(root, base, head, first_parent=True)
            self.assertIn("docs/vendored.md", str(denied.exception))

    def test_malformed_diff_entry_denies_instead_of_being_skipped(self):
        # The raw-diff parser is the one place a hostile or novel git output
        # could silently drop an entry, so its guard must deny rather than
        # ignore. Drive it directly: a real repository cannot easily emit a
        # malformed entry, and a guard nothing can reach is not a guard.
        # _diff_entries shells out with subprocess.run itself rather than
        # through the _git helper, so THAT is the seam to stub - patching
        # _git would silently do nothing and the test would pass vacuously.
        with tempfile.TemporaryDirectory() as temporary:
            root, base = self.repo(temporary)
            head = self.paths_commit(root, {"AGENTS.md": "agents\n"}, "docs")
            self.assertEqual(RC.classify_transition(root, base, head, first_parent=True)["class"], "no-artifact")
            original = RC.subprocess.run
            for corrupt, reason in (
                (":100644 100644 aaaaaaa bbbbbbb\x00AGENTS.md\x00", "status field missing"),
                (":100644 100644 aaaaaaa bbbbbbb Z\x00AGENTS.md\x00", "unknown status letter"),
                (":100644 100644 zzzzzzz bbbbbbb M\x00AGENTS.md\x00", "non-hex blob id"),
                (":100644 100644 aaaaaaa bbbbbbb M\x00\x00", "empty path"),
                (":100644 M\x00AGENTS.md\x00", "truncated meta"),
            ):
                with self.subTest(reason=reason):
                    def fake(command, *args, _corrupt=corrupt, **kwargs):
                        if "diff" in command:
                            return subprocess.CompletedProcess(command, 0, stdout=_corrupt.encode("utf-8"), stderr=b"")
                        return original(command, *args, **kwargs)

                    RC.subprocess.run = fake
                    try:
                        with self.assertRaises(RC.ContractError) as denied:
                            RC.classify_transition(root, base, head, first_parent=True)
                    finally:
                        RC.subprocess.run = original
                    self.assertIn("malformed", str(denied.exception))
            RC.subprocess.run = lambda command, *args, **kwargs: (
                subprocess.CompletedProcess(command, 0, stdout=b":100644\x00", stderr=b"")
                if "diff" in command
                else original(command, *args, **kwargs)
            )
            try:
                with self.assertRaises(RC.ContractError) as unpaired:
                    RC.classify_transition(root, base, head, first_parent=True)
            finally:
                RC.subprocess.run = original
            self.assertIn("not meta/path paired", str(unpaired.exception))
            # The stub is fully reverted: the same range classifies again.
            self.assertEqual(RC.classify_transition(root, base, head, first_parent=True)["class"], "no-artifact")

    def test_head_snapshot_is_revalidated_even_when_the_range_touches_no_lock(self):
        # Unchanged locks across the range do NOT imply a coherent release
        # snapshot: the range can START from an incoherent one. The head
        # validate_snapshot call is what catches that, and without it this
        # range would report a no-artifact verdict carrying a tag that
        # contradicts the chart.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.git(root, "init", "-q")
            self.git(root, "branch", "-m", "main")
            skewed = snapshot("0.1.9")
            skewed["chart/Chart.yaml"] = 'apiVersion: v2\nversion: 0.1.8\nappVersion: "0.1.8"\n'
            base = self.paths_commit(root, skewed, "skewed base")
            head = self.paths_commit(root, {"AGENTS.md": "agents\n"}, "docs only")
            for lock in RC.RELEASE_LOCK_PATHS:
                self.assertEqual(
                    self.git(root, "show", f"{base}:{lock}"),
                    self.git(root, "show", f"{head}:{lock}"),
                    lock,
                )
            with self.assertRaises(RC.ContractError) as denied:
                RC.classify_transition(root, base, head, first_parent=True)
            self.assertIn("chart version does not equal VERSION", str(denied.exception))


class NoArtifactClassifyShellPathTests(unittest.TestCase):
    """Executed coverage for the release-after-main classify step's shell.

    ``NoArtifactWiringTests`` only pins substrings of this step's source; it
    never runs a line of the bash that decides whether a release happens.
    This class extracts the real step body from the real workflow file and
    runs it under real bash, real git (against a synthetic repository this
    class builds), real jq, real unzip, and the real
    ``release_contract.py`` copied verbatim into that repository --
    following the ``ExistingImageShellPathTests`` house style. Only ``gh``,
    ``curl``, ``python3``, and ``sleep`` are stubbed: ``gh`` and ``curl``
    because they are the real network calls the step makes, ``sleep`` so
    the ref probe's bounded back-off costs the suite no real time, and
    ``python3`` only to redirect to this interpreter (it still runs the
    genuine ``release_contract.py``).

    This repository re-proves the no-artifact gap against ONE OF TWO
    anchors, so both are driven from here. Anchor A is a TAG OBJECT the
    step probes for (``GET .../git/ref/tags/{tag}`` then
    ``GET .../git/tags/{sha}``); anchor B, reached only once that tag is
    DEFINITIVELY absent, is the newest earlier successful protected-main
    gate run read from the Actions record -- the anchor naranjo.online's
    sibling class uses alone, because its publisher tags too late for that
    job to poll. The ``curl`` stub below therefore serves three distinct
    endpoints -- the verdict-artifact zip, the tag-ref probe, and the tag
    object resolve -- while the ``gh`` stub additionally serves the
    gated-run listing. A small on-disk script/counter file drives the ref
    probe through a scripted sequence of HTTP statuses per call, so one
    fixture can express "403, then 503, then 200" without bash re-entering
    the test process per attempt.
    """

    STEP = "Classify the completed range from its authorized gate verdict"

    _PRELUDE = r'''
set -x

python3() {
  "${TEST_PYTHON}" "$@"
}

sleep() {
  :
}

gh() {
  local all="$*"
  case "${all}" in
    *"/artifacts?"*) cat "${ARTIFACTS_JSON}" ;;
    *"/runs?branch=main"*)
      printf 'runs\n' >> "${CALL_LOG}"
      cat "${RUNS_JSON}"
      ;;
    *) return 2 ;;
  esac
}

curl() {
  local output='' url="${!#}"
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --output) output="$2"; shift 2 ;;
      *) shift ;;
    esac
  done
  case "${url}" in
    *"/artifacts/"*"/zip")
      cp "${VERDICT_ZIP}" "${output}"
      ;;
    *"/git/ref/tags/"*)
      "${TEST_PYTHON}" "${STUB_HELPER}" ref "${output}"
      ;;
    *"/git/tags/"*)
      "${TEST_PYTHON}" "${STUB_HELPER}" tag "${output}"
      ;;
    *)
      return 2
      ;;
  esac
}
'''

    # ``TAG_PROBE_JSON`` describes a scripted sequence of ref-probe
    # responses (consumed one per call, clamped to the last entry if the
    # step calls more times than scripted) plus a single tag-object
    # response. ``REF_COUNTER`` and ``CALL_LOG`` are plain files because
    # each invocation of this helper is a fresh process -- there is no
    # in-memory state to carry the call index between attempts.
    _STUB_HELPER_SOURCE = '''\
import json
import os
import sys

kind = sys.argv[1]
output_path = sys.argv[2]
script = json.load(open(os.environ["TAG_PROBE_JSON"], encoding="utf-8"))
log_path = os.environ["CALL_LOG"]

if kind == "ref":
    counter_path = os.environ["REF_COUNTER"]
    try:
        index = int(open(counter_path, encoding="utf-8").read().strip())
    except FileNotFoundError:
        index = 0
    entries = script["ref"]
    entry = entries[min(index, len(entries) - 1)]
    with open(counter_path, "w", encoding="utf-8") as counter:
        counter.write(str(index + 1))
elif kind == "tag":
    entry = script["tag"]
else:
    raise SystemExit("unknown probe kind: " + kind)

with open(log_path, "a", encoding="utf-8") as log:
    log.write(kind + " " + str(entry["status"]) + "\\n")
with open(output_path, "w", encoding="utf-8") as body:
    json.dump(entry.get("body", {}), body)
sys.stdout.write(str(entry["status"]))
'''

    # --- synthetic repository helpers, mirroring NoArtifactClassTests -----

    def git(self, root: Path, *args: str) -> str:
        return subprocess.run(
            ["git", "-C", str(root), *args], check=True, text=True, stdout=subprocess.PIPE
        ).stdout.strip()

    def release_commit(self, root: Path, version: str) -> str:
        files = snapshot(version)
        for name, contents in files.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(contents, encoding="utf-8")
        self.git(root, "add", ".")
        self.git(
            root, "-c", "user.name=Release Test", "-c", "user.email=release@example.invalid",
            "commit", "-m", version,
        )
        return self.git(root, "rev-parse", "HEAD")

    def paths_commit(self, root: Path, files: dict[str, str | None], marker: str) -> str:
        for name, contents in files.items():
            path = root / name
            if contents is None:
                path.unlink()
                self.git(root, "rm", "-q", "--cached", name)
                continue
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(contents, encoding="utf-8")
            self.git(root, "add", name)
        self.git(
            root, "-c", "user.name=Release Test", "-c", "user.email=release@example.invalid",
            "commit", "-m", marker,
        )
        return self.git(root, "rev-parse", "HEAD")

    def repo(self, temporary: str) -> tuple[Path, str]:
        root = Path(temporary)
        self.git(root, "init", "-q")
        self.git(root, "branch", "-m", "main")
        return root, self.release_commit(root, "0.1.9")

    def _seed_documentation_push(self, temporary: str) -> tuple[Path, str, str, str]:
        """Build base(0.1.9) -> release_head(0.1.10) -> docs_head.

        ``release_head`` doubles as this push's true retained-release
        boundary AND the commit the (fictional) v0.1.10 tag would point to
        once the tag probe reports it.
        """
        root, base = self.repo(temporary)
        release_head = self.release_commit(root, "0.1.10")
        docs_head = self.paths_commit(root, {"AGENTS.md": "post-release docs\n"}, "docs")
        return root, base, release_head, docs_head

    @staticmethod
    def _gated_runs(*head_shas: str, current: int = 1000) -> dict[str, object]:
        """An Actions run listing, NEWEST FIRST.

        ``head_shas[0]`` receives the highest id, so it is the run
        ``max_by(.id)`` must select. Every entry is a successful
        protected-main push run below ``MAIN_RUN_ID``, so the filter
        admits them all and only the ORDERING distinguishes the correct
        anchor from the wrong one.
        """
        return {
            "workflow_runs": [
                {
                    "id": current - 1 - index,
                    "head_branch": "main",
                    "event": "push",
                    "conclusion": "success",
                    "head_sha": sha,
                }
                for index, sha in enumerate(head_shas)
            ]
        }

    @staticmethod
    def _install_release_contract(root: Path) -> None:
        destination = root / "scripts" / "ci"
        destination.mkdir(parents=True, exist_ok=True)
        shutil.copy(HERE / "release_contract.py", destination / "release_contract.py")

    # --- workflow step extraction -------------------------------------------

    @staticmethod
    def workflow_run_block(step_name: str) -> str:
        """Extract one step's ``run: |`` body from release-after-main.yml.

        ``ExistingImageShellPathTests.workflow_run_block`` is hardcoded to
        release-publisher.yml, so this repeats its exact dedent logic
        against the orchestrator workflow instead. A renamed or removed
        step raises AssertionError rather than testing an empty block.
        """
        lines = (ROOT / ".github" / "workflows" / "release-after-main.yml").read_text(
            encoding="utf-8"
        ).splitlines()
        marker = f"      - name: {step_name}"
        try:
            start = lines.index(marker)
            run = lines.index("        run: |", start)
        except ValueError as exc:
            raise AssertionError(f"workflow step is missing: {step_name}") from exc
        body: list[str] = []
        for line in lines[run + 1 :]:
            if line.startswith("      - name:"):
                break
            if line.startswith("          "):
                body.append(line[10:])
            elif not line:
                body.append("")
            else:
                break
        if not body:
            raise AssertionError(f"workflow step has no executable run block: {step_name}")
        return "\n".join(body) + "\n"

    # --- execution -----------------------------------------------------------

    def execute(
        self,
        block: str,
        *,
        root: Path,
        completed_sha: str,
        main_run_id: str = "1000",
        artifacts_pages: list[dict[str, object]] | None = None,
        verdict: dict[str, object] | None = None,
        zip_entries: dict[str, bytes] | None = None,
        ref_script: list[dict[str, object]] | None = None,
        tag_script: dict[str, object] | None = None,
        runs: dict[str, object] | None = None,
        timeout: float = 30.0,
    ) -> tuple[subprocess.CompletedProcess[str], str, str, list[str]]:
        for tool in ("git", "jq", "unzip", "find", "seq"):
            if shutil.which(tool) is None:
                raise AssertionError(
                    f"required tool is not installed on this machine: {tool} "
                    "-- refusing to skip silently"
                )
        if artifacts_pages is None:
            artifacts_pages = [
                {"artifacts": [{"id": 1, "name": "transition-verdict", "expired": False}]}
            ]
        if zip_entries is None:
            payload = json.dumps(verdict if verdict is not None else {}).encode("utf-8")
            zip_entries = {"transition-verdict.json": payload}
        if ref_script is None:
            # A deliberately unhandled HTTP status: if a test that does not
            # expect the tag probe to be reached reaches it anyway, this
            # denies loudly (the case statement's hard-fail arm) instead of
            # silently succeeding or looping for 90 attempts.
            ref_script = [{"status": 599}]
        if tag_script is None:
            tag_script = {"status": 599}
        if runs is None:
            # Fail-closed default, mirroring the 599 ref default: a test that
            # reaches the gated-run anchor without declaring a fixture finds
            # NO earlier gated main run, so the jq expression errors and the
            # step denies loudly instead of quietly borrowing some other
            # test's anchor.
            runs = {"workflow_runs": []}

        with tempfile.TemporaryDirectory() as scratch:
            runner = Path(scratch)
            artifacts_json = runner / "artifacts-listing.json"
            artifacts_json.write_text(json.dumps(artifacts_pages), encoding="utf-8")
            verdict_zip = runner / "verdict.zip"
            with zipfile.ZipFile(verdict_zip, "w") as archive:
                for name, data in zip_entries.items():
                    archive.writestr(name, data)
            event_path = runner / "event.json"
            event_path.write_text(json.dumps(event(completed_sha)), encoding="utf-8")
            output_path = runner / "github-output.txt"
            output_path.write_text("", encoding="utf-8")
            summary_path = runner / "github-summary.md"
            summary_path.write_text("", encoding="utf-8")
            runner_temp = runner / "runner-temp"
            runner_temp.mkdir()

            runs_json = runner / "previous-main-runs.json"
            runs_json.write_text(json.dumps(runs), encoding="utf-8")
            tag_probe_json = runner / "tag-probe.json"
            tag_probe_json.write_text(
                json.dumps({"ref": ref_script, "tag": tag_script}), encoding="utf-8"
            )
            call_log = runner / "call-log.txt"
            call_log.write_text("", encoding="utf-8")
            ref_counter = runner / "ref-counter.txt"
            stub_helper = runner / "stub_helper.py"
            stub_helper.write_text(self._STUB_HELPER_SOURCE, encoding="utf-8")

            environment = os.environ.copy()
            environment.update(
                {
                    "TEST_PYTHON": ExistingImageShellPathTests.bash_path(sys.executable),
                    "GH_TOKEN": "fixture-token",
                    "COMPLETED_SHA": completed_sha,
                    "MAIN_RUN_ID": main_run_id,
                    "RUNNER_TEMP": str(runner_temp),
                    "GITHUB_OUTPUT": str(output_path),
                    "GITHUB_STEP_SUMMARY": str(summary_path),
                    "GITHUB_REPOSITORY": "owner/site",
                    "GITHUB_API_URL": "https://api.github.example.invalid",
                    "GITHUB_EVENT_PATH": str(event_path),
                    "ARTIFACTS_JSON": str(artifacts_json),
                    "RUNS_JSON": str(runs_json),
                    "VERDICT_ZIP": str(verdict_zip),
                    "TAG_PROBE_JSON": str(tag_probe_json),
                    "CALL_LOG": str(call_log),
                    "REF_COUNTER": str(ref_counter),
                    "STUB_HELPER": str(stub_helper),
                }
            )
            completed = subprocess.run(
                [ExistingImageShellPathTests.bash_executable()],
                cwd=root,
                env=environment,
                check=False,
                input=self._PRELUDE + "\n" + block,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                timeout=timeout,
            )
            calls = [line for line in call_log.read_text(encoding="utf-8").splitlines() if line]
            return (
                completed,
                output_path.read_text(encoding="utf-8"),
                summary_path.read_text(encoding="utf-8"),
                calls,
            )

    # --- scenario 1: documentation-only merge, both-direction happy path ---

    def test_documentation_only_merge_writes_no_artifact_class_and_summary(self):
        block = self.workflow_run_block(self.STEP)
        with tempfile.TemporaryDirectory() as temporary:
            root, base, release_head, docs_head = self._seed_documentation_push(temporary)
            self._install_release_contract(root)
            verdict = {"class": "no-artifact", "base_sha": release_head, "source_sha": docs_head}
            tag_object_sha = "a" * 40
            ref_script = [
                {
                    "status": 200,
                    "body": {
                        "ref": "refs/tags/v0.1.10",
                        "object": {"type": "tag", "sha": tag_object_sha},
                    },
                }
            ]
            tag_script = {"status": 200, "body": {"object": {"type": "commit", "sha": release_head}}}
            completed, output, summary, calls = self.execute(
                block,
                root=root,
                completed_sha=docs_head,
                verdict=verdict,
                ref_script=ref_script,
                tag_script=tag_script,
            )
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertIn("class=no-artifact\n", output)
            self.assertIn("NO-ARTIFACT:", completed.stdout)
            self.assertIn("No-artifact merge", summary)
            self.assertEqual(calls, ["ref 200", "tag 200"])

    # --- scenario 2: artifact merge, the other happy-path direction --------

    def test_artifact_merge_writes_artifact_class(self):
        block = self.workflow_run_block(self.STEP)
        with tempfile.TemporaryDirectory() as temporary:
            root, base = self.repo(temporary)
            self._install_release_contract(root)
            bump_head = self.release_commit(root, "0.1.10")
            verdict = {"class": "artifact", "base_sha": base, "source_sha": bump_head}
            completed, output, summary, calls = self.execute(
                block, root=root, completed_sha=bump_head, verdict=verdict
            )
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertIn("class=artifact\n", output)
            self.assertNotIn("NO-ARTIFACT:", completed.stdout)
            self.assertEqual(summary, "")
            # The artifact branch of the case statement is a no-op: the tag
            # probe must never fire for a genuine artifact merge.
            self.assertEqual(calls, [])

    # --- scenario 3: THE LOAD-BEARING PROOF -- a forged base inside the push

    def test_forged_base_inside_the_push_is_caught_by_the_tag_anchor(self):
        """A verdict naming base_sha AFTER the version bump must still deny.

        Push = [commit that bumps VERSION and touches code] then
        [docs-only commit]. The true class over the whole push is
        artifact. A forged (or buggy) verdict claims base_sha = the BUMP
        commit itself and class = no-artifact: re-deriving over
        [bump..docs] genuinely reports no-artifact, because the docs
        commit alone changes nothing -- that FIRST re-derivation is
        parameterised by claimed_base and is therefore NOT independent of
        the verdict, exactly as in naranjo.online's sibling attack.

        Anchor A (the retained tag) is computed from HEAD's tree alone, so
        the forgery cannot change WHICH tag is demanded: that tree reads
        0.1.10, the version THIS VERY PUSH was supposed to release, so
        v0.1.10 cannot already exist and anchor A is unavailable.

        Anchor A being unavailable is therefore the attack's own
        signature, which is exactly why the fallback may not be a bypass.
        This test proves it is not: with an all-404 tag fixture the step
        falls through to anchor B -- the last gated main head, straight
        from the Actions record, which the verdict also cannot choose --
        and the four-lock equality DENIES, because the disguised artifact
        merge carries its version bump and that head still reads 0.1.9.

        The attack is caught on BOTH paths, by two independent anchors.
        """
        block = self.workflow_run_block(self.STEP)
        with tempfile.TemporaryDirectory() as temporary:
            root, base = self.repo(temporary)
            self._install_release_contract(root)
            bump = self.paths_commit(
                root,
                {**snapshot("0.1.10"), "cmd/server/extra.go": "package server\n"},
                "bump with trailing code",
            )
            docs_head = self.paths_commit(root, {"AGENTS.md": "docs\n"}, "docs")
            verdict = {"class": "no-artifact", "base_sha": bump, "source_sha": docs_head}
            completed, output, _summary, calls = self.execute(
                block,
                root=root,
                completed_sha=docs_head,
                verdict=verdict,
                ref_script=[{"status": 404}],
                runs=self._gated_runs(base),
            )
            self.assertNotEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertIn(
                f"DENY: VERSION changed since the last gated main head {base}",
                completed.stderr,
            )
            self.assertNotIn("class=", output)
            # The tag probe answered definitively on its FIRST call and the
            # step went straight to anchor B: no 90-attempt wait survives.
            self.assertEqual(calls, ["ref 404", "runs"])

    # --- scenario 4: THE OWNER-REQUIRED PATH -- absent tag must not block --

    def test_absent_retained_tag_falls_back_to_the_gated_run_anchor(self):
        """An honest documentation merge is NOT blocked by a missing tag.

        This repository's release job denies on duplicated exact-SHA
        CodeQL runs when GitHub double-delivers the merge-push event
        (issue #81), which left six of the twelve main commits before this
        change with no tag at all. Anchoring solely on the tag therefore
        made the documentation fast path dead whenever an UNRELATED
        release had flaked, and that stickiness is the friction this class
        exists to remove.

        Here the retained tag is absent, anchor B supplies the proof
        instead, and the merge classifies no-artifact and succeeds.
        """
        block = self.workflow_run_block(self.STEP)
        with tempfile.TemporaryDirectory() as temporary:
            root, base, release_head, docs_head = self._seed_documentation_push(temporary)
            self._install_release_contract(root)
            verdict = {"class": "no-artifact", "base_sha": release_head, "source_sha": docs_head}
            completed, output, summary, calls = self.execute(
                block,
                root=root,
                completed_sha=docs_head,
                verdict=verdict,
                ref_script=[{"status": 404}],
                runs=self._gated_runs(release_head),
            )
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertIn("class=no-artifact\n", output)
            self.assertIn("No-artifact merge", summary)
            self.assertIn("last gated main head", completed.stdout)
            self.assertEqual(calls, ["ref 404", "runs"])

    def test_absent_tag_and_no_earlier_gated_run_denies(self):
        """BOTH anchors unavailable is the only case that still denies."""
        block = self.workflow_run_block(self.STEP)
        with tempfile.TemporaryDirectory() as temporary:
            root, base, release_head, docs_head = self._seed_documentation_push(temporary)
            self._install_release_contract(root)
            verdict = {"class": "no-artifact", "base_sha": release_head, "source_sha": docs_head}
            completed, output, _summary, calls = self.execute(
                block,
                root=root,
                completed_sha=docs_head,
                verdict=verdict,
                ref_script=[{"status": 404}],
                runs={"workflow_runs": []},
            )
            self.assertNotEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertIn(
                "neither the retained tag nor an earlier gated main run is available",
                completed.stderr,
            )
            self.assertNotIn("class=", output)
            self.assertEqual(calls, ["ref 404", "runs"])

    def test_lock_free_artifact_commit_denies_on_the_gated_run_anchor(self):
        """The four-lock check cannot see a code-only change; the
        cumulative re-classification must.

        A commit touching only ``cmd/server`` moves no VERSION, chart or
        changelog byte, so the four-lock equality passes it. Anchor B is
        only sound because the cumulative proof runs over the same range
        and sees the non-allowlisted path.

        Scope, stated honestly: this test kills the CUMULATIVE check only.
        Deleting the four-lock loop leaves it green -- the cumulative
        re-classification catches a code-only commit unaided -- and an
        earlier version of this docstring wrongly claimed otherwise. The
        four-lock loop is killed by
        ``test_forged_base_inside_the_push_is_caught_by_the_tag_anchor``,
        where the disguised merge moves VERSION and only that loop sees it.
        """
        block = self.workflow_run_block(self.STEP)
        with tempfile.TemporaryDirectory() as temporary:
            root, base, release_head, docs_head = self._seed_documentation_push(temporary)
            self._install_release_contract(root)
            code_head = self.paths_commit(
                root, {"cmd/server/extra.go": "package server\n"}, "lock-free code change"
            )
            final_head = self.paths_commit(root, {"AGENTS.md": "more docs\n"}, "docs again")
            verdict = {"class": "no-artifact", "base_sha": code_head, "source_sha": final_head}
            completed, output, _summary, _calls = self.execute(
                block,
                root=root,
                completed_sha=final_head,
                verdict=verdict,
                ref_script=[{"status": 404}],
                runs=self._gated_runs(docs_head),
            )
            self.assertNotEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertNotIn("class=", output)

    def test_transient_exhaustion_denies_instead_of_reaching_the_gated_run_anchor(self):
        """Anchor A UNKNOWN is not anchor A ABSENT.

        A persistent 403 -- the commonest shape of a GITHUB_TOKEN
        permission regression -- exhausts the retry budget without ever
        learning whether the tag exists. Falling through to anchor B then
        both breaks the stated "deny when BOTH anchors are unavailable"
        invariant and prints "the tag is absent", which the step never
        established. A perfectly usable anchor B is supplied here on
        purpose: the step must deny ANYWAY, and must never call the runs
        endpoint.
        """
        block = self.workflow_run_block(self.STEP)
        with tempfile.TemporaryDirectory() as temporary:
            root, base, release_head, docs_head = self._seed_documentation_push(temporary)
            self._install_release_contract(root)
            verdict = {"class": "no-artifact", "base_sha": release_head, "source_sha": docs_head}
            completed, output, _summary, calls = self.execute(
                block,
                root=root,
                completed_sha=docs_head,
                verdict=verdict,
                # Clamped: the stub serves this entry for every attempt.
                ref_script=[{"status": 403}],
                runs=self._gated_runs(release_head),
            )
            self.assertNotEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertIn("never returned a definitive answer", completed.stderr)
            self.assertNotIn("is absent", completed.stderr)
            self.assertNotIn("class=", output)
            self.assertNotIn("runs", calls, "must never reach anchor B on an unknown outcome")

    # --- anchor B's run FILTER: the fixture helper cannot express a
    # non-conforming run, so these tests pass raw listings instead. Without
    # them, dropping the jq branch/event/conclusion predicates leaves the
    # whole suite green -- and an anchor taken from a FAILED gate run is the
    # one route to a silently skipped release, because a main tip that was
    # never proven docs-only would sit before the anchor and escape the
    # cumulative proof entirely.

    def _assert_nonconforming_run_is_not_anchored(self, run: dict[str, object]) -> None:
        block = self.workflow_run_block(self.STEP)
        with tempfile.TemporaryDirectory() as temporary:
            root, base, release_head, docs_head = self._seed_documentation_push(temporary)
            self._install_release_contract(root)
            verdict = {"class": "no-artifact", "base_sha": release_head, "source_sha": docs_head}
            entry = {
                "id": 999,
                "head_branch": "main",
                "event": "push",
                "conclusion": "success",
                "head_sha": release_head,
            }
            entry.update(run)
            completed, output, _summary, _calls = self.execute(
                block,
                root=root,
                completed_sha=docs_head,
                verdict=verdict,
                ref_script=[{"status": 404}],
                # The ONLY run on offer violates one predicate, so a correct
                # filter finds nothing and the jq error denies.
                runs={"workflow_runs": [entry]},
            )
            self.assertNotEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertIn(
                "neither the retained tag nor an earlier gated main run is available",
                completed.stderr,
            )
            self.assertNotIn("class=", output)

    def test_a_failed_gate_run_is_never_anchored(self):
        self._assert_nonconforming_run_is_not_anchored({"conclusion": "failure"})

    def test_a_cancelled_gate_run_is_never_anchored(self):
        self._assert_nonconforming_run_is_not_anchored({"conclusion": "cancelled"})

    def test_a_non_main_branch_run_is_never_anchored(self):
        self._assert_nonconforming_run_is_not_anchored({"head_branch": "opus5/topic"})

    def test_a_pull_request_run_is_never_anchored(self):
        self._assert_nonconforming_run_is_not_anchored({"event": "pull_request"})

    def test_a_run_at_or_above_the_current_run_is_never_anchored(self):
        # MAIN_RUN_ID defaults to 1000; `.id < $current` must exclude these.
        self._assert_nonconforming_run_is_not_anchored({"id": 1000})
        self._assert_nonconforming_run_is_not_anchored({"id": 1001})

    def test_gated_run_anchor_equal_to_the_completed_sha_denies(self):
        """A run record naming this very push as its own anchor is refused.

        Asserts the guard's OWN message. Previously this asserted only a
        non-zero exit, so deleting the refusal left it green -- the denial
        merely relocated to the cumulative call raising on an empty range,
        which is indistinguishable from the outside. Same decorative class
        as the original gitlink test.
        """
        block = self.workflow_run_block(self.STEP)
        with tempfile.TemporaryDirectory() as temporary:
            root, base, release_head, docs_head = self._seed_documentation_push(temporary)
            self._install_release_contract(root)
            verdict = {"class": "no-artifact", "base_sha": release_head, "source_sha": docs_head}
            completed, output, _summary, _calls = self.execute(
                block,
                root=root,
                completed_sha=docs_head,
                verdict=verdict,
                ref_script=[{"status": 404}],
                runs=self._gated_runs(docs_head),
            )
            self.assertNotEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertIn("it cannot anchor itself", completed.stderr)
            self.assertNotIn("class=", output)

    def test_a_gated_run_head_off_the_mainline_denies_on_ancestry(self):
        """The anchor must be an ancestor of the merged head.

        Builds a genuinely divergent commit so the ancestry refusal is
        reached on its own terms, and asserts ITS message rather than a
        bare non-zero exit.
        """
        block = self.workflow_run_block(self.STEP)
        with tempfile.TemporaryDirectory() as temporary:
            root, base, release_head, docs_head = self._seed_documentation_push(temporary)
            self._install_release_contract(root)
            # A sibling commit off `base`, never merged into docs_head.
            self.git(root, "checkout", "-q", "-b", "sidebranch", base)
            divergent = self.paths_commit(root, {"AGENTS.md": "side\n"}, "divergent")
            self.git(root, "checkout", "-q", "main")
            verdict = {"class": "no-artifact", "base_sha": release_head, "source_sha": docs_head}
            completed, output, _summary, _calls = self.execute(
                block,
                root=root,
                completed_sha=docs_head,
                verdict=verdict,
                ref_script=[{"status": 404}],
                runs=self._gated_runs(divergent),
            )
            self.assertNotEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertIn("is not an ancestor of", completed.stderr)
            self.assertNotIn("class=", output)

    def test_gated_run_anchor_uses_the_newest_earlier_run_not_the_oldest(self):
        """``max_by`` versus ``min_by`` is only visible on a SUCCESS case.

        Both orderings deny every attack, so an attack fixture cannot tell
        them apart. Two earlier gated runs are supplied; selecting the
        OLDER one spans the artifact release and false-denies a legitimate
        documentation merge.
        """
        block = self.workflow_run_block(self.STEP)
        with tempfile.TemporaryDirectory() as temporary:
            root, base, release_head, docs_head = self._seed_documentation_push(temporary)
            self._install_release_contract(root)
            verdict = {"class": "no-artifact", "base_sha": release_head, "source_sha": docs_head}
            completed, output, _summary, _calls = self.execute(
                block,
                root=root,
                completed_sha=docs_head,
                verdict=verdict,
                ref_script=[{"status": 404}],
                # Newest first: release_head is the correct anchor, base
                # (0.1.9) would span the 0.1.10 release and false-deny.
                runs=self._gated_runs(release_head, base),
            )
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertIn("class=no-artifact\n", output)

    # --- scenario 5: a definitive 404 must not be polled -------------------

    def test_a_404_is_definitive_and_is_never_polled(self):
        """The old 90x10s poll is gone; a missing tag answers immediately.

        Waiting fifteen minutes for a tag that may never arrive bought no
        security once anchor B existed -- it only charged every
        documentation merge the wait. Exactly one ref call may happen.
        """
        block = self.workflow_run_block(self.STEP)
        with tempfile.TemporaryDirectory() as temporary:
            root, base, release_head, docs_head = self._seed_documentation_push(temporary)
            self._install_release_contract(root)
            verdict = {"class": "no-artifact", "base_sha": release_head, "source_sha": docs_head}
            completed, _output, _summary, calls = self.execute(
                block,
                root=root,
                completed_sha=docs_head,
                verdict=verdict,
                # Clamped: if a mutation turned 404 back into a retry, the
                # stub would serve this entry forever and `calls` would grow.
                ref_script=[{"status": 404}],
                runs=self._gated_runs(release_head),
            )
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertEqual(
                calls.count("ref 404"), 1, "a definitive 404 must not be retried"
            )

    # --- scenario 6: transient statuses are retried, never treated fatal ---

    def test_transient_statuses_are_retried_not_treated_as_fatal(self):
        block = self.workflow_run_block(self.STEP)
        with tempfile.TemporaryDirectory() as temporary:
            root, base, release_head, docs_head = self._seed_documentation_push(temporary)
            self._install_release_contract(root)
            verdict = {"class": "no-artifact", "base_sha": release_head, "source_sha": docs_head}
            tag_object_sha = "c" * 40
            # Transient codes the retry arm names, then the success. The
            # budget is three attempts, so two transients fit before it.
            ref_script = [
                {"status": 403},
                {"status": 503},
                {
                    "status": 200,
                    "body": {
                        "ref": "refs/tags/v0.1.10",
                        "object": {"type": "tag", "sha": tag_object_sha},
                    },
                },
            ]
            tag_script = {"status": 200, "body": {"object": {"type": "commit", "sha": release_head}}}
            completed, output, _summary, calls = self.execute(
                block,
                root=root,
                completed_sha=docs_head,
                verdict=verdict,
                ref_script=ref_script,
                tag_script=tag_script,
            )
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertIn("class=no-artifact\n", output)
            # Two transient attempts, the terminal success, then the one
            # tag-object resolve — and NO fallback, because anchor A won.
            self.assertEqual(calls, ["ref 403", "ref 503", "ref 200", "tag 200"])

    # --- scenario 7: a hard status denies immediately, never retried -------

    def _assert_hard_status_denies_immediately(self, status: int) -> None:
        block = self.workflow_run_block(self.STEP)
        with tempfile.TemporaryDirectory() as temporary:
            root, base, release_head, docs_head = self._seed_documentation_push(temporary)
            self._install_release_contract(root)
            verdict = {"class": "no-artifact", "base_sha": release_head, "source_sha": docs_head}
            # A single scripted response. If a mutation loosened the
            # hard-status arm into a retry, the stub would clamp to this
            # same entry forever and `calls` would grow past one attempt.
            completed, output, _summary, calls = self.execute(
                block,
                root=root,
                completed_sha=docs_head,
                verdict=verdict,
                ref_script=[{"status": status}],
                # A perfectly usable fallback anchor is deliberately made
                # available: a hard status must deny ANYWAY. Routing a
                # broken credential around to anchor B would hide real
                # breakage behind the merge-friction fallback.
                runs=self._gated_runs(release_head),
            )
            self.assertNotEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertIn(f"DENY: retained-tag probe returned HTTP {status}", completed.stderr)
            self.assertNotIn("class=", output)
            self.assertEqual(
                calls,
                [f"ref {status}"],
                "a hard status must deny on the FIRST attempt and never reach anchor B",
            )

    def test_unauthorized_status_denies_immediately(self):
        self._assert_hard_status_denies_immediately(401)

    def test_unprocessable_status_denies_immediately(self):
        self._assert_hard_status_denies_immediately(422)

    # --- scenario 8: the tag-object response -- status first, then type ----

    def test_tag_object_http_status_other_than_200_denies(self):
        """Isolates ``test "${object_status}" = 200`` and nothing else.

        This fixture is scenario 1's happy path with exactly one field
        able to deny changed: the tag-object response carries HTTP 404
        instead of 200. It differs from scenario 1 in one other place,
        and that difference REMOVES a confound rather than adding one --
        the anchor-B run listing scenario 1 leaves empty is populated
        here, so a fall-through could no longer deny for want of a
        fallback (see the inline note at the fixture).

        Every other guard around the assertion is deliberately
        SATISFIED, so nothing else in the step can account for the
        denial --

        * the ref probe answers 200 with a well-formed annotated-tag ref,
          so ``tag-ref-object`` parses it and the branch is entered;
        * the tag-object BODY is the same valid ``{"type": "commit",
          "sha": <release_head>}`` scenario 1 succeeds on, so the type
          guard, the 40-hex shape check, the cumulative re-classification
          and the retained-tag equality would every one of them PASS were
          they reached.

        That is what separates this from a decorative test: deleting the
        assertion under test does not relocate the denial, it removes it
        -- the step then anchors on the body of a 404 and exits 0 with
        ``class=no-artifact``, which is precisely the fail-open the
        assertion exists to prevent.

        Two assertions pin the isolation from the inside. ``set -x``
        traces the command-substitution RESULT, so ``test 404 = 200`` is
        the assertion under test observing the real runtime status rather
        than any static program text; and the ABSENCE of
        ``test commit = commit`` proves execution stopped there rather
        than at the type guard one line below.
        """
        block = self.workflow_run_block(self.STEP)
        with tempfile.TemporaryDirectory() as temporary:
            root, base, release_head, docs_head = self._seed_documentation_push(temporary)
            self._install_release_contract(root)
            verdict = {"class": "no-artifact", "base_sha": release_head, "source_sha": docs_head}
            ref_script = [
                {
                    "status": 200,
                    "body": {
                        "ref": "refs/tags/v0.1.10",
                        "object": {"type": "tag", "sha": "a" * 40},
                    },
                }
            ]
            tag_script = {
                "status": 404,
                "body": {"object": {"type": "commit", "sha": release_head}},
            }
            completed, output, summary, calls = self.execute(
                block,
                root=root,
                completed_sha=docs_head,
                verdict=verdict,
                ref_script=ref_script,
                tag_script=tag_script,
                # A perfectly usable anchor B is deliberately on offer: an
                # unreadable tag OBJECT is not the definitively-absent TAG
                # the fallback exists for, so this must deny outright and
                # never reach the runs endpoint.
                runs=self._gated_runs(release_head),
            )
            self.assertNotEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertIn("test 404 = 200", completed.stderr)
            self.assertNotIn("test commit = commit", completed.stderr)
            self.assertNotIn("class=", output)
            self.assertEqual(summary, "")
            self.assertEqual(calls, ["ref 200", "tag 404"])

    def test_tag_object_resolving_to_a_non_commit_type_denies(self):
        block = self.workflow_run_block(self.STEP)
        with tempfile.TemporaryDirectory() as temporary:
            root, base, release_head, docs_head = self._seed_documentation_push(temporary)
            self._install_release_contract(root)
            verdict = {"class": "no-artifact", "base_sha": release_head, "source_sha": docs_head}
            tag_object_sha = "d" * 40
            ref_script = [
                {
                    "status": 200,
                    "body": {
                        "ref": "refs/tags/v0.1.10",
                        "object": {"type": "tag", "sha": tag_object_sha},
                    },
                }
            ]
            tag_script = {"status": 200, "body": {"object": {"type": "tree", "sha": "e" * 40}}}
            completed, output, _summary, calls = self.execute(
                block,
                root=root,
                completed_sha=docs_head,
                verdict=verdict,
                ref_script=ref_script,
                tag_script=tag_script,
            )
            self.assertNotEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            # `set -x` traces the command-substitution RESULT adjacent to
            # the literal right-hand operand, so only the actual runtime
            # value "tree" -- not the static jq program text, which is
            # traced on every invocation including the happy path -- proves
            # the object-type guard genuinely observed a non-commit type.
            self.assertIn("test tree = commit", completed.stderr)
            self.assertNotIn("class=", output)
            self.assertEqual(calls, ["ref 200", "tag 200"])

    # --- scenario 9: a real tag, but its gap to HEAD is not documentation --

    def test_tag_target_to_head_gap_containing_a_non_documentation_commit_denies(self):
        """The tag anchor finds a REAL tag -- unlike scenarios 3 and 4 --
        but the cumulative re-proof from that real tag to HEAD still
        catches a non-documentation commit the narrower
        claimed_base..HEAD slice hid.

        History: base (a real v0.1.9 release) -> code (touches a
        non-documentation file, no version bump) -> docs (documentation
        only) = HEAD. The verdict names claimed_base = code, so the FIRST
        re-derivation ([code..docs]) is genuinely no-artifact and agrees
        with the verdict -- the retained version at that tree is still
        0.1.9, because `code` never touched VERSION. The tag probe
        therefore demands v0.1.9, which DOES exist here and resolves to
        `base`. The cumulative re-proof runs over [base..docs] instead --
        the range the verdict's narrower claim hid -- which contains the
        non-documentation commit without an exact release patch, and
        `classify_transition` denies it as a mixed range.
        """
        block = self.workflow_run_block(self.STEP)
        with tempfile.TemporaryDirectory() as temporary:
            root, base = self.repo(temporary)
            self._install_release_contract(root)
            code = self.paths_commit(
                root, {"internal/server/extra.go": "package server\n"}, "code touch"
            )
            docs_head = self.paths_commit(root, {"AGENTS.md": "docs\n"}, "docs")
            verdict = {"class": "no-artifact", "base_sha": code, "source_sha": docs_head}
            tag_object_sha = "f" * 40
            ref_script = [
                {
                    "status": 200,
                    "body": {
                        "ref": "refs/tags/v0.1.9",
                        "object": {"type": "tag", "sha": tag_object_sha},
                    },
                }
            ]
            tag_script = {"status": 200, "body": {"object": {"type": "commit", "sha": base}}}
            completed, output, _summary, calls = self.execute(
                block,
                root=root,
                completed_sha=docs_head,
                verdict=verdict,
                ref_script=ref_script,
                tag_script=tag_script,
            )
            self.assertNotEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertIn("DENY: ", completed.stderr)
            self.assertIn("without one exact release patch", completed.stderr)
            self.assertIn("internal/server/extra.go", completed.stderr)
            self.assertNotIn("class=", output)
            self.assertEqual(calls, ["ref 200", "tag 200"])

    def test_cumulative_reclassifying_as_artifact_denies(self):
        """Isolates ``test $(jq ... cumulative.class) = no-artifact`` alone.

        Scenario 9's mixed-range gap fails inside the cumulative
        ``transition`` call itself (a ContractError from an unallowlisted
        path with no release patch), so it never reaches this later
        equality check. This scenario instead builds a tag_target..HEAD
        gap that is a perfectly CLEAN, valid one-patch release bump
        followed by docs -- something ``classify_transition`` genuinely
        classifies "artifact" rather than erroring on -- so only the
        explicit class-equality guard after the cumulative call can catch
        it. The tag probe is scripted (independent of git reality) to
        resolve the retained tag back to `base`, one commit further back
        than the verdict's own claimed_base, to open that gap.
        """
        block = self.workflow_run_block(self.STEP)
        with tempfile.TemporaryDirectory() as temporary:
            root, base = self.repo(temporary)
            self._install_release_contract(root)
            valid_bump = self.release_commit(root, "0.1.10")
            docs_head = self.paths_commit(root, {"AGENTS.md": "docs\n"}, "docs")
            verdict = {"class": "no-artifact", "base_sha": valid_bump, "source_sha": docs_head}
            tag_object_sha = "1" + "a" * 39
            ref_script = [
                {
                    "status": 200,
                    "body": {
                        "ref": "refs/tags/v0.1.10",
                        "object": {"type": "tag", "sha": tag_object_sha},
                    },
                }
            ]
            tag_script = {"status": 200, "body": {"object": {"type": "commit", "sha": base}}}
            completed, output, _summary, calls = self.execute(
                block,
                root=root,
                completed_sha=docs_head,
                verdict=verdict,
                ref_script=ref_script,
                tag_script=tag_script,
            )
            self.assertNotEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertIn("test artifact = no-artifact", completed.stderr)
            self.assertNotIn("class=", output)
            self.assertEqual(calls, ["ref 200", "tag 200"])

    # --- scenarios 10: the transition-verdict artifact listing -------------

    def _assert_artifact_listing_denies(self, *, artifacts: list[dict[str, object]]) -> None:
        block = self.workflow_run_block(self.STEP)
        with tempfile.TemporaryDirectory() as temporary:
            root, base, release_head, docs_head = self._seed_documentation_push(temporary)
            self._install_release_contract(root)
            completed, output, _summary, calls = self.execute(
                block,
                root=root,
                completed_sha=docs_head,
                artifacts_pages=[{"artifacts": artifacts}],
                verdict={"class": "no-artifact", "base_sha": release_head, "source_sha": docs_head},
            )
            self.assertNotEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            # `set -x` traces the jq PROGRAM TEXT (a static command-line
            # argument) on every invocation, so the literal else-branch
            # message string is visible in stderr even when jq never takes
            # that branch -- that text alone is not distinguishing. jq's
            # actual runtime error is prefixed "jq: error (at FILE:LINE): ",
            # with no surrounding quotes; matching "): " immediately before
            # the message is what proves the error() call actually fired.
            self.assertIn("): expected exactly one transition-verdict artifact", completed.stderr)
            self.assertNotIn("class=", output)
            self.assertEqual(calls, [], "must deny before the tag probe is ever reached")

    def test_missing_transition_verdict_artifact_denies(self):
        self._assert_artifact_listing_denies(artifacts=[])

    def test_duplicate_transition_verdict_artifacts_deny(self):
        self._assert_artifact_listing_denies(
            artifacts=[
                {"id": 1, "name": "transition-verdict", "expired": False},
                {"id": 2, "name": "transition-verdict", "expired": False},
            ]
        )

    def test_expired_only_transition_verdict_artifact_denies(self):
        self._assert_artifact_listing_denies(
            artifacts=[{"id": 1, "name": "transition-verdict", "expired": True}]
        )

    def test_valid_artifact_alongside_an_expired_duplicate_still_succeeds(self):
        # The three denial cases above prove the exactly-one LENGTH check.
        # None of them proves the `expired == false` FILTER does anything:
        # a jq selector that ignored `expired` entirely would still deny all
        # three. This is the positive case that separates them - two entries
        # named transition-verdict, one expired - and it must pass, choosing
        # the live one by id.
        block = self.workflow_run_block(self.STEP)
        with tempfile.TemporaryDirectory() as temporary:
            root, base, release_head, docs_head = self._seed_documentation_push(temporary)
            self._install_release_contract(root)
            verdict = {"class": "no-artifact", "base_sha": release_head, "source_sha": docs_head}
            tag_object_sha = "a" * 40
            ref_script = [
                {
                    "status": 200,
                    "body": {
                        "ref": "refs/tags/v0.1.10",
                        "object": {"type": "tag", "sha": tag_object_sha},
                    },
                }
            ]
            tag_script = {"status": 200, "body": {"object": {"type": "commit", "sha": release_head}}}
            completed, output, _summary, calls = self.execute(
                block,
                root=root,
                completed_sha=docs_head,
                verdict=verdict,
                ref_script=ref_script,
                tag_script=tag_script,
                artifacts_pages=[
                    {
                        "artifacts": [
                            {"id": 7, "name": "transition-verdict", "expired": True},
                            {"id": 1, "name": "transition-verdict", "expired": False},
                        ]
                    }
                ],
            )
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertIn("class=no-artifact\n", output)
            self.assertEqual(calls, ["ref 200", "tag 200"])

    # --- scenario 11: claimed_source/claimed_base malformed or wrong -------

    def test_claimed_source_mismatch_denies(self):
        block = self.workflow_run_block(self.STEP)
        with tempfile.TemporaryDirectory() as temporary:
            root, base, release_head, docs_head = self._seed_documentation_push(temporary)
            self._install_release_contract(root)
            wrong_source = "b" * 40
            verdict = {
                "class": "no-artifact", "base_sha": release_head, "source_sha": wrong_source,
            }
            completed, output, _summary, calls = self.execute(
                block, root=root, completed_sha=docs_head, verdict=verdict
            )
            self.assertNotEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertIn(f"test {wrong_source} = {docs_head}", completed.stderr)
            self.assertNotIn("class=", output)
            self.assertEqual(calls, [])

    def test_claimed_base_not_lowercase_hex_denies(self):
        block = self.workflow_run_block(self.STEP)
        with tempfile.TemporaryDirectory() as temporary:
            root, base, release_head, docs_head = self._seed_documentation_push(temporary)
            self._install_release_contract(root)
            bad_base = "A" * 40
            verdict = {"class": "no-artifact", "base_sha": bad_base, "source_sha": docs_head}
            completed, output, _summary, calls = self.execute(
                block, root=root, completed_sha=docs_head, verdict=verdict
            )
            self.assertNotEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            # `=~` alone is not distinguishing (the earlier, always-reached
            # MAIN_RUN_ID regex check also traces one); require the bad
            # value adjacent to the operator, matching the traced
            # `[[ AAAA...A =~ ... ]]` line for this exact guard.
            self.assertIn(f"[[ {bad_base} =~", completed.stderr)
            self.assertNotIn("class=", output)
            self.assertEqual(calls, [])

    # --- scenario 12: claimed_class disagrees with the re-derivation -------

    def _assert_class_mismatch_denies(self, *, claimed_class: str) -> None:
        block = self.workflow_run_block(self.STEP)
        with tempfile.TemporaryDirectory() as temporary:
            root, base, release_head, docs_head = self._seed_documentation_push(temporary)
            self._install_release_contract(root)
            verdict = {
                "class": claimed_class, "base_sha": release_head, "source_sha": docs_head,
            }
            completed, output, _summary, calls = self.execute(
                block, root=root, completed_sha=docs_head, verdict=verdict
            )
            self.assertNotEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertIn(f"test no-artifact = {claimed_class}", completed.stderr)
            self.assertNotIn(
                "DENY: unknown transition class", completed.stdout + completed.stderr
            )
            self.assertNotIn("class=", output)
            self.assertEqual(calls, [])

    def test_foreign_verdict_class_denies_before_reaching_the_catchall(self):
        # A claimed class of "release" is denied by the equality gate one
        # line above the case statement, because the real classifier can
        # never itself produce "release" to agree with it. Fail-closed is
        # proven; the printed catch-all text is not reachable here and
        # this test does not pretend otherwise.
        self._assert_class_mismatch_denies(claimed_class="release")

    def test_claimed_class_disagrees_with_rederivation_denies(self):
        self._assert_class_mismatch_denies(claimed_class="artifact")

    # --- scenario 13: the verdict zip carries more than one file -----------

    def test_zip_with_more_than_one_file_denies(self):
        block = self.workflow_run_block(self.STEP)
        with tempfile.TemporaryDirectory() as temporary:
            root, base, release_head, docs_head = self._seed_documentation_push(temporary)
            self._install_release_contract(root)
            verdict = {"class": "no-artifact", "base_sha": release_head, "source_sha": docs_head}
            zip_entries = {
                "transition-verdict.json": json.dumps(verdict).encode("utf-8"),
                "unexpected-extra-file.json": b"{}",
            }
            completed, output, _summary, calls = self.execute(
                block, root=root, completed_sha=docs_head, zip_entries=zip_entries
            )
            self.assertNotEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            # Match the traced comparison across BOTH shells that run this
            # suite, without losing the "it was 2, not 1" evidence. `wc -l`
            # pads its output on macOS but not on GNU coreutils, and bash
            # quotes a traced word only when it needs to -- so the same
            # guard traces as `test '       2' -eq 1` locally and
            # `test 2 -eq 1` on the CI runner. Pinning either literal makes
            # the suite pass on one platform and fail on the other; this
            # regression cost one red CI run in the sibling repository
            # before it was caught.
            self.assertRegex(completed.stderr, r"test\s+'?\s*2'?\s+-eq\s+1")
            self.assertNotIn("class=", output)
            self.assertEqual(calls, [])


    def test_lock_free_artifact_commit_in_the_gap_denies_via_the_tag_anchor(self):
        """A no-bump artifact commit must deny even though the tag EXISTS.

        The sibling repository was vulnerable here and this one is not, and
        the difference is worth proving rather than asserting. There, the
        gap re-proof anchored on a boundary recovered from git and then
        WALKED the anchor forward over trailing artifact commits; with a
        forged base that walk stepped over a later, unreleased artifact
        commit and re-anchored past it, so the cumulative proof never saw
        it. This repository has no such walk: the cumulative proof anchors
        directly on the commit the retained tag points at, which no verdict
        field can move.

        History: [0.1.9] -> [M1 releases 0.1.10, tagged] -> [C changes code,
        no bump] -> [D documentation]. Unlike the forged-base scenario, the
        retained tag v0.1.10 genuinely EXISTS, so the poll succeeds and the
        job gets all the way to the cumulative check -- which re-classifies
        tag_target..D, sees C, and denies. Every release lock is identical
        across the whole gap, so nothing but the cumulative proof can catch
        this one.
        """
        block = self.workflow_run_block(self.STEP)
        with tempfile.TemporaryDirectory() as temporary:
            root, _base = self.repo(temporary)
            release_head = self.release_commit(root, "0.1.10")
            lock_free = self.paths_commit(
                root, {"cmd/server/extra.go": "package server\n"}, "lock-free artifact"
            )
            docs_head = self.paths_commit(root, {"AGENTS.md": "docs\n"}, "docs")
            self._install_release_contract(root)
            # The FORGED base: naming the lock-free commit makes the
            # parameterised re-derivation report no-artifact, so the job
            # proceeds past the class-equality check and the tag anchor is
            # what has to catch it. Naming the honest base would deny one
            # step earlier and prove nothing about the anchor.
            verdict = {"class": "no-artifact", "base_sha": lock_free, "source_sha": docs_head}
            tag_object_sha = "a" * 40
            ref_script = [
                {
                    "status": 200,
                    "body": {
                        "ref": "refs/tags/v0.1.10",
                        "object": {"type": "tag", "sha": tag_object_sha},
                    },
                }
            ]
            tag_script = {"status": 200, "body": {"object": {"type": "commit", "sha": release_head}}}
            completed, output, _summary, calls = self.execute(
                block,
                root=root,
                completed_sha=docs_head,
                verdict=verdict,
                ref_script=ref_script,
                tag_script=tag_script,
            )
            self.assertNotEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertNotIn("class=", output)
            self.assertNotIn("NO-ARTIFACT:", completed.stdout)
            # The tag resolved fine; the denial came from the cumulative
            # re-proof, not from a failed probe.
            self.assertEqual(calls, ["ref 200", "tag 200"])


class ExistingImageShellPathTests(unittest.TestCase):
    @staticmethod
    def workflow_run_block(step_name: str) -> str:
        lines = (ROOT / ".github" / "workflows" / "release-publisher.yml").read_text(
            encoding="utf-8"
        ).splitlines()
        marker = f"      - name: {step_name}"
        try:
            start = lines.index(marker)
            run = lines.index("        run: |", start)
        except ValueError as exc:
            raise AssertionError(f"workflow step is missing: {step_name}") from exc
        body: list[str] = []
        for line in lines[run + 1 :]:
            if line.startswith("      - name:"):
                break
            if line.startswith("          "):
                body.append(line[10:])
            elif not line:
                body.append("")
            else:
                break
        if not body:
            raise AssertionError(f"workflow step has no executable run block: {step_name}")
        return "\n".join(body) + "\n"

    @staticmethod
    def bash_executable() -> str:
        discovered = shutil.which("bash")
        if discovered:
            return discovered
        if os.name == "nt":
            candidate = Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "Git" / "bin" / "bash.exe"
            if candidate.is_file():
                return str(candidate)
        raise AssertionError("bash is required to execute the release workflow shell path")

    @staticmethod
    def bash_path(path: str) -> str:
        normalized = Path(path).resolve().as_posix()
        if len(normalized) >= 3 and normalized[1:3] == ":/":
            return f"/{normalized[0].lower()}/{normalized[3:]}"
        return normalized

    def execute(self, block: str) -> tuple[subprocess.CompletedProcess[str], str]:
        source = "https://github.com/owner/site"
        revision = "a" * 40
        with tempfile.TemporaryDirectory(dir=ROOT, prefix=".release-shell-") as temporary:
            runner = Path(temporary)
            runner_relative = runner.relative_to(ROOT).as_posix()
            for architecture in ("amd64", "arm64"):
                predicate = embedded_predicate(source, revision, f"linux/{architecture}")
                (runner / f"fixture-{architecture}.json").write_text(
                    json.dumps(predicate), encoding="utf-8"
                )
                (runner / f"sbom-{architecture}.json").write_text(
                    json.dumps(spdx_document(architecture)), encoding="utf-8"
                )
            (runner / "sbom-map.json").write_text(
                json.dumps(
                    {
                        f"linux/{architecture}": {
                            "SPDX": spdx_document(architecture)
                        }
                        for architecture in ("amd64", "arm64")
                    }
                ),
                encoding="utf-8",
            )
            output = runner / "github-output.txt"
            prelude = r'''
python3() {
  "${TEST_PYTHON}" "$@"
}

jq() {
  local expression='' input=''
  while [ "$#" -gt 0 ]; do
    case "$1" in
      -*) shift ;;
      *)
        if [ -z "${expression}" ]; then
          expression="$1"
        else
          input="$1"
        fi
        shift
        ;;
    esac
  done
  case "${expression}" in
    '.token // .access_token')
      "${TEST_PYTHON}" -c 'import json,sys; value=json.load(open(sys.argv[1], encoding="utf-8")); print(value.get("token") or value["access_token"])' "${input}"
      ;;
    'keys[]')
      "${TEST_PYTHON}" -c 'import json,sys; value=json.load(open(sys.argv[1], encoding="utf-8")); sys.stdout.buffer.write(("\n".join(value.keys())+"\n").encode("utf-8"))' "${input}"
      ;;
    *) return 2 ;;
  esac
}

curl() {
  local all="$*" output='' headers=''
  if [[ "${all}" == *'https://ghcr.io/token'* ]]; then
    printf '{"token":"fixture-token"}'
    return 0
  fi
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --output) output="$2"; shift 2 ;;
      --dump-header) headers="$2"; shift 2 ;;
      *) shift ;;
    esac
  done
  printf '{"schemaVersion":2}' > "${output}"
  local digest
  digest="$(sha256sum "${output}" | awk '{print $1}')"
  printf 'docker-content-digest: sha256:%s\r\n' "${digest}" > "${headers}"
  printf '200'
}

docker() {
  case "$*" in
    *'.SBOM'*linux/amd64*) cat "${RUNNER_TEMP}/sbom-amd64.json" ;;
    *'.SBOM'*linux/arm64*) cat "${RUNNER_TEMP}/sbom-arm64.json" ;;
    *linux/amd64*) cat "${RUNNER_TEMP}/fixture-amd64.json" ;;
    *linux/arm64*) cat "${RUNNER_TEMP}/fixture-arm64.json" ;;
    *'.Provenance'*) printf '{"linux/amd64":{},"linux/arm64":{}}' ;;
    *'.SBOM'*) cat "${RUNNER_TEMP}/sbom-map.json" ;;
    *) return 2 ;;
  esac
}

cosign() {
  case "$1" in
    verify) return 0 ;;
    verify-attestation)
      if [[ "$*" == *'--type https://spdx.dev/Document'* ]]; then
        "${TEST_PYTHON}" -c 'import base64,json,sys; [print(json.dumps({"payload":base64.b64encode(open(path,"rb").read()).decode("ascii")})) for path in sys.argv[1:]]' \
          "${RUNNER_TEMP}/existing-linux-amd64.sbom.statement.json" \
          "${RUNNER_TEMP}/existing-linux-arm64.sbom.statement.json"
      else
        "${TEST_PYTHON}" -c 'import base64,json,sys; [print(json.dumps({"payload":base64.b64encode(open(path,"rb").read()).decode("ascii")})) for path in sys.argv[1:]]' \
          "${RUNNER_TEMP}/existing-linux-amd64.statement.json" \
          "${RUNNER_TEMP}/existing-linux-arm64.statement.json"
      fi
      ;;
    *) return 2 ;;
  esac
}
'''
            environment = os.environ.copy()
            environment.update(
                {
                    "TEST_PYTHON": self.bash_path(sys.executable),
                    "RUNNER_TEMP": runner_relative,
                    "GITHUB_OUTPUT": f"{runner_relative}/github-output.txt",
                    "GITHUB_ACTOR": "release-fixture",
                    "GHCR_PASSWORD": "fixture-password",
                    "GITHUB_SERVER_URL": "https://github.com",
                    "GITHUB_REPOSITORY": "owner/site",
                    "SOURCE_SHA": revision,
                    "GITHUB_REF": "refs/tags/v0.1.10",
                    "IMAGE": "ghcr.io/owner/site",
                    "TAG": "v0.1.10",
                }
            )
            completed = subprocess.run(
                [self.bash_executable(), "-s"],
                cwd=ROOT,
                env=environment,
                input=prelude + "\n" + block,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                timeout=30,
            )
            return completed, output.read_text(encoding="utf-8") if output.exists() else ""

    def test_actual_complete_image_retry_path_uses_validated_logical_count(self):
        block = self.workflow_run_block("Classify an absent, complete, or burned image tag")
        completed, output = self.execute(block)
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertIn("existing image state: complete", completed.stdout)
        self.assertIn("state=complete\n", output)
        self.assertRegex(output, r"digest=sha256:[0-9a-f]{64}\n")

        assignment = 'verified_count="$((validated_count + validated_sbom_count))"'
        self.assertIn(assignment, block)
        mutants = (
            block.replace(assignment, "", 1),
            block.replace(assignment, 'verified_count="${validated_count}"', 1),
        )
        for index, mutant in enumerate(mutants):
            with self.subTest(count_mutant=index):
                killed, _output = self.execute(mutant)
                self.assertNotEqual(killed.returncode, 0, killed.stdout + killed.stderr)
                self.assertIn("existing image state: burned", killed.stdout)


class RegistryAliasShellTests(unittest.TestCase):
    @staticmethod
    def execute(mode: str, alias: str, expected: str) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory(dir=ROOT, prefix=".registry-alias-") as temporary:
            runner = Path(temporary)
            relative = runner.relative_to(ROOT).as_posix()
            (runner / "exact.json").write_text(
                '{"mediaType":"application/vnd.oci.image.index.v1+json","schemaVersion":2}',
                encoding="utf-8",
            )
            (runner / "foreign.json").write_text(
                '{"mediaType":"application/vnd.oci.image.manifest.v1+json","schemaVersion":2}',
                encoding="utf-8",
            )
            (runner / "calls").write_text("0\n", encoding="utf-8")
            prelude = r'''
python3() { "${TEST_PYTHON}" "$@"; }
sleep() { :; }
curl() {
  local all="$*" output='' headers=''
  if [[ "${all}" == *'https://ghcr.io/token'* ]]; then
    printf '{"token":"fixture-token"}'
    return 0
  fi
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --output) output="$2"; shift 2 ;;
      --dump-header) headers="$2"; shift 2 ;;
      --write-out|--header|--proto) shift 2 ;;
      --silent|--show-error|--location|--fail-with-body) shift ;;
      *) shift ;;
    esac
  done
  local count
  count="$(tr -d '\r\n' < "${MOCK_CALLS}")"
  count=$((count + 1))
  printf '%s\n' "${count}" > "${MOCK_CALLS}"
  if [ "${MOCK_MODE}" = all-loss ] || \
     { [ "${MOCK_MODE}" = response-loss ] && [ "${count}" -eq 1 ]; }; then
    return 7
  fi
  if [ "${MOCK_MODE}" = absent ]; then
    printf '{}\n' > "${output}"
    : > "${headers}"
    printf '404'
    return 0
  fi
  if [ "${MOCK_MODE}" = retarget ]; then
    cp "${MOCK_FOREIGN}" "${output}"
  else
    cp "${MOCK_EXACT}" "${output}"
  fi
  local digest
  digest="$(sha256sum "${output}" | awk '{print $1}')"
  printf 'HTTP/2 200\r\ndocker-content-digest: sha256:%s\r\n' "${digest}" > "${headers}"
  printf '200'
}
'''
            block = (
                "source scripts/ci/verify-registry-alias.sh "
                f"'{alias}' '{expected}' "
                "'application/vnd.oci.image.index.v1+json' fixture"
            )
            environment = os.environ.copy()
            environment.update(
                {
                    "TEST_PYTHON": ExistingImageShellPathTests.bash_path(sys.executable),
                    "RUNNER_TEMP": relative,
                    "GITHUB_ACTOR": "release-fixture",
                    "GHCR_PASSWORD": "fixture-password",
                    "MOCK_MODE": mode,
                    "MOCK_CALLS": f"{relative}/calls",
                    "MOCK_EXACT": f"{relative}/exact.json",
                    "MOCK_FOREIGN": f"{relative}/foreign.json",
                }
            )
            return subprocess.run(
                [ExistingImageShellPathTests.bash_executable(), "-c", prelude + "\n" + block],
                cwd=ROOT,
                env=environment,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                timeout=30,
            )

    def test_exact_response_loss_retry_and_concurrent_retarget_paths(self):
        body = b'{"mediaType":"application/vnd.oci.image.index.v1+json","schemaVersion":2}'
        expected = "sha256:" + hashlib.sha256(body).hexdigest()
        for alias in (
            "ghcr.io/owner/site:v0.1.10",
            "ghcr.io/owner/charts/site:0.1.10",
        ):
            with self.subTest(alias=alias):
                exact = self.execute("exact", alias, expected)
                self.assertEqual(exact.returncode, 0, exact.stdout + exact.stderr)
                self.assertEqual(exact.stdout.strip(), expected)
                recovered = self.execute("response-loss", alias, expected)
                self.assertEqual(recovered.returncode, 0, recovered.stdout + recovered.stderr)
                self.assertIn("response was lost", recovered.stderr)

        retargeted = self.execute(
            "retarget", "ghcr.io/owner/site:v0.1.10", expected
        )
        self.assertNotEqual(retargeted.returncode, 0)
        self.assertIn(
            "DENY: registry alias was absent or retargeted after publication",
            retargeted.stderr,
        )
        absent = self.execute("absent", "ghcr.io/owner/site:v0.1.10", expected)
        self.assertNotEqual(absent.returncode, 0)
        self.assertIn("unexpected HTTP 404", absent.stderr)
        lost = self.execute("all-loss", "ghcr.io/owner/site:v0.1.10", expected)
        self.assertNotEqual(lost.returncode, 0)
        self.assertIn("remained unavailable after five observations", lost.stderr)


class ChartImageDigestTests(unittest.TestCase):
    """ADR 0016 step 1: only the PUBLISHED chart may carry a real digest."""

    DIGEST = "sha256:" + "ab" * 32
    OTHER = "sha256:" + "cd" * 32

    @staticmethod
    def committed_values() -> str:
        return (ROOT / "chart" / "values.yaml").read_text(encoding="utf-8")

    @staticmethod
    def run_cli(*args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-I", "-B", str(HERE / "release_contract.py"), *args],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            timeout=60,
        )

    def test_the_reviewed_tree_keeps_the_fail_closed_sentinel(self):
        # Acceptance 4. If this ever goes green with a real digest committed,
        # an unscanned, unattested value has entered the reviewed tree and the
        # fail-closed default is gone.
        self.assertEqual(RC.CHART_IMAGE_DIGEST_SENTINEL, "sha256:" + "0" * 64)
        text = self.committed_values()
        self.assertEqual(
            RC._direct_child_scalar(text, "image", "digest"),
            RC.CHART_IMAGE_DIGEST_SENTINEL,
        )
        with self.assertRaises(RC.ContractError) as denial:
            RC.require_embedded_chart_digest(text, self.DIGEST)
        self.assertIn("still carries the fail-closed digest sentinel", str(denial.exception))

    def test_embedding_rewrites_exactly_one_line_and_re_applies_as_a_no_op(self):
        text = self.committed_values()
        embedded = RC.embed_chart_image_digest(text, self.DIGEST)
        self.assertEqual(
            RC.require_embedded_chart_digest(embedded, self.DIGEST), self.DIGEST
        )
        before = text.split("\n")
        after = embedded.split("\n")
        self.assertEqual(len(before), len(after))
        changed = [
            index for index, pair in enumerate(zip(before, after)) if pair[0] != pair[1]
        ]
        self.assertEqual(len(changed), 1)
        self.assertEqual(
            before[changed[0]], f"  digest: {RC.CHART_IMAGE_DIGEST_SENTINEL}"
        )
        self.assertEqual(after[changed[0]], f"  digest: {self.DIGEST}")
        # Both publisher packaging paths run the identical substitution, so a
        # second application must change nothing rather than rewrite again.
        self.assertEqual(RC.embed_chart_image_digest(embedded, self.DIGEST), embedded)

    def test_every_malformed_digest_denies_in_both_directions(self):
        text = self.committed_values()
        embedded = RC.embed_chart_image_digest(text, self.DIGEST)
        for malformed in (
            "sha256:" + "a" * 63,
            "sha256:" + "a" * 65,
            "a" * 64,
            "sha512:" + "a" * 64,
            "SHA256:" + "a" * 64,
            "sha256:" + "A" * 64,
            "sha256:" + "g" * 64,
            " " + self.DIGEST,
            self.DIGEST + "\n",
            "",
            RC.CHART_IMAGE_DIGEST_SENTINEL,
            None,
        ):
            with self.subTest(digest=malformed):
                with self.assertRaises(RC.ContractError):
                    RC.embed_chart_image_digest(text, malformed)
                with self.assertRaises(RC.ContractError):
                    RC.require_embedded_chart_digest(embedded, malformed)

    def test_a_foreign_or_unlocatable_image_digest_never_gets_overwritten(self):
        text = self.committed_values()
        embedded = RC.embed_chart_image_digest(text, self.DIGEST)
        with self.assertRaises(RC.ContractError) as foreign:
            RC.embed_chart_image_digest(embedded, self.OTHER)
        self.assertIn("neither the sentinel nor this release digest", str(foreign.exception))
        with self.assertRaises(RC.ContractError):
            RC.require_embedded_chart_digest(embedded, self.OTHER)
        sentinel_line = f"  digest: {RC.CHART_IMAGE_DIGEST_SENTINEL}"
        for label, mutant in (
            ("renamed key", text.replace(sentinel_line, "  digestx: x", 1)),
            ("empty value", text.replace(sentinel_line, "  digest:", 1)),
            ("duplicated key", text.replace("\nimage:\n", f"\nimage:\n{sentinel_line}\n", 1)),
            ("no image mapping", text.replace("\nimage:\n", "\n", 1)),
            ("ambiguous line breaks", text.replace("\n", "\r\n")),
        ):
            with self.subTest(values=label):
                with self.assertRaises(RC.ContractError):
                    RC.embed_chart_image_digest(mutant, self.DIGEST)

    def test_the_cli_writes_the_working_copy_and_proves_its_own_postcondition(self):
        with tempfile.TemporaryDirectory(dir=ROOT, prefix=".chart-digest-cli-") as temporary:
            values = Path(temporary) / "values.yaml"
            values.write_text(self.committed_values(), encoding="utf-8")
            sentinel = self.run_cli(
                "chart-digest-verify", "--values", str(values), "--digest", self.DIGEST
            )
            self.assertNotEqual(sentinel.returncode, 0)
            self.assertIn("still carries the fail-closed digest sentinel", sentinel.stderr)
            embed = self.run_cli(
                "chart-digest-embed", "--values", str(values), "--digest", self.DIGEST
            )
            self.assertEqual(embed.returncode, 0, embed.stderr)
            self.assertEqual(embed.stdout.strip(), self.DIGEST)
            verify = self.run_cli(
                "chart-digest-verify", "--values", str(values), "--digest", self.DIGEST
            )
            self.assertEqual(verify.returncode, 0, verify.stderr)
            self.assertEqual(verify.stdout.strip(), self.DIGEST)
            settled = values.read_text(encoding="utf-8")
            again = self.run_cli(
                "chart-digest-embed", "--values", str(values), "--digest", self.DIGEST
            )
            self.assertEqual(again.returncode, 0, again.stderr)
            self.assertEqual(values.read_text(encoding="utf-8"), settled)
            for label, digest in (
                ("63 hex", "sha256:" + "a" * 63),
                ("no algorithm prefix", "a" * 64),
                ("sentinel", RC.CHART_IMAGE_DIGEST_SENTINEL),
                ("foreign digest", self.OTHER),
            ):
                with self.subTest(denied=label):
                    denied = self.run_cli(
                        "chart-digest-embed", "--values", str(values), "--digest", digest
                    )
                    self.assertNotEqual(denied.returncode, 0)
                    self.assertIn("DENY:", denied.stderr)
                    # A denied embed leaves the working copy untouched.
                    self.assertEqual(values.read_text(encoding="utf-8"), settled)


class ChartDigestShellPathTests(unittest.TestCase):
    """Both real packaging blocks, executed with stubbed registry tooling."""

    VERSION = "0.1.25"
    DIGEST = "sha256:" + "ab" * 32
    CHART = "ghcr.io/owner/charts/site"
    MANIFEST_BODY = (
        b'{"mediaType":"application/vnd.oci.image.manifest.v1+json","schemaVersion":2}'
    )
    PRELUDE = r'''
python3() { "${TEST_PYTHON}" "$@"; }
export -f python3
sleep() { :; }

curl() {
  local all="$*" output='' headers=''
  if [[ "${all}" == *'https://ghcr.io/token'* ]]; then
    printf '{"token":"fixture-token"}'
    return 0
  fi
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --output) output="$2"; shift 2 ;;
      --dump-header) headers="$2"; shift 2 ;;
      *) shift ;;
    esac
  done
  cp "${MOCK_MANIFEST_BODY}" "${output}"
  printf 'HTTP/2 200\r\ndocker-content-digest: %s\r\n' "${MOCK_MANIFEST_DIGEST}" \
    > "${headers}"
  printf '200'
}
export -f curl

helm() {
  local subcommand="$1"; shift
  case "${subcommand}" in
    package)
      local source='' version='' destination=''
      while [ "$#" -gt 0 ]; do
        case "$1" in
          --version) version="$2"; shift 2 ;;
          --app-version) shift 2 ;;
          -d) destination="$2"; shift 2 ;;
          -*) shift ;;
          *) source="$1"; shift ;;
        esac
      done
      local staging="${MOCK_STAGING}/package-$$"
      rm -rf -- "${staging}"
      mkdir -p "${staging}"
      cp -R "${source}" "${staging}/${MOCK_CHART_NAME}"
      tar -czf "${destination}/${MOCK_CHART_NAME}-${version}.tgz" \
        -C "${staging}" "${MOCK_CHART_NAME}"
      rm -rf -- "${staging}"
      printf 'Successfully packaged chart\n'
      ;;
    pull)
      local destination=''
      while [ "$#" -gt 0 ]; do
        case "$1" in
          -d) destination="$2"; shift 2 ;;
          *) shift ;;
        esac
      done
      cp "${MOCK_REGISTRY_CHART}" \
        "${destination}/${MOCK_CHART_NAME}-${MOCK_VERSION}.tgz"
      ;;
    registry)
      cat >/dev/null
      printf 'Login Succeeded\n'
      ;;
    push)
      cp "$1" "${MOCK_REGISTRY_CHART}"
      printf 'Pushed: fixture\nDigest: %s\n' "${MOCK_CHART_DIGEST}"
      ;;
    *) return 2 ;;
  esac
}

cosign() { return 0; }
'''

    @classmethod
    def chart_name(cls) -> str:
        return RC._top_level_scalar(
            (ROOT / "chart" / "Chart.yaml").read_text(encoding="utf-8"), "name"
        )

    def execute(
        self,
        block: str,
        *,
        digest: str | None = None,
        published: str | None = None,
    ) -> tuple[subprocess.CompletedProcess[str], str, str | None]:
        """Run one packaging block in a sandbox holding its own chart copy.

        `published` is the digest the already-published archive carries, or
        None for the sentinel; it is left unstaged entirely when the block is
        the publish path, so a run that pushes nothing is observable.
        """
        name = self.chart_name()
        manifest_digest = "sha256:" + hashlib.sha256(self.MANIFEST_BODY).hexdigest()
        with tempfile.TemporaryDirectory(dir=ROOT, prefix=".chart-digest-shell-") as temporary:
            sandbox = Path(temporary)
            shutil.copytree(ROOT / "chart", sandbox / "chart")
            (sandbox / "scripts" / "ci").mkdir(parents=True)
            for helper in ("release_contract.py", "verify-registry-alias.sh"):
                shutil.copy2(HERE / helper, sandbox / "scripts" / "ci" / helper)
            runner = sandbox / "runner"
            staging = sandbox / "staging"
            for directory in (runner, staging):
                directory.mkdir()
            body = sandbox / "manifest-body.json"
            body.write_bytes(self.MANIFEST_BODY)
            registry_chart = sandbox / "registry-chart.tgz"
            # The classifier READS an already-published archive; the publish
            # path CREATES one, so leaving it unstaged there makes "this run
            # pushed nothing at all" directly observable.
            if "helm push" not in block:
                source = sandbox / "published" / name
                shutil.copytree(sandbox / "chart", source)
                values = source / "values.yaml"
                if published is not None:
                    values.write_text(
                        RC.embed_chart_image_digest(
                            values.read_text(encoding="utf-8"), published
                        ),
                        encoding="utf-8",
                    )
                with tarfile.open(registry_chart, "w:gz") as bundle:
                    bundle.add(source, arcname=name)
            environment = os.environ.copy()
            environment.update(
                {
                    "TEST_PYTHON": ExistingImageShellPathTests.bash_path(sys.executable),
                    "RUNNER_TEMP": ExistingImageShellPathTests.bash_path(str(runner)),
                    "GITHUB_OUTPUT": ExistingImageShellPathTests.bash_path(
                        str(runner / "github-output.txt")
                    ),
                    "GITHUB_ACTOR": "release-fixture",
                    "GHCR_PASSWORD": "fixture-password",
                    "GITHUB_SERVER_URL": "https://github.com",
                    "GITHUB_REPOSITORY": "owner/site",
                    "CHART": self.CHART,
                    "VERSION": self.VERSION,
                    "IMAGE_DIGEST": self.DIGEST if digest is None else digest,
                    "MOCK_CHART_NAME": name,
                    "MOCK_VERSION": self.VERSION,
                    "MOCK_STAGING": ExistingImageShellPathTests.bash_path(str(staging)),
                    "MOCK_MANIFEST_BODY": ExistingImageShellPathTests.bash_path(str(body)),
                    "MOCK_MANIFEST_DIGEST": manifest_digest,
                    "MOCK_CHART_DIGEST": manifest_digest,
                    "MOCK_REGISTRY_CHART": ExistingImageShellPathTests.bash_path(
                        str(registry_chart)
                    ),
                }
            )
            completed = subprocess.run(
                [ExistingImageShellPathTests.bash_executable(), "-s"],
                cwd=sandbox,
                env=environment,
                input=self.PRELUDE + "\n" + block,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                timeout=120,
            )
            output_file = runner / "github-output.txt"
            output = output_file.read_text(encoding="utf-8") if output_file.exists() else ""
            pushed: str | None = None
            if registry_chart.exists():
                with tarfile.open(registry_chart, "r:gz") as bundle:
                    member = bundle.extractfile(f"{name}/values.yaml")
                    assert member is not None
                    pushed = member.read().decode("utf-8")
            return completed, output, pushed

    @staticmethod
    def classifier_block() -> str:
        return ExistingImageShellPathTests.workflow_run_block(
            "Classify an absent, complete, or burned chart version"
        )

    @staticmethod
    def publish_block() -> str:
        return ExistingImageShellPathTests.workflow_run_block(
            "Publish and sign an absent chart version"
        )

    EMBED = (
        "python3 -I -B scripts/ci/release_contract.py chart-digest-embed \\\n"
        '  --values chart/values.yaml --digest "${IMAGE_DIGEST}" >/dev/null\n'
    )

    def test_a_republished_version_stays_complete_only_because_both_paths_embed(self):
        block = self.classifier_block()
        self.assertIn(self.EMBED, block)
        verify = (
            "python3 -I -B scripts/ci/release_contract.py chart-digest-verify \\\n"
            '  --values "${expected_tree}/${chart_name}/values.yaml" \\\n'
            '  --digest "${IMAGE_DIGEST}" >/dev/null\n'
        )
        self.assertIn(verify, block)

        exact, output, _pushed = self.execute(block, published=self.DIGEST)
        self.assertEqual(exact.returncode, 0, exact.stdout + exact.stderr)
        self.assertIn("existing chart state: complete", exact.stdout)
        self.assertIn("state=complete\n", output)

        # The mutation the issue names: a fix that only edits the publish step
        # leaves this path packaging the sentinel, and the reproduction diff
        # then reports a false `burned` for an intact publication.
        skipped, _output, _pushed = self.execute(
            block.replace(self.EMBED, "", 1).replace(verify, "", 1),
            published=self.DIGEST,
        )
        self.assertNotEqual(skipped.returncode, 0, skipped.stdout + skipped.stderr)
        self.assertIn("existing chart state: burned", skipped.stdout)

        # Dropping only the substitution is caught earlier still, by the
        # packaged-archive re-read, before the diff is ever consulted.
        unverified, _output, _pushed = self.execute(
            block.replace(self.EMBED, "", 1), published=self.DIGEST
        )
        self.assertNotEqual(unverified.returncode, 0)
        self.assertIn("still carries the fail-closed digest sentinel", unverified.stderr)
        self.assertNotIn("existing chart state:", unverified.stdout)

        # A malformed digest denies before anything is packaged.
        for label, malformed in (
            ("63 hex", "sha256:" + "a" * 63),
            ("no algorithm prefix", "a" * 64),
            ("sentinel", RC.CHART_IMAGE_DIGEST_SENTINEL),
        ):
            with self.subTest(classifier_digest=label):
                denied, _output, _pushed = self.execute(
                    block, digest=malformed, published=self.DIGEST
                )
                self.assertNotEqual(denied.returncode, 0)
                self.assertIn("DENY:", denied.stderr)

        # Honest consequence, pinned rather than hidden: re-running against a
        # chart published BEFORE this change (sentinel in the published tree)
        # denies `burned` instead of publishing anything. It fails closed.
        legacy, _output, _pushed = self.execute(block, published=None)
        self.assertNotEqual(legacy.returncode, 0)
        self.assertIn("existing chart state: burned", legacy.stdout)

    def test_the_published_archive_carries_the_digest_and_never_the_sentinel(self):
        block = self.publish_block()
        self.assertIn(self.EMBED, block)
        verify = (
            "python3 -I -B scripts/ci/release_contract.py chart-digest-verify \\\n"
            '  --values "${packaged_values}" --digest "${IMAGE_DIGEST}" >/dev/null\n'
        )
        self.assertIn(verify, block)

        published, output, pushed = self.execute(block)
        self.assertEqual(published.returncode, 0, published.stdout + published.stderr)
        self.assertIn(
            "digest=sha256:" + hashlib.sha256(self.MANIFEST_BODY).hexdigest(), output
        )
        self.assertIsNotNone(pushed)
        self.assertEqual(
            RC.require_embedded_chart_digest(pushed, self.DIGEST), self.DIGEST
        )
        self.assertNotIn(RC.CHART_IMAGE_DIGEST_SENTINEL, pushed)

        # Substitution turned into a no-op: the post-package re-read fails the
        # run, and nothing reaches the registry at all.
        no_op, _output, unpushed = self.execute(block.replace(self.EMBED, "", 1))
        self.assertNotEqual(no_op.returncode, 0, no_op.stdout + no_op.stderr)
        self.assertIn("still carries the fail-closed digest sentinel", no_op.stderr)
        self.assertIsNone(unpushed)

        # The defect this change repairs, reproduced: with BOTH the embed and
        # the re-read removed the run is green and publishes the sentinel, so
        # the post-package check is what makes that state unreachable.
        defect, _output, sentinel_push = self.execute(
            block.replace(self.EMBED, "", 1).replace(verify, "", 1)
        )
        self.assertEqual(defect.returncode, 0, defect.stdout + defect.stderr)
        self.assertIsNotNone(sentinel_push)
        self.assertIn(RC.CHART_IMAGE_DIGEST_SENTINEL, sentinel_push)

        for label, malformed in (
            ("63 hex", "sha256:" + "a" * 63),
            ("no algorithm prefix", "a" * 64),
            ("uppercase hex", "sha256:" + "A" * 64),
            ("sentinel", RC.CHART_IMAGE_DIGEST_SENTINEL),
        ):
            with self.subTest(publish_digest=label):
                denied, _output, never_pushed = self.execute(block, digest=malformed)
                self.assertNotEqual(denied.returncode, 0)
                self.assertIn("DENY:", denied.stderr)
                self.assertIsNone(never_pushed)


class PublicationShellTransactionTests(unittest.TestCase):
    TAG = "v0.1.10"
    SOURCE = "a" * 40
    DATE = "2026-08-13T15:21:32Z"

    def test_release_bot_authority_is_independent_across_every_release_state(self):
        self.assertEqual(
            (RC.GITHUB_ACTIONS_BOT_LOGIN, RC.GITHUB_ACTIONS_BOT_ID),
            ("github-actions[bot]", 41898282),
        )
        for state, expected in (
            ("draft-empty", "draft-empty"),
            ("draft-ready", "draft-ready"),
            ("exact", "exact"),
        ):
            record, raw, asset = release_record(state)
            self.assertEqual(record["author"], {"login": "github-actions[bot]", "id": 41898282})
            if state == "draft-empty":
                self.assertEqual(record["assets"], [])
            else:
                self.assertEqual(
                    record["assets"][0]["uploader"],
                    {"login": "github-actions[bot]", "id": 41898282},
                )
            self.assertEqual(
                RC.validate_release_record(
                    record,
                    manifest=release_manifest(),
                    manifest_bytes=raw,
                    asset_bytes=asset,
                ),
                expected,
            )

        # Retry transactions reuse the prepared/staged/exact fixtures above;
        # the scheduled audit must exercise the same exact-state validator.
        publisher = (ROOT / ".github/workflows/release-publisher.yml").read_text(
            encoding="utf-8"
        )
        audit = (ROOT / ".github/workflows/release-integrity-audit.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("for attempt in 1 2 3 4 5", publisher)
        self.assertIn("release-state", publisher)
        self.assertIn("release-state", audit)
        self.assertIn("--require exact", audit)

    def test_release_tag_select_classifies_absent_one_and_ambiguous_matches(self):
        record, _raw, _asset = release_record("draft-empty")
        foreign_tag = copy.deepcopy(record)
        foreign_tag["tag_name"] = "v9.9.9"
        self.assertEqual(
            RC.select_release_by_tag(
                [foreign_tag], tag=self.TAG, repository="owner/site"
            ),
            ("absent", None),
        )
        self.assertEqual(
            RC.select_release_by_tag(
                [foreign_tag, record], tag=self.TAG, repository="owner/site"
            ),
            ("one", record),
        )
        with self.assertRaises(RC.ContractError) as raised:
            RC.select_release_by_tag(
                [record, copy.deepcopy(record)], tag=self.TAG, repository="owner/site"
            )
        self.assertIn(f"share tag_name {self.TAG!r}", str(raised.exception))
        self.assertIn("owner/site", str(raised.exception))
        self.assertIn("GET /repos/owner/site/releases", str(raised.exception))

    @staticmethod
    def workflow_run_block(path: Path, step_name: str) -> str:
        lines = path.read_text(encoding="utf-8").splitlines()
        marker = f"      - name: {step_name}"
        try:
            start = lines.index(marker)
            run = lines.index("        run: |", start)
        except ValueError as exc:
            raise AssertionError(f"workflow step is missing: {step_name}") from exc
        body: list[str] = []
        for line in lines[run + 1 :]:
            if line.startswith("      - name:"):
                break
            if line.startswith("          "):
                body.append(line[10:])
            elif not line:
                body.append("")
            else:
                break
        if not body:
            raise AssertionError(f"workflow step has no executable run block: {step_name}")
        return "\n".join(body) + "\n"

    @staticmethod
    def run_bash(
        prelude: str, block: str, environment: dict[str, str]
    ) -> subprocess.CompletedProcess[str]:
        merged = os.environ.copy()
        merged.update(environment)
        return subprocess.run(
            [ExistingImageShellPathTests.bash_executable(), "-c", prelude + "\n" + block],
            cwd=ROOT,
            env=merged,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            timeout=30,
        )

    def run_tag_transaction(self, mode: str) -> tuple[subprocess.CompletedProcess[str], list[str]]:
        block = self.workflow_run_block(
            ROOT / ".github/workflows/release-after-main.yml",
            "Create or verify the exact immutable annotated tag",
        )
        with tempfile.TemporaryDirectory(dir=ROOT, prefix=".tag-transaction-") as temporary:
            runner = Path(temporary)
            relative = runner.relative_to(ROOT).as_posix()
            ref, tag = exact_tag_records(self.TAG, self.SOURCE, f"Release {self.TAG} from {self.SOURCE}", self.DATE)
            foreign = copy.deepcopy(tag)
            foreign["object"]["sha"] = "c" * 40
            (runner / "ref.json").write_text(json.dumps(ref), encoding="utf-8")
            (runner / "tag.json").write_text(json.dumps(tag), encoding="utf-8")
            (runner / "foreign-tag.json").write_text(json.dumps(foreign), encoding="utf-8")
            initial = {
                "exact": "exact",
                "create": "absent",
                "race": "absent",
                "conflict": "foreign",
                "created-foreign": "absent",
            }[mode]
            (runner / "state").write_text(initial + "\n", encoding="utf-8")
            calls = runner / "calls"
            calls.write_text("", encoding="utf-8")
            prelude = r'''
python3() { "${TEST_PYTHON}" "$@"; }
git() {
  if [ "$1" = show ]; then printf '%s\n' "${TAGGER_DATE}"; return 0; fi
  return 2
}
sleep() { :; }
curl() {
  local output='' url=''
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --output) output="$2"; shift 2 ;;
      --write-out|--header|--proto) shift 2 ;;
      --silent|--show-error|--location) shift ;;
      *) url="$1"; shift ;;
    esac
  done
  local state
  state="$(tr -d '\r\n' < "${MOCK_STATE}")"
  if [[ "${url}" == */git/ref/tags/* ]]; then
    if [ "${state}" = absent ]; then printf '{}\n' > "${output}"; printf '404'; return 0; fi
    cp "${MOCK_REF}" "${output}"; printf '200'; return 0
  fi
  if [[ "${url}" == */git/tags/* ]]; then
    if [ "${state}" = foreign ]; then cp "${MOCK_FOREIGN_TAG}" "${output}"; else cp "${MOCK_TAG}" "${output}"; fi
    printf '200'; return 0
  fi
  return 2
}
gh() {
  if [[ "$*" == *'/git/tags'* ]]; then
    printf 'tags\n' >> "${MOCK_CALLS}"
    if [ "${MOCK_MODE}" = created-foreign ]; then cat "${MOCK_FOREIGN_TAG}"; else cat "${MOCK_TAG}"; fi
    return 0
  fi
  if [[ "$*" == *'/git/refs'* ]]; then
    printf 'refs\n' >> "${MOCK_CALLS}"
    if [ "${MOCK_MODE}" = race ]; then printf 'exact\n' > "${MOCK_STATE}"; return 1; fi
    printf 'exact\n' > "${MOCK_STATE}"
    return 0
  fi
  return 2
}
'''
            completed = self.run_bash(
                prelude,
                block,
                {
                    "TEST_PYTHON": ExistingImageShellPathTests.bash_path(sys.executable),
                    "RUNNER_TEMP": relative,
                    "GITHUB_API_URL": "https://api.github.test",
                    "GITHUB_REPOSITORY": RC.EXPECTED_REPOSITORY,
                    "GH_TOKEN": "mutation-token",
                    "SOURCE_SHA": self.SOURCE,
                    "TAG": self.TAG,
                    "TAGGER_DATE": self.DATE,
                    "MOCK_MODE": mode,
                    "MOCK_STATE": f"{relative}/state",
                    "MOCK_CALLS": f"{relative}/calls",
                    "MOCK_REF": f"{relative}/ref.json",
                    "MOCK_TAG": f"{relative}/tag.json",
                    "MOCK_FOREIGN_TAG": f"{relative}/foreign-tag.json",
                },
            )
            return completed, calls.read_text(encoding="utf-8").splitlines()

    def test_real_tag_verify_create_race_and_conflict_paths(self):
        existing, calls = self.run_tag_transaction("exact")
        self.assertEqual(existing.returncode, 0, existing.stdout + existing.stderr)
        self.assertIn(f"verified existing {self.TAG} at {self.SOURCE}", existing.stdout)
        self.assertEqual(calls, [])

        created, calls = self.run_tag_transaction("create")
        self.assertEqual(created.returncode, 0, created.stdout + created.stderr)
        self.assertEqual(calls, ["tags", "refs"])

        raced, calls = self.run_tag_transaction("race")
        self.assertEqual(raced.returncode, 0, raced.stdout + raced.stderr)
        self.assertEqual(calls, ["tags", "refs"])

        conflict, calls = self.run_tag_transaction("conflict")
        self.assertNotEqual(conflict.returncode, 0)
        self.assertEqual(calls, [])
        self.assertIn(
            "DENY: annotated tag target is not the exact source commit", conflict.stderr
        )

        created_foreign, calls = self.run_tag_transaction("created-foreign")
        self.assertNotEqual(created_foreign.returncode, 0)
        self.assertEqual(calls, ["tags"])
        self.assertIn(
            "DENY: annotated tag target is not the exact source commit",
            created_foreign.stderr,
        )

    def run_release_transaction(
        self, mode: str, block: str | None = None
    ) -> tuple[subprocess.CompletedProcess[str], list[str]]:
        block = block or self.workflow_run_block(
            ROOT / ".github/workflows/release-publisher.yml",
            "Create the draft, upload the manifest, and publish immutably",
        )
        block = block.replace("${{ steps.release.outputs.tag }}", self.TAG)
        with tempfile.TemporaryDirectory(dir=ROOT, prefix=".release-transaction-") as temporary:
            runner = Path(temporary)
            relative = runner.relative_to(ROOT).as_posix()
            manifest = release_manifest()
            manifest_path = runner / RC.RELEASE_MANIFEST_NAME
            RC.write_release_manifest(manifest_path, manifest)
            for state in ("draft-empty", "draft-ready", "exact"):
                record, _raw, _asset = release_record(state, manifest)
                (runner / f"{state}.json").write_text(json.dumps(record), encoding="utf-8")
            hostile, _raw, _asset = release_record("exact", manifest)
            hostile["assets"].append(copy.deepcopy(hostile["assets"][0]))
            (runner / "foreign.json").write_text(json.dumps(hostile), encoding="utf-8")
            initial = {
                "exact": "exact",
                "create": "absent",
                "create-race": "absent",
                "stuck-create": "absent",
                "upload-race": "draft-empty",
                "edit-race": "draft-ready",
                "foreign": "foreign",
                "duplicate-draft": "absent",
            }[mode]
            (runner / "state").write_text(initial + "\n", encoding="utf-8")
            calls = runner / "calls"
            calls.write_text("", encoding="utf-8")
            (runner / "release-notes.md").write_text("informational notes\n", encoding="utf-8")
            prelude = r'''
python3() { "${TEST_PYTHON}" "$@"; }
sleep() { :; }
bash() {
  if [ "$1" = scripts/ci/verify-registry-alias.sh ]; then
    printf '%s\n' "$3"
    return 0
  fi
  command bash "$@"
}
curl() {
  local output='' url=''
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --output) output="$2"; shift 2 ;;
      --write-out|--header|--proto) shift 2 ;;
      --silent|--show-error|--location|--fail-with-body) shift ;;
      *) url="$1"; shift ;;
    esac
  done
  if [[ "${url}" == */releases/assets/* ]]; then
    cp "${MOCK_MANIFEST}" "${output}"
    return 0
  fi
  local state
  state="$(tr -d '\r\n' < "${MOCK_STATE}")"
  # The plural list endpoint is queried only after a by-tag 404, and it DOES
  # surface drafts (the real GitHub behavior the by-tag branch below cannot
  # model) so the fallback this mock exists to prove is genuinely exercised.
  if [[ "${url}" == *"/releases?per_page=100" ]]; then
    if [ "${MOCK_MODE}" = duplicate-draft ]; then
      printf '[%s,%s]\n' \
        "$(cat "${MOCK_FIXTURES}/draft-empty.json")" \
        "$(cat "${MOCK_FIXTURES}/draft-ready.json")" > "${output}"
      printf '200'
      return 0
    fi
    if [ "${state}" = absent ]; then printf '[]\n' > "${output}"; printf '200'; return 0; fi
    printf '[%s]\n' "$(cat "${MOCK_FIXTURES}/${state}.json")" > "${output}"
    printf '200'
    return 0
  fi
  # Only a published/exact Release is ever visible on the by-tag endpoint;
  # an absent or still-draft Release 404s there, same as real GitHub.
  if [ "${state}" = absent ] || [ "${state}" = draft-empty ] || [ "${state}" = draft-ready ]; then
    printf '{}\n' > "${output}"; printf '404'; return 0
  fi
  cp "${MOCK_FIXTURES}/${state}.json" "${output}"
  printf '200'
}
gh() {
  if [ "$1" != release ]; then return 2; fi
  local operation="$2"
  printf '%s\n' "${operation}" >> "${MOCK_CALLS}"
  case "${operation}" in
    create)
      if [ "${MOCK_MODE}" = stuck-create ]; then return 1; fi
      if [ "${MOCK_MODE}" = create-race ]; then printf 'exact\n' > "${MOCK_STATE}"; return 1; fi
      printf 'draft-empty\n' > "${MOCK_STATE}"; return 0 ;;
    upload)
      if [ "${MOCK_MODE}" = upload-race ]; then printf 'exact\n' > "${MOCK_STATE}"; return 1; fi
      printf 'draft-ready\n' > "${MOCK_STATE}"; return 0 ;;
    edit)
      if [ "${MOCK_MODE}" = edit-race ]; then printf 'exact\n' > "${MOCK_STATE}"; return 1; fi
      printf 'exact\n' > "${MOCK_STATE}"; return 0 ;;
    *) return 2 ;;
  esac
}
'''
            completed = self.run_bash(
                prelude,
                block,
                {
                    "TEST_PYTHON": ExistingImageShellPathTests.bash_path(sys.executable),
                    "RUNNER_TEMP": relative,
                    "GITHUB_API_URL": "https://api.github.test",
                    "GH_TOKEN": "mutation-token",
                    "GHCR_PASSWORD": "mutation-token",
                    "GITHUB_ACTOR": "release-fixture",
                    "GITHUB_REPOSITORY": RC.EXPECTED_REPOSITORY,
                    "IMAGE": RC.EXPECTED_IMAGE,
                    "CHART": RC.EXPECTED_CHART,
                    "TAG": self.TAG,
                    "VERSION": "0.1.10",
                    "IMAGE_DIGEST": "sha256:" + "d" * 64,
                    "CHART_DIGEST": "sha256:" + "e" * 64,
                    "MOCK_MODE": mode,
                    "MOCK_STATE": f"{relative}/state",
                    "MOCK_CALLS": f"{relative}/calls",
                    "MOCK_FIXTURES": relative,
                    "MOCK_MANIFEST": f"{relative}/{RC.RELEASE_MANIFEST_NAME}",
                },
            )
            return completed, calls.read_text(encoding="utf-8").splitlines()

    def test_real_release_create_upload_publish_and_retry_paths(self):
        exact, calls = self.run_release_transaction("exact")
        self.assertEqual(exact.returncode, 0, exact.stdout + exact.stderr)
        self.assertEqual(calls, [])

        created, calls = self.run_release_transaction("create")
        self.assertEqual(created.returncode, 0, created.stdout + created.stderr)
        self.assertEqual(calls, ["create", "upload", "edit"])

        for mode, expected_call in (
            ("create-race", "create"),
            ("upload-race", "upload"),
            ("edit-race", "edit"),
        ):
            raced, calls = self.run_release_transaction(mode)
            with self.subTest(mode=mode):
                self.assertEqual(raced.returncode, 0, raced.stdout + raced.stderr)
                self.assertEqual(calls, [expected_call])
                self.assertIn("checking for an exact concurrent winner", raced.stderr)

        stuck, calls = self.run_release_transaction("stuck-create")
        self.assertNotEqual(stuck.returncode, 0)
        self.assertEqual(calls, ["create"])
        self.assertIn(
            "DENY: draft create did not reach a resumable or exact state", stuck.stderr
        )

        foreign, calls = self.run_release_transaction("foreign")
        self.assertNotEqual(foreign.returncode, 0)
        self.assertEqual(calls, [])
        self.assertIn(
            "DENY: GitHub Release must contain exactly one manifest asset", foreign.stderr
        )

        # Proves the by-tag-404 fallback for real: the by-tag probe 404s (as
        # GitHub genuinely does for an unpublished draft), the plural list
        # probe surfaces two Releases sharing one tag_name, and the real
        # (unmocked) release-tag-select command must fail closed rather than
        # pick one silently.
        duplicate, calls = self.run_release_transaction("duplicate-draft")
        self.assertNotEqual(duplicate.returncode, 0)
        self.assertEqual(calls, [])
        self.assertIn(
            f"DENY: 2 GitHub Releases share tag_name {self.TAG!r}", duplicate.stderr
        )
        self.assertIn("GET /repos/", duplicate.stderr)

    def test_terminal_exact_state_assertion_kills_inversion_mutant(self):
        block = self.workflow_run_block(
            ROOT / ".github/workflows/release-publisher.yml",
            "Create the draft, upload the manifest, and publish immutably",
        )
        guard = 'if [ "${state}" != exact ]; then'
        self.assertIn(guard, block)
        mutant = block.replace(guard, 'if [ "${state}" = exact ]; then', 1)
        killed, _calls = self.run_release_transaction("create", mutant)
        self.assertNotEqual(killed.returncode, 0, killed.stdout + killed.stderr)
        self.assertIn(
            "DENY: GitHub Release did not become authoritative immutable exact state",
            killed.stderr,
        )


class NoArtifactWiringTests(unittest.TestCase):
    """The verdict artifact and orchestrator classification stay fail closed."""

    def test_gate_publishes_the_transition_verdict_on_protected_pushes_only(self):
        gate = (ROOT / ".github/workflows/pr-gate.yml").read_text(encoding="utf-8")
        self.assertIn("name: transition-verdict", gate)
        self.assertIn("if-no-files-found: error", gate)
        self.assertIn("transition-verdict.json", gate)
        upload = gate.split("- name: Publish the transition verdict", 1)[1].split("- name: ", 1)[0]
        self.assertIn("github.event_name == 'push' && github.ref == 'refs/heads/main'", upload)
        self.assertIn("overwrite: true", upload)
        self.assertRegex(gate, r"uses: actions/upload-artifact@[0-9a-f]{40}")

    def test_orchestrator_classifies_before_any_release_effect(self):
        orchestrator = (ROOT / ".github/workflows/release-after-main.yml").read_text(encoding="utf-8")
        self.assertIn("id: classify", orchestrator)
        self.assertEqual(
            orchestrator.count("if: steps.classify.outputs.class == 'artifact'"),
            4,
            "every release-effect step must be gated on the artifact class",
        )
        self.assertIn('test "${rederived_class}" = "${claimed_class}"', orchestrator)
        self.assertIn("expected exactly one transition-verdict artifact", orchestrator)
        self.assertIn('test "${claimed_source}" = "${COMPLETED_SHA}"', orchestrator)
        # GitHub serves /actions/runs/{id}/attempts/{n}/jobs but NOT the
        # attempts/<n>/artifacts endpoint (404), so an attempt-scoped fetch
        # would fail the classify step on every merge. Pin the single
        # artifacts-fetch LINE rather than the whole file, so prose
        # explaining the 404 can neither satisfy nor break this assertion.
        artifact_fetch = [
            line for line in orchestrator.splitlines() if "/artifacts?per_page=" in line
        ]
        self.assertEqual(len(artifact_fetch), 1, artifact_fetch)
        self.assertIn(
            "/actions/runs/${MAIN_RUN_ID}/artifacts?per_page=100", artifact_fetch[0]
        )
        self.assertNotIn("attempts", artifact_fetch[0])
        self.assertIn(
            "overwrite: true", (ROOT / ".github/workflows/pr-gate.yml").read_text(encoding="utf-8")
        )
        self.assertIn("publisher not dispatched", orchestrator)
        self.assertLess(
            orchestrator.index("id: classify"),
            orchestrator.index("Dispatch the successful-main-bound publisher"),
        )
        cumulative = orchestrator.split("no-artifact)", 1)[1].split("DENY: unknown transition class", 1)[0]
        self.assertIn('--base "${anchor}"', cumulative)
        self.assertIn("= no-artifact", cumulative)
        # The gap re-proof must anchor on evidence the VERDICT CANNOT CHOOSE.
        # The class re-derivation is parameterised by claimed_base, so a
        # verdict naming a base inside the push re-derives a genuine artifact
        # merge as documentation. TWO anchors defeat that, and the cumulative
        # proof must use one of them and never claimed_base: the retained tag
        # (computed from HEAD's tree alone) or the last gated main head (read
        # from the Actions record). Anchoring on claimed_base — or on a
        # boundary recovered from git, which would move with the forgery —
        # reopens that hole silently.
        # Assert over EXECUTABLE lines only: the comments above explain the
        # attack and necessarily name claimed_base, and prose must never be
        # able to satisfy or break a guard.
        cumulative_code = "\n".join(
            line for line in cumulative.splitlines() if not line.lstrip().startswith("#")
        )
        self.assertNotIn("claimed_base", cumulative_code)
        # Anchor A.
        self.assertIn("git/ref/tags/${retained_tag}", cumulative_code)
        # Anchor B, with the four-lock equality that denies a forged base on
        # that path, plus the ancestry and self-anchor refusals.
        # Pin the FULL query, not just the path. The server-side
        # `event=push&status=success` narrowing cannot be observed through
        # the test stub (which serves its fixture regardless of query), so
        # dropping it is invisible to every behavioural test. This is the
        # one place it can be caught.
        self.assertIn(
            "workflows/pr-gate.yml/runs?branch=main&event=push&status=success&per_page=100",
            cumulative_code,
        )
        # The client-side predicates ARE behaviourally tested (see the
        # non-conforming-run tests); pinned here too so a silent removal is
        # caught twice.
        self.assertIn('.head_branch == "main"', cumulative_code)
        self.assertIn('.event == "push"', cumulative_code)
        self.assertIn('.conclusion == "success"', cumulative_code)
        self.assertIn("max_by(.id)", cumulative_code)
        self.assertIn(
            "for lock in VERSION chart/Chart.yaml chart/values.yaml CHANGELOG.md; do",
            cumulative_code,
        )
        # Both refusals are explicit `if` blocks with their own DENY
        # message, not bare `test` calls: a silent denial is
        # indistinguishable from a downstream failure, which is what made
        # the self-anchor test decorative.
        self.assertIn('git merge-base --is-ancestor "${previous_head}"', cumulative_code)
        self.assertIn('if [ "${previous_head}" = "${COMPLETED_SHA}" ]; then', cumulative_code)
        self.assertIn("it cannot anchor itself", cumulative_code)
        self.assertIn("is not an ancestor of", cumulative_code)
        # Anchor A's three outcomes must stay distinct: an exhausted
        # transient probe is UNKNOWN, not absent, and must deny.
        self.assertIn("tag_absent", cumulative_code)
        self.assertIn("never returned a definitive answer", cumulative_code)
        # The sibling repository's boundary-recovery WALK must never be
        # ported here. Both of its fail-opens lived in that walk, and this
        # repository has no need of it: anchor B is the immediately
        # preceding gated head, so the range is exactly this merge.
        self.assertNotIn("release-window", cumulative_code)
        self.assertNotIn("boundary_sha", cumulative_code)
        self.assertNotIn("advancing", cumulative_code)

    def test_agents_contract_names_the_exact_code_allowlist(self):
        agents = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
        for name in sorted(RC.DOCUMENTATION_FILES):
            self.assertIn(f"`{name}`", agents)
        self.assertIn("Markdown files under `docs/`", agents)
        self.assertIn("no-artifact", agents)
        self.assertIn("nothing to version, sign, scan", agents)


class WorkflowStructureTests(unittest.TestCase):
    PINNED_ACTION_SHA = "bcd2ba49218906704ab6c1aa796996da409d3eb1"

    @staticmethod
    def job(workflow: str, name: str, following: str | None = None) -> str:
        marker = f"\n  {name}:\n"
        if marker not in workflow:
            raise ValueError(f"workflow job is missing: {name}")
        segment = workflow.split(marker, 1)[1]
        if following is not None:
            next_marker = f"\n  {following}:\n"
            if next_marker not in segment:
                raise ValueError(f"workflow job ordering is missing: {name} -> {following}")
            segment = segment.split(next_marker, 1)[0]
        return segment

    @staticmethod
    def workflow_jobs(workflow: str) -> dict[str, str]:
        jobs = workflow.split("\njobs:\n", 1)[1]
        matches = list(re.finditer(r"(?m)^  ([A-Za-z0-9_-]+):\s*$", jobs))
        return {
            match.group(1): jobs[match.end() : matches[index + 1].start()]
            if index + 1 < len(matches)
            else jobs[match.end() :]
            for index, match in enumerate(matches)
        }

    @staticmethod
    def require_tag_partition(publisher: str) -> None:
        image = publisher.split("id: image_state", 1)[1].split("id: chart_state", 1)[0]
        chart = publisher.split("id: chart_state", 1)[1]
        if 'manifests/${TAG}' not in image or 'manifests/${VERSION}' in image:
            raise ValueError("image registry tag must be plain vX.Y.Z exactly once")
        if 'manifests/${VERSION}' not in chart or 'manifests/${TAG}' in chart:
            raise ValueError("Helm registry tag must be numeric SemVer exactly once")
        if 'helm package chart --version "${TAG}"' in publisher or '--version "v${version}"' in publisher:
            raise ValueError("Helm package version must not gain a v or double-v prefix")

    @classmethod
    def require_releasable_main_job_definitions(cls, gate: str, codeql: str) -> None:
        for name, following in (
            ("security", "dependency-review"),
            ("application", "chart"),
            ("chart", "container"),
        ):
            job = cls.job(gate, name, following)
            if re.search(r"(?m)^    if:", job):
                raise ValueError(f"required main PR-gate job gained a skip condition: {name}")
        # The three conditional jobs are pinned to the EXACT job-level condition
        # rather than to the mere presence of one, because for these the
        # condition IS the contract that PR_GATE_MAIN_JOBS mirrors. `container`
        # moved here from the no-skip loop above: it is `pull_request`-only, so
        # a DROPPED condition silently restores the duplicate main-push build of
        # a tree the PR already built, and a WIDENED one (say
        # `!= 'workflow_dispatch'`) would restore it while still reading as a
        # skip. Comparing findall's full list, not just its membership, also
        # refuses a SECOND job-level `if:` smuggled in beside the real one.
        for name, following, condition in (
            ("dependency-review", "application", "github.event_name == 'pull_request'"),
            ("container", "coverage-badges", "github.event_name == 'pull_request'"),
            (
                "coverage-badges",
                None,
                "github.event_name == 'push' && github.ref == 'refs/heads/main'",
            ),
        ):
            job = cls.job(gate, name, following)
            if re.findall(r"(?m)^    if: (.+)$", job) != [condition]:
                raise ValueError(f"{name} event-specific condition is not exact")
        analyze = cls.job(codeql, "analyze")
        if re.search(r"(?m)^    if:", analyze):
            raise ValueError("CodeQL analyze job gained a skip condition")

    @classmethod
    def require_badge_shell_strictness(cls, gate: str) -> None:
        coverage = cls.job(gate, "coverage-badges")
        for required in (
            "set -euo pipefail",
            "pushd frontend >/dev/null",
            "popd >/dev/null",
            'pushd "${work}" >/dev/null',
        ):
            if required not in coverage:
                raise ValueError(f"coverage-badges shell strictness lost: {required}")
        if coverage.count("set -euo pipefail") < 2 or coverage.count("popd >/dev/null") < 2:
            raise ValueError("both coverage-badge shell blocks must fail closed")
        if "cd frontend" in coverage or 'mkdir -p "${work}" && cd' in coverage:
            raise ValueError("coverage-badges retained fail-open directory changes")

    @staticmethod
    def require_trivy_source_gate(gate: str) -> None:
        for required in (
            "trivy fs --scanners vuln --include-dev-deps --list-all-pkgs",
            "--severity HIGH,CRITICAL --exit-code 1 --format json",
            "release_contract.py trivy-source",
            "--package-json frontend/package.json",
        ):
            if required not in gate:
                raise ValueError(f"Trivy frontend source gate lost: {required}")

    @staticmethod
    def require_chart_digest_embed(publisher: str) -> None:
        """Every chart packaging path binds the archive to the scanned digest."""
        embed = "release_contract.py chart-digest-embed"
        verify = "release_contract.py chart-digest-verify"
        package = "helm package chart"
        segments = publisher.split(package)
        if len(segments) != 3:
            raise ValueError("publisher must package the chart exactly twice")
        head, middle, tail = segments
        if embed not in head or embed not in middle:
            raise ValueError("every helm package must be preceded by the digest embed")
        if verify not in middle or verify not in tail:
            raise ValueError("every helm package must be followed by an archive re-read")
        if middle.index(verify) > middle.index(embed):
            raise ValueError("the first packaged chart must be re-read before the second embed")
        if publisher.count('--digest "${IMAGE_DIGEST}"') != 4:
            raise ValueError("both packaging paths must embed and re-read the SAME resolved digest")
        sources = set(re.findall(r"(?m)^\s*IMAGE_DIGEST: (.+)$", publisher))
        if sources != {"${{ steps.image.outputs.digest }}"}:
            raise ValueError("the chart digest may only come from the resolved image digest")
        scan = publisher.index("Gate the final image digest at HIGH and CRITICAL")
        sign = publisher.index("Sign the immutable image digest")
        attest = publisher.index("Attach and verify exact BuildKit SLSA and SPDX SBOM attestations")
        if not scan < sign < attest < publisher.index(embed):
            raise ValueError("the chart digest embed must follow the scan, signing, and attestations")

    @staticmethod
    def require_alias_and_sbom_closure(publisher: str) -> None:
        for required in (
            "registry-manifest",
            "scripts/ci/verify-registry-alias.sh",
            "Re-resolve both intended aliases before manifest staging",
            '"${IMAGE}:${TAG}" "${IMAGE_DIGEST}"',
            '"${CHART}:${VERSION}" "${CHART_DIGEST}"',
            "verify_publication_aliases",
            "sbom: true",
            "sbom-platforms",
            "sbom-statement",
            "sbom-set",
            "cosign verify-attestation --type 'https://spdx.dev/Document' --output json",
            "${{ env.IMAGE }}:${{ steps.release.outputs.tag }}",
            'helm push "${RUNNER_TEMP}/${chart_name}-${version}.tgz" "oci://${CHART%/*}"',
        ):
            if required not in publisher:
                raise ValueError(f"publisher alias/SBOM closure lost: {required}")
        if publisher.count("scripts/ci/verify-registry-alias.sh") < 6:
            raise ValueError("both aliases must be rebound after push, before staging, and before immutable publication")
        if publisher.count("sbom-platforms") < 2 or publisher.count("sbom-set") < 2:
            raise ValueError("new and reused images must validate exact SBOM platform and signed sets")
        if publisher.count("verify_publication_aliases") < 3:
            raise ValueError("Release create/retry and immutable edit must recheck both aliases")
        resolve = publisher.index("Re-resolve both intended aliases before manifest staging")
        manifest = publisher.index("Generate the deterministic release manifest")
        release = publisher.index("Create the draft, upload the manifest, and publish immutably")
        if not resolve < manifest < release:
            raise ValueError("alias re-resolution must immediately precede manifest and Release staging")
        pre_manifest = publisher[resolve:manifest]
        for exact_binding in (
            '"${IMAGE}:${TAG}" "${IMAGE_DIGEST}"',
            '"${CHART}:${VERSION}" "${CHART_DIGEST}"',
        ):
            if exact_binding not in pre_manifest:
                raise ValueError(f"pre-manifest alias binding lost: {exact_binding}")

    @staticmethod
    def require_exact_release_wiring(orchestrator: str, publisher: str) -> None:
        WorkflowStructureTests.require_alias_and_sbom_closure(publisher)
        for required in (
            "fetch-depth: 0",
            "release-window",
            "tag-state",
            "tag-created-object",
            "classify_tag exact >/dev/null",
            "classify_tag absent >/dev/null",
            'tagger[name]=${tagger_name}',
            'tagger[email]=${tagger_email}',
            'tagger[date]=${tagger_date}',
        ):
            if required not in orchestrator:
                raise ValueError(f"orchestrator lost exact release wiring: {required}")
        for required in (
            "tag-record",
            "cosign attest --yes --predicate",
            "cosign verify-attestation --type 'https://slsa.dev/provenance/v1' --output json",
            "release-state",
            "release-manifest",
            "manifest-record",
            "release-asset-id",
            "release-tag-select",
            "gh release create \"${tag}\" --verify-tag --draft",
            "gh release upload \"${tag}\" \"${manifest}\"",
            "gh release edit \"${tag}\" --draft=false",
            "draft-empty",
            "draft-ready",
            "observe_release | grep -Fx exact",
            "/releases/tags/${tag}",
            "/releases?per_page=100",
            "X-GitHub-Api-Version: 2026-03-10",
            "for attempt in 1 2 3 4 5",
            "Terminally rebind the REST tag ref and annotated object",
            # The freshly built image's provenance must name THIS run exactly
            # (issue #111); the existing-image classifier cannot use its own
            # run ID, because a re-dispatch recovery legitimately reuses bytes
            # an earlier run built, so it recovers and reuses that one run.
            '--builder-run-id "${GITHUB_RUN_ID}"',
            "attestation-builder-run",
            '--builder-run-id "${builder_run_id}"',
        ):
            if required not in publisher:
                raise ValueError(f"publisher lost exact release wiring: {required}")
        for repeated in (
            "attestation-statement",
            "--builder-run-id",
            "attestation-set",
            "cosign verify-attestation --type 'https://slsa.dev/provenance/v1' --output json",
            "sbom-statement",
            "sbom-set",
            "cosign verify-attestation --type 'https://spdx.dev/Document' --output json",
        ):
            if publisher.count(repeated) < 2:
                raise ValueError(f"publisher must use {repeated} for both existing and new images")
        if orchestrator.count("classify_tag exact >/dev/null") < 3:
            raise ValueError("orchestrator must verify exact tag state before reuse, after a race, and after create")
        if publisher.count("state=\"$(observe_release)\"") < 4:
            raise ValueError("publisher must re-observe Release state after each resumable transaction edge")
        if publisher.count("X-GitHub-Api-Version: 2026-03-10") < 2:
            raise ValueError("publisher must version both main-run and Release REST reads")
        terminal_marker = "\n      - name: Terminally rebind the REST tag ref and annotated object\n"
        terminal = publisher.split(terminal_marker, 1)[1]
        if "\n      - name:" in terminal or "\n        if:" in terminal:
            raise ValueError("terminal REST tag rebind must be unconditional and literally last")
        for required in ("tag-ref-object", "tag-record", "${SOURCE_SHA}", "/git/tags/${tag_object}"):
            if required not in terminal:
                raise ValueError(f"terminal REST tag rebind lost: {required}")
        for forbidden in (
            "cosign download attestation",
            'git rev-list -n 1 "${tag}"',
            "--clobber",
        ):
            if forbidden in publisher:
                raise ValueError(f"publisher contains unauthenticated or local-ref verifier: {forbidden}")

    @staticmethod
    def require_successful_main_privilege_boundary(orchestrator: str, publisher: str) -> None:
        authorize = WorkflowStructureTests.job(publisher, "authorize", "immutable_settings")
        publish = WorkflowStructureTests.job(publisher, "publish")
        for exact_destination in (
            f"IMAGE: {RC.EXPECTED_IMAGE}",
            f"CHART: {RC.EXPECTED_CHART}",
        ):
            if exact_destination not in publisher:
                raise ValueError(
                    f"publisher package destination is not exact: {exact_destination}"
                )
        for required in (
            "actions: read",
            "contents: read",
            "main-run-record",
            "codeql-run-record",
            "workflow-jobs",
            'actions/runs/${MAIN_RUN_ID}',
            'actions/runs/${CODEQL_RUN_ID}',
            "authority/scripts/ci/release_contract.py",
            "ref: ${{ github.sha }}",
            "path: authority",
            '--run-id "${MAIN_RUN_ID}"',
            '--repository "${GITHUB_REPOSITORY}"',
            '--source-sha "${SOURCE_SHA}"',
            'test "${authorized_sha}" = "${SOURCE_SHA}"',
            'test "${authorized_codeql_sha}" = "${SOURCE_SHA}"',
            '--workflow pr-gate --run-id "${MAIN_RUN_ID}"',
            '--workflow codeql --run-id "${CODEQL_RUN_ID}"',
            'source_sha=%s\\n',
        ):
            if required not in authorize:
                raise ValueError(f"read-only main-run authorization lost: {required}")
        for forbidden in ("contents: write", "packages: write", "id-token: write"):
            if forbidden in authorize:
                raise ValueError(f"authorization job gained privilege: {forbidden}")
        for required in (
            "needs: [authorize, immutable_settings]",
            "needs.immutable_settings.result == 'success'",
            "ref: ${{ needs.authorize.outputs.source_sha }}",
            "fetch-depth: 0",
            "persist-credentials: false",
            "SOURCE_SHA: ${{ needs.authorize.outputs.source_sha }}",
            "@refs/heads/main",
        ):
            if required not in publish:
                raise ValueError(f"privileged publication lost main-run dependency: {required}")
        package_bind = publish.index(
            "Bind protected workflow, authorized checkout, and committed locks"
        )
        first_registry_read = publish.index(
            "Classify an absent, complete, or burned image tag"
        )
        if package_bind > first_registry_read:
            raise ValueError("package identities must bind before registry side effects")
        binding_step = publish.split(
            "- name: Bind protected workflow, authorized checkout, and committed locks",
            1,
        )[1].split("- name: Install checksum-verified tools", 1)[0]
        for required in (
            'workflow-ref "${GITHUB_WORKFLOW_REF}"',
            '--image "${IMAGE}"',
            '--chart "${CHART}"',
        ):
            if required not in binding_step:
                raise ValueError(
                    f"pre-side-effect package identity binding lost: {required}"
                )
        for required in (
            "MAIN_RUN_ID: ${{ github.event.workflow_run.id }}",
            "CODEQL_RUN_ID: ${{ steps.main_ci.outputs.codeql_run_id }}",
            "codeql-run-list",
            "codeql-run-record",
            "workflow-jobs",
            "actions/workflows/codeql.yml/runs?branch=main&event=push&head_sha=${SOURCE_SHA}",
            "for _ in $(seq 1 30)",
            "--ref main",
            '-f main_run_id="${MAIN_RUN_ID}"',
            '-f codeql_run_id="${CODEQL_RUN_ID}"',
        ):
            if required not in orchestrator:
                raise ValueError(f"orchestrator lost exact main-run dispatch binding: {required}")
        if '--ref "${TAG}"' in orchestrator:
            raise ValueError("publisher workflow must never be selected from a mutable tag ref")
        if orchestrator.index("Authorize exact successful PR-gate and CodeQL main jobs") > orchestrator.index(
            "Create or verify the exact immutable annotated tag"
        ):
            raise ValueError("exact main job inventories must authorize before any tag side effect")
        for required in (
            "main_run_id:",
            "codeql_run_id:",
            "source_sha:",
            "release-${{ inputs.source_sha }}",
        ):
            if required not in publisher:
                raise ValueError(f"publisher dispatch interface lost: {required}")
        for forbidden in ("GITHUB_SHA", "GITHUB_REF_NAME", "@${GITHUB_REF}"):
            if forbidden in publisher:
                raise ValueError(f"publisher retained tag-selected or event-SHA authority: {forbidden}")

    @classmethod
    def require_settings_token_isolation(cls, orchestrator: str, publisher: str) -> None:
        pin = f"actions/create-github-app-token@{cls.PINNED_ACTION_SHA} # v3.2.0"
        for label, workflow, mutation_name, mutation_following in (
            ("orchestrator", orchestrator, "release", None),
            ("publisher", publisher, "publish", None),
        ):
            settings = cls.job(
                workflow,
                "immutable_settings",
                "release" if label == "orchestrator" else "publish",
            )
            mutation = cls.job(workflow, mutation_name, mutation_following)
            for required in (
                "environment: platform-release",
                pin,
                "app-id: ${{ vars.PLATFORM_RELEASE_APP_ID }}",
                "private-key: ${{ secrets.PLATFORM_RELEASE_APP_PRIVATE_KEY }}",
                "owner: ${{ github.repository_owner }}",
                "repositories: ${{ github.event.repository.name }}",
                "permission-administration: read",
                "skip-token-revoke: false",
                "IMMUTABLE_SETTINGS_TOKEN: ${{ steps.immutable_settings.outputs.token }}",
                'GH_TOKEN="${IMMUTABLE_SETTINGS_TOKEN}"',
                "settings-preflight",
            ):
                if required not in settings:
                    raise ValueError(f"{label} settings token isolation lost: {required}")
            if "\n    outputs:" in settings:
                raise ValueError(f"{label} settings job must expose no token-capable output")
            for forbidden in (
                "contents: write",
                "packages: write",
                "actions: write",
                "id-token: write",
                "secrets.GITHUB_TOKEN",
            ):
                if forbidden in settings:
                    raise ValueError(f"{label} settings job gained mutation authority: {forbidden}")
            for forbidden in (
                "IMMUTABLE_SETTINGS_TOKEN",
                "PLATFORM_RELEASE_APP_ID",
                "PLATFORM_RELEASE_APP_PRIVATE_KEY",
                "steps.immutable_settings.outputs.token",
                "create-github-app-token",
            ):
                if forbidden in mutation:
                    raise ValueError(f"{label} mutation job gained settings token: {forbidden}")
            if "secrets.GITHUB_TOKEN" not in mutation:
                raise ValueError(f"{label} mutation job lost ordinary GITHUB_TOKEN authority")
        orchestrator_release = cls.job(orchestrator, "release")
        publisher_settings = cls.job(publisher, "immutable_settings", "publish")
        publisher_publish = cls.job(publisher, "publish")
        if "needs: immutable_settings" not in orchestrator_release:
            raise ValueError("tag mutation must depend on the immutable-settings recheck")
        if "needs: authorize" not in publisher_settings:
            raise ValueError("settings recheck must follow successful-main authorization")
        if "needs: [authorize, immutable_settings]" not in publisher_publish:
            raise ValueError("registry/signing/Release mutation must depend on settings recheck")

    @staticmethod
    def require_integrity_audit(audit: str) -> None:
        for required in (
            "schedule:",
            "workflow_dispatch:",
            "timeout-minutes: 45",
            "cancel-in-progress: false",
            "release-state",
            "--require exact",
            "release-manifest.json",
            "tag-record",
            "Audit mutable registry aliases against immutable manifest digests",
            'test "${observed}" = "${expected}"',
            "registry-manifest",
            "attestation-set",
            # The audit rebuilds expected provenance for a PUBLISHED image, so
            # it recovers the one builder run from the artifact and binds every
            # platform to it; dropping either flag would restore an unbound
            # builder identity.
            "attestation-builder-run",
            '--builder-run-id "${builder_run_id}"',
            "json-keys",
            "sbom-platforms",
            "sbom-statement",
            "sbom-set",
            "cosign verify-attestation --type 'https://spdx.dev/Document' --output json",
            "audit-sbom.json",
            "CHART_DIGEST",
            "Rescan the immutable image digest at HIGH and CRITICAL",
            "trivy image --scanners vuln --severity HIGH,CRITICAL --exit-code 1",
            '"${IMAGE_ALIAS%:*}@${IMAGE_DIGEST}"',
        ):
            if required not in audit:
                raise ValueError(f"scheduled release-integrity audit lost: {required}")
        if audit.count("cosign verify --certificate-identity") < 2:
            raise ValueError("scheduled audit must verify both image and chart signatures")
        if audit.count("sbom-statement") < 1 or audit.count("sbom-set") < 1:
            raise ValueError("scheduled audit must bind exact signed per-platform SPDX payloads")
        for forbidden in (
            "contents: write",
            "packages: write",
            "id-token: write",
            "cosign sign",
            "cosign attest",
            "gh release create",
            "gh release edit",
            "helm push",
            "docker buildx build",
        ):
            if forbidden in audit:
                raise ValueError(f"scheduled release-integrity audit gained mutation: {forbidden}")

    def test_no_distinct_main_sha_can_be_canceled_or_share_release_identity(self):
        gate = (ROOT / ".github/workflows/pr-gate.yml").read_text(encoding="utf-8")
        codeql = (ROOT / ".github/workflows/codeql.yml").read_text(encoding="utf-8")
        orchestrator = (ROOT / ".github/workflows/release-after-main.yml").read_text(encoding="utf-8")
        publisher = (ROOT / ".github/workflows/release-publisher.yml").read_text(encoding="utf-8")
        audit = (ROOT / ".github/workflows/release-integrity-audit.yml").read_text(encoding="utf-8")
        self.require_releasable_main_job_definitions(gate, codeql)
        self.require_badge_shell_strictness(gate)
        # The whole container job body, so the two mutants below rewrite THAT
        # job's condition and nothing else — `dependency-review` carries the
        # byte-identical `if:` line, and a naive gate-wide replace would hit it
        # first and prove the wrong thing.
        container = self.job(gate, "container", "coverage-badges")
        for changed_gate, changed_codeql in (
            (
                gate.replace("  security:\n    runs-on:", "  security:\n    if: false\n    runs-on:", 1),
                codeql,
            ),
            (
                gate,
                codeql.replace("  analyze:\n    runs-on:", "  analyze:\n    if: false\n    runs-on:", 1),
            ),
            # Container pin, both directions the workflow can regress: the
            # condition removed outright (the pre-#109 state, which rebuilds the
            # merged tree), and the condition widened to one that still admits
            # the main push.
            (
                gate.replace(
                    container,
                    container.replace("    if: github.event_name == 'pull_request'\n", "", 1),
                    1,
                ),
                codeql,
            ),
            (
                gate.replace(
                    container,
                    container.replace(
                        "if: github.event_name == 'pull_request'",
                        "if: github.event_name != 'workflow_dispatch'",
                        1,
                    ),
                    1,
                ),
                codeql,
            ),
        ):
            with self.assertRaises(ValueError):
                self.require_releasable_main_job_definitions(changed_gate, changed_codeql)
        for mutant in (
            gate.replace(
                "          set -euo pipefail\n          pushd frontend",
                "          set -o pipefail\n          pushd frontend",
                1,
            ),
            gate.replace("pushd frontend >/dev/null", "cd frontend", 1),
            gate.replace('pushd "${work}" >/dev/null', 'cd "${work}"', 1),
        ):
            with self.assertRaises(ValueError):
                self.require_badge_shell_strictness(mutant)
        for workflow in (gate, codeql):
            self.assertIn("github.event.pull_request.number || github.sha", workflow)
            self.assertIn("cancel-in-progress: ${{ github.event_name == 'pull_request' }}", workflow)
        self.assertIn("release-after-main-${{ github.event.workflow_run.head_sha }}", orchestrator)
        self.assertIn("release-${{ inputs.source_sha }}", publisher)
        self.assertIn("release-integrity-audit-${{ github.sha }}", audit)
        for workflow in (orchestrator, publisher, audit):
            self.assertIn("cancel-in-progress: false", workflow)
        self.assertNotIn("queue:", gate + codeql + orchestrator + publisher + audit)
        self.assertIn("workflow_run:", orchestrator)
        self.assertIn("github.event.workflow_run.head_sha", orchestrator)
        self.assertIn("actions: write", orchestrator)
        self.assertIn("workflow_dispatch:", publisher)
        self.assertIn("source_sha:", publisher)
        self.assertNotRegex(publisher, r"(?ms)^\s+push:\s*\n\s+tags:")
        self.require_successful_main_privilege_boundary(orchestrator, publisher)
        for package_mutant in (
            publisher.replace(
                f"IMAGE: {RC.EXPECTED_IMAGE}",
                "IMAGE: ghcr.io/snaraj/lidersea.com",
                1,
            ),
            publisher.replace(
                f"CHART: {RC.EXPECTED_CHART}",
                "CHART: ghcr.io/snaraj/charts/lidersea.com",
                1,
            ),
            publisher.replace('--image "${IMAGE}"', "", 1),
            publisher.replace('--chart "${CHART}"', "", 1),
        ):
            with self.assertRaises(ValueError):
                self.require_successful_main_privilege_boundary(
                    orchestrator, package_mutant
                )
        self.require_settings_token_isolation(orchestrator, publisher)
        self.assertGreaterEqual(publisher.count("registry-state --http-status"), 2)
        self.assertGreaterEqual(publisher.count("--data-urlencode \"scope=repository:"), 2)
        self.assertGreaterEqual(publisher.count("registry-manifest"), 2)
        self.assertGreaterEqual(publisher.count("scripts/ci/verify-registry-alias.sh"), 6)
        self.assertNotIn("if ! docker buildx imagetools inspect \"${IMAGE}:${TAG}\"", publisher)
        self.assertNotIn("if ! helm show chart", publisher)
        self.require_tag_partition(publisher)
        self.require_alias_and_sbom_closure(publisher)
        for mutant in (
            publisher.replace(
                "${{ env.IMAGE }}:${{ steps.release.outputs.tag }}",
                "${{ env.IMAGE }}:wrong-${{ steps.release.outputs.tag }}",
                1,
            ),
            publisher.replace(
                'helm push "${RUNNER_TEMP}/${chart_name}-${version}.tgz" "oci://${CHART%/*}"',
                'helm push "${RUNNER_TEMP}/${chart_name}-${version}.tgz" "oci://ghcr.io/owner/wrong"',
                1,
            ),
            publisher.replace("          sbom: true", "          sbom: false", 1),
            publisher.replace(
                '"${IMAGE}:${TAG}" "${IMAGE_DIGEST}"',
                '"${IMAGE}:${TAG}" "sha256:${IMAGE_DIGEST#sha256:0}"',
                1,
            ),
            publisher.replace(
                '"${CHART}:${VERSION}" "${CHART_DIGEST}"',
                '"${CHART}:${VERSION}" "sha256:${CHART_DIGEST#sha256:0}"',
                1,
            ),
        ):
            with self.assertRaises(ValueError):
                self.require_alias_and_sbom_closure(mutant)
        for mutation in (
            publisher.replace('manifests/${VERSION}', 'manifests/${TAG}'),
            publisher.replace('manifests/${VERSION}', 'manifests/v${VERSION}'),
            publisher.replace('--version "${version}"', '--version "v${version}"'),
        ):
            with self.assertRaises(ValueError):
                self.require_tag_partition(mutation)
        self.assertIn('helm package chart --version "${version}" --app-version "${version}"', publisher)
        self.assertNotIn("targetCommitish", publisher)
        self.assertIn('gh release create "${tag}" --verify-tag', publisher)
        self.require_exact_release_wiring(orchestrator, publisher)
        for owner, token in (
            ("orchestrator", "MAIN_RUN_ID: ${{ github.event.workflow_run.id }}"),
            ("orchestrator", "CODEQL_RUN_ID: ${{ steps.main_ci.outputs.codeql_run_id }}"),
            ("orchestrator", "codeql-run-list"),
            ("orchestrator", "workflow-jobs"),
            ("orchestrator", "for _ in $(seq 1 30)"),
            ("orchestrator", "--ref main"),
            ("orchestrator", '-f main_run_id="${MAIN_RUN_ID}"'),
            ("orchestrator", '-f codeql_run_id="${CODEQL_RUN_ID}"'),
            ("publisher", "actions: read"),
            ("publisher", "main-run-record"),
            ("publisher", "codeql-run-record"),
            ("publisher", "workflow-jobs"),
            ("publisher", 'actions/runs/${MAIN_RUN_ID}'),
            ("publisher", 'actions/runs/${CODEQL_RUN_ID}'),
            ("publisher", '--run-id "${MAIN_RUN_ID}"'),
            ("publisher", '--repository "${GITHUB_REPOSITORY}"'),
            ("publisher", '--source-sha "${SOURCE_SHA}"'),
            ("publisher", 'test "${authorized_sha}" = "${SOURCE_SHA}"'),
            ("publisher", 'test "${authorized_codeql_sha}" = "${SOURCE_SHA}"'),
            ("publisher", "needs: [authorize, immutable_settings]"),
            ("publisher", "needs.immutable_settings.result == 'success'"),
            ("publisher", "ref: ${{ needs.authorize.outputs.source_sha }}"),
            ("publisher", 'workflow-ref "${GITHUB_WORKFLOW_REF}"'),
            ("publisher", '--image "${IMAGE}"'),
            ("publisher", '--chart "${CHART}"'),
        ):
            changed_orchestrator = orchestrator.replace(token, "") if owner == "orchestrator" else orchestrator
            changed_publisher = publisher.replace(token, "") if owner == "publisher" else publisher
            with self.subTest(main_run_mutation=token), self.assertRaises(ValueError):
                self.require_successful_main_privilege_boundary(changed_orchestrator, changed_publisher)
        with self.assertRaises(ValueError):
            self.require_successful_main_privilege_boundary(
                orchestrator.replace("--ref main", '--ref "${TAG}"', 1),
                publisher,
            )
        for owner, token in (
            ("orchestrator", "fetch-depth: 0"),
            ("orchestrator", "release-window"),
            ("orchestrator", "tag-state"),
            ("orchestrator", "tag-created-object"),
            ("orchestrator", "classify_tag exact >/dev/null"),
            ("orchestrator", "classify_tag absent >/dev/null"),
            ("orchestrator", 'tagger[name]=${tagger_name}'),
            ("orchestrator", 'tagger[email]=${tagger_email}'),
            ("orchestrator", 'tagger[date]=${tagger_date}'),
            ("publisher", "tag-record"),
            ("publisher", "cosign attest --yes --predicate"),
            ("publisher", "cosign verify-attestation --type 'https://slsa.dev/provenance/v1' --output json"),
            ("publisher", "release-state"),
            ("publisher", "release-manifest"),
            ("publisher", "manifest-record"),
            ("publisher", "release-asset-id"),
            ("publisher", "release-tag-select"),
            ("publisher", "gh release upload \"${tag}\" \"${manifest}\""),
            ("publisher", "gh release edit \"${tag}\" --draft=false"),
            ("publisher", "observe_release | grep -Fx exact"),
            ("publisher", "/releases/tags/${tag}"),
            ("publisher", "/releases?per_page=100"),
            ("publisher", "X-GitHub-Api-Version: 2026-03-10"),
            ("publisher", "for attempt in 1 2 3 4 5"),
            ("publisher", "Terminally rebind the REST tag ref and annotated object"),
            ("publisher", "attestation-statement"),
            ("publisher", '--builder-run-id "${GITHUB_RUN_ID}"'),
            ("publisher", "attestation-builder-run"),
            ("publisher", '--builder-run-id "${builder_run_id}"'),
            ("publisher", "attestation-set"),
            ("publisher", "sbom-statement"),
            ("publisher", "sbom-set"),
            ("publisher", "scripts/ci/verify-registry-alias.sh"),
            ("publisher", "Re-resolve both intended aliases before manifest staging"),
        ):
            changed_orchestrator = orchestrator.replace(token, "") if owner == "orchestrator" else orchestrator
            changed_publisher = publisher.replace(token, "") if owner == "publisher" else publisher
            with self.subTest(wiring_mutation=token), self.assertRaises(ValueError):
                self.require_exact_release_wiring(changed_orchestrator, changed_publisher)
        for forbidden in (
            "cosign download attestation",
            'git rev-list -n 1 "${tag}"',
            "--clobber",
        ):
            with self.subTest(forbidden_mutation=forbidden), self.assertRaises(ValueError):
                self.require_exact_release_wiring(orchestrator, publisher + forbidden)
        template = (ROOT / ".github/PULL_REQUEST_TEMPLATE.md").read_text(encoding="utf-8")
        for required in (
            "Closes #",
            "Protected base",
            "Exact head",
            "Next patch release",
            "Successful-main run binding and manual/unmerged dispatch denial",
            "requires-review",
        ):
            self.assertIn(required, template)

    def test_settings_token_boundary_mutants_are_killed(self):
        orchestrator = (ROOT / ".github/workflows/release-after-main.yml").read_text(encoding="utf-8")
        publisher = (ROOT / ".github/workflows/release-publisher.yml").read_text(encoding="utf-8")
        self.require_settings_token_isolation(orchestrator, publisher)
        for owner, token in (
            ("orchestrator", "environment: platform-release"),
            (
                "orchestrator",
                f"actions/create-github-app-token@{self.PINNED_ACTION_SHA} # v3.2.0",
            ),
            ("orchestrator", "permission-administration: read"),
            ("orchestrator", "skip-token-revoke: false"),
            ("orchestrator", 'GH_TOKEN="${IMMUTABLE_SETTINGS_TOKEN}"'),
            ("publisher", "app-id: ${{ vars.PLATFORM_RELEASE_APP_ID }}"),
            ("publisher", "private-key: ${{ secrets.PLATFORM_RELEASE_APP_PRIVATE_KEY }}"),
            ("publisher", "repositories: ${{ github.event.repository.name }}"),
            ("publisher", "settings-preflight"),
            ("publisher", "needs: [authorize, immutable_settings]"),
        ):
            changed_orchestrator = orchestrator.replace(token, "") if owner == "orchestrator" else orchestrator
            changed_publisher = publisher.replace(token, "") if owner == "publisher" else publisher
            with self.subTest(token=token), self.assertRaises(ValueError):
                self.require_settings_token_isolation(changed_orchestrator, changed_publisher)
        for workflow_mutant in (
            orchestrator.replace(
                "GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}",
                "GH_TOKEN: ${{ steps.immutable_settings.outputs.token }}",
                1,
            ),
            orchestrator.replace(
                "permissions:\n      actions: write",
                "outputs:\n      token: ${{ steps.immutable_settings.outputs.token }}\n    permissions:\n      actions: write",
                1,
            ),
        ):
            with self.assertRaises(ValueError):
                self.require_settings_token_isolation(workflow_mutant, publisher)

    def test_every_job_has_a_positive_timeout_and_every_action_is_sha_pinned(self):
        for path in sorted((ROOT / ".github/workflows").glob("*.yml")):
            workflow = path.read_text(encoding="utf-8")
            jobs = self.workflow_jobs(workflow)
            self.assertTrue(jobs, path.name)
            for name, job in jobs.items():
                with self.subTest(path=path.name, job=name):
                    self.assertRegex(job, r"(?m)^    timeout-minutes: [1-9][0-9]*$")
                mutant = job.replace("timeout-minutes:", "timeout-removed:", 1)
                with self.assertRaises(AssertionError):
                    self.assertRegex(mutant, r"(?m)^    timeout-minutes: [1-9][0-9]*$")
            for action in re.findall(r"(?m)^\s*uses:\s+([^\s#]+)", workflow):
                with self.subTest(path=path.name, action=action):
                    self.assertRegex(action, r"@[0-9a-f]{40}$")

    def test_manifest_scan_and_scheduled_read_only_integrity_audit_are_load_bearing(self):
        gate = (ROOT / ".github/workflows/pr-gate.yml").read_text(encoding="utf-8")
        publisher = (ROOT / ".github/workflows/release-publisher.yml").read_text(encoding="utf-8")
        audit = (ROOT / ".github/workflows/release-integrity-audit.yml").read_text(encoding="utf-8")
        self.require_trivy_source_gate(gate)
        for token in (
            "--include-dev-deps",
            "--list-all-pkgs",
            "release_contract.py trivy-source",
        ):
            with self.subTest(source_scan_mutant=token), self.assertRaises(ValueError):
                self.require_trivy_source_gate(gate.replace(token, "", 1))
        self.assertIn("trivy config --severity HIGH,CRITICAL --exit-code 1", gate)
        scan = publisher.index("Gate the final image digest at HIGH and CRITICAL")
        sign = publisher.index("Sign the immutable image digest")
        self.assertLess(scan, sign)
        self.assertIn('"${IMAGE}@${{ steps.image.outputs.digest }}"', publisher[scan:sign])
        self.require_integrity_audit(audit)
        for token in (
            "--require exact",
            'test "${observed}" = "${expected}"',
            "cosign verify --certificate-identity",
            "registry-manifest",
            "attestation-set",
            "attestation-builder-run",
            '--builder-run-id "${builder_run_id}"',
            "sbom-platforms",
            "sbom-statement",
            "sbom-set",
            "audit-sbom.json",
            "trivy image --scanners vuln --severity HIGH,CRITICAL --exit-code 1",
        ):
            with self.subTest(audit_mutant=token), self.assertRaises(ValueError):
                self.require_integrity_audit(audit.replace(token, ""))

    def test_both_chart_packaging_paths_embed_and_re_read_the_release_digest(self):
        publisher = (ROOT / ".github/workflows/release-publisher.yml").read_text(
            encoding="utf-8"
        )
        self.require_chart_digest_embed(publisher)
        embed = "release_contract.py chart-digest-embed"
        verify = "release_contract.py chart-digest-verify"
        embeds = publisher.split(embed)
        self.assertEqual(len(embeds), 3)
        for label, mutant in (
            ("classifier embed removed", publisher.replace(embed, "", 1)),
            ("publish embed removed", embed.join(embeds[:2]) + embeds[2]),
            ("classifier re-read removed", publisher.replace(verify, "", 1)),
            ("one packaging path removed", publisher.replace("helm package chart", "", 1)),
            (
                "digest re-derived from the tag",
                publisher.replace('--digest "${IMAGE_DIGEST}"', '--digest "${TAG}"', 1),
            ),
            (
                "digest no longer the resolved image digest",
                publisher.replace(
                    "IMAGE_DIGEST: ${{ steps.image.outputs.digest }}",
                    "IMAGE_DIGEST: ${{ steps.image_state.outputs.digest }}",
                    1,
                ),
            ),
            (
                "embed hoisted ahead of the scan and attestation gates",
                publisher.replace(
                    "      - name: Gate the final image digest at HIGH and CRITICAL",
                    f"      # {embed}\n      - name: Gate the final image digest at HIGH and CRITICAL",
                    1,
                ),
            ),
        ):
            with self.subTest(chart_digest_mutant=label), self.assertRaises(ValueError):
                self.require_chart_digest_embed(mutant)


if __name__ == "__main__":
    unittest.main()
