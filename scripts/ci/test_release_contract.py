"""Hostile tests for the per-main-merge release contract."""

from __future__ import annotations

import base64
import contextlib
import copy
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
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


def embedded_predicate(source: str, revision: str, marker: str) -> dict[str, object]:
    return {
        "buildDefinition": {
            "buildType": "https://mobyproject.org/buildkit@v1",
            "externalParameters": {"marker": marker},
            "internalParameters": {},
        },
        "runDetails": {
            "builder": {"id": source + "/actions/runs/123"},
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
        "merge_methods": ["rebase", "squash"],
        "required_status_checks": [
            {"context": context, "integration_id": 15368} for context in REQUIRED_CHECKS
        ],
        "strict_status_checks": True,
        "require_pull_request": True,
        "require_linear_history": True,
        "allow_force_pushes": False,
        "allow_deletions": False,
        "restrict_updates": False,
        "bypass_actors": [],
        "immutable_releases": True,
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
        },
        "repos/owner/site/immutable-releases": {
            "enabled": True,
            "enforced_by_owner": False,
        },
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
            "conditions": {
                "ref_name": {"exclude": [], "include": ["refs/heads/main"]},
            },
            "bypass_actors": [],
            "rules": [
                {"type": "deletion"},
                {"type": "non_fast_forward"},
                {"type": "required_linear_history"},
                {
                    "type": "pull_request",
                    "parameters": {"allowed_merge_methods": ["rebase", "squash"]},
                },
                {
                    "type": "required_status_checks",
                    "parameters": {
                        "do_not_enforce_on_create": False,
                        "required_status_checks": checks,
                        "strict_required_status_checks_policy": True,
                    },
                },
                {"type": "code_scanning", "parameters": {}},
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


class SettingsReceiptTests(unittest.TestCase):
    @staticmethod
    def require_documented_contract(text: str) -> None:
        for token in (
            "Release-control readiness receipt",
            '"immutable_releases": true',
            '"merge_methods": ["rebase", "squash"]',
            '"context": "security", "integration_id": 15368',
            '"context": "dependency-review", "integration_id": 15368',
            '"strict_status_checks": true',
            '"require_pull_request": true',
            '"require_linear_history": true',
            '"allow_force_pushes": false',
            '"allow_deletions": false',
            '"restrict_updates": false',
            '"bypass_actors": []',
            "settings-preflight",
            "settings-receipt",
            "must remain Draft",
        ):
            if token not in text:
                raise ValueError(f"release settings contract lost: {token}")

    def test_only_the_exact_immutable_no_bypass_receipt_is_ready(self):
        exact = settings_receipt()
        RC.validate_settings_receipt(exact, "owner/site")
        mutations: list[dict[str, object]] = []
        for key, value in (
            ("repository", "other/site"),
            ("branch", "release"),
            ("merge_methods", ["squash"]),
            ("merge_methods", ["merge", "rebase", "squash"]),
            ("merge_methods", ["rebase", "rebase", "squash"]),
            ("strict_status_checks", False),
            ("require_pull_request", False),
            ("require_linear_history", False),
            ("allow_force_pushes", True),
            ("allow_deletions", True),
            ("restrict_updates", True),
            ("bypass_actors", ["present"]),
            ("immutable_releases", False),
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
            "repos/owner/site/rulesets",
            "repos/owner/site/rulesets/42",
        ]:
            raise AssertionError(f"unexpected settings endpoints: {self_calls}")
        if getter.call_args_list[2].kwargs != {"paginate": True}:
            raise AssertionError("ruleset inventory must use exhaustive pagination")
        if any(call.kwargs for index, call in enumerate(getter.call_args_list) if index != 2):
            raise AssertionError("only the list endpoint should paginate")
        return receipt

    def test_authoritative_raw_preflight_rejects_every_control_mutant(self):
        exact = settings_api()
        self.assertEqual(self.observe(copy.deepcopy(exact)), settings_receipt())

        mutations: list[dict[str, object]] = []
        for endpoint, path, value in (
            ("repos/owner/site", ("allow_merge_commit",), True),
            ("repos/owner/site", ("allow_rebase_merge",), False),
            ("repos/owner/site", ("default_branch",), "release"),
            ("repos/owner/site/immutable-releases", ("enabled",), False),
            ("repos/owner/site/rulesets/42", ("enforcement",), "disabled"),
            ("repos/owner/site/rulesets/42", ("conditions", "ref_name", "include"), ["~ALL"]),
            ("repos/owner/site/rulesets/42", ("bypass_actors",), [{"actor_type": "RepositoryRole"}]),
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
            "deletion",
            "non_fast_forward",
            "required_linear_history",
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

        for field, value in (
            ("allowed_merge_methods", ["merge", "rebase", "squash"]),
            ("allowed_merge_methods", ["squash"]),
        ):
            changed = copy.deepcopy(exact)
            pull = next(
                rule
                for rule in changed["repos/owner/site/rulesets/42"]["rules"]
                if rule["type"] == "pull_request"
            )
            pull["parameters"][field] = value
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
            '"immutable_releases": true',
            '"merge_methods": ["rebase", "squash"]',
            '"context": "security", "integration_id": 15368',
            '"strict_status_checks": true',
            '"require_pull_request": true',
            '"require_linear_history": true',
            '"allow_force_pushes": false',
            '"allow_deletions": false',
            '"restrict_updates": false',
            '"bypass_actors": []',
            "settings-preflight",
            "settings-receipt",
            "must remain Draft",
        )
        for token in tokens:
            with self.subTest(deletion=token), self.assertRaises(ValueError):
                self.require_documented_contract(runbook.replace(token, "", 1))
        for old, new in (
            ('"immutable_releases": true', '"immutable_releases": false'),
            ('"strict_status_checks": true', '"strict_status_checks": false'),
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


class PublisherBindingTests(unittest.TestCase):
    SHA = "a" * 40

    def test_source_sha_ref_event_and_snapshot_checks_are_executable(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name, contents in snapshot("0.1.10").items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(contents, encoding="utf-8")
            workflow_ref = "owner/site/.github/workflows/release-publisher.yml@refs/heads/main"
            intent = RC.validate_publisher(
                root,
                self.SHA,
                self.SHA,
                "refs/heads/main",
                "workflow_dispatch",
                "owner/site",
                workflow_ref,
            )
            self.assertEqual(intent, RC.ReleaseIntent(self.SHA, RC.Version.parse("0.1.10")))
            for source, checkout, ref, event_name, repository, selected_workflow in (
                ("b" * 40, self.SHA, "refs/heads/main", "workflow_dispatch", "owner/site", workflow_ref),
                (self.SHA, "b" * 40, "refs/heads/main", "workflow_dispatch", "owner/site", workflow_ref),
                (self.SHA, self.SHA, "refs/tags/v0.1.10", "workflow_dispatch", "owner/site", workflow_ref),
                (self.SHA, self.SHA, "refs/heads/main", "push", "owner/site", workflow_ref),
                (self.SHA, self.SHA, "refs/heads/main", "workflow_dispatch", "other/site", workflow_ref),
                (
                    self.SHA,
                    self.SHA,
                    "refs/heads/main",
                    "workflow_dispatch",
                    "owner/site",
                    "owner/site/.github/workflows/release-publisher.yml@refs/tags/v0.1.10",
                ),
            ):
                with self.subTest(
                    source=source,
                    checkout=checkout,
                    ref=ref,
                    event=event_name,
                    repository=repository,
                    workflow=selected_workflow,
                ), self.assertRaises(RC.ContractError):
                    RC.validate_publisher(
                        root,
                        source,
                        checkout,
                        ref,
                        event_name,
                        repository,
                        selected_workflow,
                    )


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

    def test_release_metadata_and_zero_asset_inventory_are_exact(self):
        exact = {
            "tag_name": self.TAG,
            "name": f"lidersea.com {self.TAG}",
            "body": "exact notes\n",
            "draft": False,
            "prerelease": False,
            "immutable": True,
            "assets": [],
        }
        RC.validate_release_record(exact, tag=self.TAG, title=f"lidersea.com {self.TAG}", body="exact notes")
        for key, value in (
            ("tag_name", "v0.1.11"),
            ("name", "foreign"),
            ("body", "foreign"),
            ("body", None),
            ("draft", True),
            ("prerelease", True),
            ("immutable", False),
            ("immutable", None),
            ("assets", [{"name": "foreign.bin"}]),
            ("assets", None),
        ):
            changed = copy.deepcopy(exact)
            changed[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(RC.ContractError):
                RC.validate_release_record(changed, tag=self.TAG, title=f"lidersea.com {self.TAG}", body="exact notes")


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

    def release(self) -> dict[str, object]:
        return {
            "tag_name": self.TAG,
            "name": f"lidersea.com {self.TAG}",
            "body": "exact notes\n",
            "draft": False,
            "prerelease": False,
            "immutable": True,
            "assets": [],
        }

    def test_absent_create_verify_and_concurrent_retry_need_no_local_tag_ref(self):
        ref, tag = exact_tag_records(self.TAG, self.SOURCE, self.MESSAGE, self.DATE)
        # Both racers can observe absence. The winner creates the exact REST
        # records; the loser re-queries those records after its create fails.
        self.assertEqual(RC.classify_tag_state(404, None, None, **self.tag_expected()), "absent")
        self.assertEqual(RC.classify_tag_state(404, None, None, **self.tag_expected()), "absent")
        self.assertEqual(RC.classify_tag_state(200, ref, tag, **self.tag_expected()), "exact")
        self.assertEqual(RC.classify_tag_state(200, ref, tag, **self.tag_expected()), "exact")

        expected_release = self.release()
        for _racer in range(2):
            self.assertEqual(
                RC.classify_release_state(
                    404, None, tag=self.TAG, title=f"lidersea.com {self.TAG}", body="exact notes"
                ),
                "absent",
            )
        for _retry in range(2):
            self.assertEqual(
                RC.classify_release_state(
                    200,
                    expected_release,
                    tag=self.TAG,
                    title=f"lidersea.com {self.TAG}",
                    body="exact notes",
                ),
                "exact",
            )

    def test_missing_records_conflicts_and_non_authoritative_absence_fail_closed(self):
        ref, tag = exact_tag_records(self.TAG, self.SOURCE, self.MESSAGE, self.DATE)
        for status in (0, 301, 401, 403, 409, 422, 429, 500, 503):
            with self.subTest(kind="tag-status", status=status), self.assertRaises(RC.ContractError):
                RC.classify_tag_state(status, None, None, **self.tag_expected())
            with self.subTest(kind="release-status", status=status), self.assertRaises(RC.ContractError):
                RC.classify_release_state(
                    status, None, tag=self.TAG, title=f"lidersea.com {self.TAG}", body="exact notes"
                )
        for changed_ref, changed_tag in ((None, tag), (ref, None)):
            with self.assertRaises(RC.ContractError):
                RC.classify_tag_state(200, changed_ref, changed_tag, **self.tag_expected())
        with self.assertRaises(RC.ContractError):
            RC.classify_tag_state(404, ref, tag, **self.tag_expected())
        with self.assertRaises(RC.ContractError):
            RC.classify_release_state(
                404,
                self.release(),
                tag=self.TAG,
                title=f"lidersea.com {self.TAG}",
                body="exact notes",
            )

    def test_exact_shell_state_assertions_kill_deletion_and_inversion_mutants(self):
        for state in ("absent", "exact"):
            self.assertEqual(RC.require_publication_state(state, state), state)
        for actual, required in (("absent", "exact"), ("exact", "absent"), ("foreign", "exact")):
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
            notes = Path(temporary) / "notes.md"
            notes.write_text("exact notes\n", encoding="utf-8")
            release_args = [
                "release-state",
                "--http-status",
                "404",
                "--tag",
                self.TAG,
                "--title",
                f"lidersea.com {self.TAG}",
                "--body",
                str(notes),
            ]
            self.assertEqual(invoke([*release_args, "--require", "absent"]), 0)
            self.assertEqual(invoke([*release_args, "--require", "exact"]), 1)


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
            (("runDetails", "builder", "id"), "https://github.com/attacker/site/actions/runs/1"),
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
                )


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
    *linux/amd64*) cat "${RUNNER_TEMP}/fixture-amd64.json" ;;
    *linux/arm64*) cat "${RUNNER_TEMP}/fixture-arm64.json" ;;
    *'.Provenance'*) printf '{"linux/amd64":{},"linux/arm64":{}}' ;;
    *'.SBOM'*) printf '{"linux/amd64":{},"linux/arm64":{}}' ;;
    *) return 2 ;;
  esac
}

cosign() {
  case "$1" in
    verify) return 0 ;;
    verify-attestation)
      "${TEST_PYTHON}" -c 'import base64,json,sys; [print(json.dumps({"payload":base64.b64encode(open(path,"rb").read()).decode("ascii")})) for path in sys.argv[1:]]' \
        "${RUNNER_TEMP}/existing-linux-amd64.statement.json" \
        "${RUNNER_TEMP}/existing-linux-arm64.statement.json"
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
                [self.bash_executable(), "-c", prelude + "\n" + block],
                cwd=ROOT,
                env=environment,
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

        assignment = 'verified_count="${validated_count}"'
        self.assertIn(assignment, block)
        mutants = (
            block.replace(assignment, "", 1),
            block.replace(assignment, 'verified_count="${#expected_attestations[@]}"', 1),
        )
        for index, mutant in enumerate(mutants):
            with self.subTest(count_mutant=index):
                killed, _output = self.execute(mutant)
                self.assertNotEqual(killed.returncode, 0, killed.stdout + killed.stderr)
                self.assertIn("existing image state: burned", killed.stdout)


class WorkflowStructureTests(unittest.TestCase):
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

    @staticmethod
    def require_exact_release_wiring(orchestrator: str, publisher: str) -> None:
        for required in (
            "fetch-depth: 0",
            "release-window",
            "tag-state",
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
            "cosign attest --yes --statement",
            "cosign verify-attestation --type slsaprovenance1 --output json",
            "release-state",
            "classify_release exact >/dev/null",
            "classify_release absent >/dev/null",
            "/releases/tags/${tag}",
            "X-GitHub-Api-Version: 2026-03-10",
            "for attempt in 1 2 3 4 5",
            'test "${race_verified}" = true',
        ):
            if required not in publisher:
                raise ValueError(f"publisher lost exact release wiring: {required}")
        for repeated in (
            "attestation-statement",
            "attestation-set",
            "cosign verify-attestation --type slsaprovenance1 --output json",
        ):
            if publisher.count(repeated) < 2:
                raise ValueError(f"publisher must use {repeated} for both existing and new images")
        if orchestrator.count("classify_tag exact >/dev/null") < 3:
            raise ValueError("orchestrator must verify exact tag state before reuse, after a race, and after create")
        if publisher.count("classify_release exact >/dev/null") < 3:
            raise ValueError("publisher must verify exact Release state before reuse, after a race, and after create")
        if publisher.count("X-GitHub-Api-Version: 2026-03-10") < 2:
            raise ValueError("publisher must version both main-run and Release REST reads")
        for forbidden in ("cosign download attestation", 'git rev-list -n 1 "${tag}"'):
            if forbidden in publisher:
                raise ValueError(f"publisher contains unauthenticated or local-ref verifier: {forbidden}")

    @staticmethod
    def require_successful_main_privilege_boundary(orchestrator: str, publisher: str) -> None:
        if '\n  authorize:\n' not in publisher or '\n  publish:\n' not in publisher:
            raise ValueError("publisher must separate read-only authorization from privileged publication")
        authorize = publisher.split('\n  authorize:\n', 1)[1].split('\n  publish:\n', 1)[0]
        publish = publisher.split('\n  publish:\n', 1)[1]
        for required in (
            "actions: read",
            "contents: read",
            "main-run-record",
            'actions/runs/${MAIN_RUN_ID}',
            "authority/scripts/ci/release_contract.py",
            "ref: ${{ github.sha }}",
            "path: authority",
            '--run-id "${MAIN_RUN_ID}"',
            '--repository "${GITHUB_REPOSITORY}"',
            '--source-sha "${SOURCE_SHA}"',
            'test "${authorized_sha}" = "${SOURCE_SHA}"',
            'source_sha=%s\\n',
        ):
            if required not in authorize:
                raise ValueError(f"read-only main-run authorization lost: {required}")
        for forbidden in ("contents: write", "packages: write", "id-token: write"):
            if forbidden in authorize:
                raise ValueError(f"authorization job gained privilege: {forbidden}")
        for required in (
            "needs: authorize",
            "if: needs.authorize.result == 'success'",
            "ref: ${{ needs.authorize.outputs.source_sha }}",
            "fetch-depth: 0",
            "persist-credentials: false",
            "SOURCE_SHA: ${{ needs.authorize.outputs.source_sha }}",
            'workflow-ref "${GITHUB_WORKFLOW_REF}"',
            "@refs/heads/main",
        ):
            if required not in publish:
                raise ValueError(f"privileged publication lost main-run dependency: {required}")
        for required in (
            "MAIN_RUN_ID: ${{ github.event.workflow_run.id }}",
            "--ref main",
            '-f main_run_id="${MAIN_RUN_ID}"',
        ):
            if required not in orchestrator:
                raise ValueError(f"orchestrator lost exact main-run dispatch binding: {required}")
        if '--ref "${TAG}"' in orchestrator:
            raise ValueError("publisher workflow must never be selected from a mutable tag ref")
        for required in ("main_run_id:", "source_sha:", "release-${{ inputs.source_sha }}"):
            if required not in publisher:
                raise ValueError(f"publisher dispatch interface lost: {required}")
        for forbidden in ("GITHUB_SHA", "GITHUB_REF_NAME", "@${GITHUB_REF}"):
            if forbidden in publisher:
                raise ValueError(f"publisher retained tag-selected or event-SHA authority: {forbidden}")

    def test_no_distinct_main_sha_can_be_canceled_or_share_release_identity(self):
        gate = (ROOT / ".github/workflows/pr-gate.yml").read_text(encoding="utf-8")
        orchestrator = (ROOT / ".github/workflows/release-after-main.yml").read_text(encoding="utf-8")
        publisher = (ROOT / ".github/workflows/release-publisher.yml").read_text(encoding="utf-8")
        self.assertIn("github.event.pull_request.number || github.run_id", gate)
        self.assertNotIn("queue:", gate + orchestrator + publisher)
        self.assertIn("workflow_run:", orchestrator)
        self.assertIn("github.event.workflow_run.head_sha", orchestrator)
        self.assertIn("actions: write", orchestrator)
        self.assertIn("workflow_dispatch:", publisher)
        self.assertIn("source_sha:", publisher)
        self.assertNotRegex(publisher, r"(?ms)^\s+push:\s*\n\s+tags:")
        self.require_successful_main_privilege_boundary(orchestrator, publisher)
        self.assertGreaterEqual(publisher.count("registry-state --http-status"), 2)
        self.assertGreaterEqual(publisher.count("--data-urlencode \"scope=repository:"), 2)
        self.assertGreaterEqual(publisher.count("docker-content-digest:"), 2)
        self.assertNotIn("if ! docker buildx imagetools inspect \"${IMAGE}:${TAG}\"", publisher)
        self.assertNotIn("if ! helm show chart", publisher)
        self.require_tag_partition(publisher)
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
            ("orchestrator", "--ref main"),
            ("orchestrator", '-f main_run_id="${MAIN_RUN_ID}"'),
            ("publisher", "actions: read"),
            ("publisher", "main-run-record"),
            ("publisher", 'actions/runs/${MAIN_RUN_ID}'),
            ("publisher", '--run-id "${MAIN_RUN_ID}"'),
            ("publisher", '--repository "${GITHUB_REPOSITORY}"'),
            ("publisher", '--source-sha "${SOURCE_SHA}"'),
            ("publisher", 'test "${authorized_sha}" = "${SOURCE_SHA}"'),
            ("publisher", "needs: authorize"),
            ("publisher", "if: needs.authorize.result == 'success'"),
            ("publisher", "ref: ${{ needs.authorize.outputs.source_sha }}"),
            ("publisher", 'workflow-ref "${GITHUB_WORKFLOW_REF}"'),
        ):
            changed_orchestrator = orchestrator.replace(token, "", 1) if owner == "orchestrator" else orchestrator
            changed_publisher = publisher.replace(token, "", 1) if owner == "publisher" else publisher
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
            ("orchestrator", "classify_tag exact >/dev/null"),
            ("orchestrator", "classify_tag absent >/dev/null"),
            ("orchestrator", 'tagger[name]=${tagger_name}'),
            ("orchestrator", 'tagger[email]=${tagger_email}'),
            ("orchestrator", 'tagger[date]=${tagger_date}'),
            ("publisher", "tag-record"),
            ("publisher", "cosign attest --yes --statement"),
            ("publisher", "cosign verify-attestation --type slsaprovenance1 --output json"),
            ("publisher", "release-state"),
            ("publisher", "classify_release exact >/dev/null"),
            ("publisher", "classify_release absent >/dev/null"),
            ("publisher", "/releases/tags/${tag}"),
            ("publisher", "X-GitHub-Api-Version: 2026-03-10"),
            ("publisher", "for attempt in 1 2 3 4 5"),
            ("publisher", 'test "${race_verified}" = true'),
            ("publisher", "attestation-statement"),
            ("publisher", "attestation-set"),
        ):
            changed_orchestrator = orchestrator.replace(token, "", 1) if owner == "orchestrator" else orchestrator
            changed_publisher = publisher.replace(token, "", 1) if owner == "publisher" else publisher
            with self.subTest(wiring_mutation=token), self.assertRaises(ValueError):
                self.require_exact_release_wiring(changed_orchestrator, changed_publisher)
        for forbidden in ("cosign download attestation", 'git rev-list -n 1 "${tag}"'):
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
            "architecture sanity review",
        ):
            self.assertIn(required, template)


if __name__ == "__main__":
    unittest.main()
