#!/usr/bin/env python3
"""Fail-closed release identity and GitHub event policy.

This module is intentionally standard-library only.  CI and its hostile tests
use the same functions, so event, version, and immutable-artifact decisions
cannot drift into prose-only conventions.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import copy
import datetime as dt
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping


SEMVER_RE = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
EXPECTED_WORKFLOW = "PR gate"
EXPECTED_WORKFLOW_PATH = ".github/workflows/pr-gate.yml"
EXPECTED_PUBLISHER_PATH = ".github/workflows/release-publisher.yml"
INTOTO_STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
SLSA_PREDICATE_TYPE = "https://slsa.dev/provenance/v1"
DIGEST_RE = re.compile(r"^sha256:([0-9a-f]{64})$")
GITHUB_API_VERSION = "2026-03-10"
EXPECTED_MAIN_RULESET = "Protect-Main"
GITHUB_ACTIONS_INTEGRATION_ID = 15368
REQUIRED_STATUS_CHECKS = (
    "analyze (go, manual)",
    "analyze (javascript-typescript, none)",
    "application",
    "chart",
    "container",
    "dependency-review",
    "security",
)


class ContractError(ValueError):
    """A release input cannot satisfy the immutable publication contract."""


@dataclass(frozen=True, order=True)
class Version:
    major: int
    minor: int
    patch: int

    @classmethod
    def parse(cls, raw: str) -> "Version":
        match = SEMVER_RE.fullmatch(raw.strip())
        if not match:
            raise ContractError(f"invalid semantic version: {raw!r}")
        return cls(*(int(part) for part in match.groups()))

    def __str__(self) -> str:
        return f"{self.major}.{self.minor}.{self.patch}"

    @property
    def tag(self) -> str:
        return f"v{self}"


@dataclass(frozen=True)
class ReleaseIntent:
    source_sha: str
    version: Version

    @property
    def tag(self) -> str:
        return self.version.tag


@dataclass(frozen=True)
class TransitionWindow:
    base_sha: str
    intent: ReleaseIntent


def require_sha(raw: object, field: str) -> str:
    if not isinstance(raw, str) or not SHA_RE.fullmatch(raw):
        raise ContractError(f"{field} must be one lowercase 40-hex commit SHA")
    return raw


def require_next_patch(base: Version, head: Version) -> None:
    expected = Version(base.major, base.minor, base.patch + 1)
    if head != expected:
        raise ContractError(f"head version {head} must be exact next patch {expected}")


def _top_level_scalar(text: str, key: str) -> str:
    values: list[str] = []
    for line in text.splitlines():
        if line == line.lstrip() and line.startswith(f"{key}:"):
            values.append(line.split(":", 1)[1].strip().strip("\"'"))
    if len(values) != 1 or not values[0]:
        raise ContractError(f"expected exactly one non-empty top-level {key!r} scalar")
    return values[0]


def _direct_child_scalar(text: str, parent: str, key: str) -> str:
    parents = [index for index, line in enumerate(text.splitlines()) if line.rstrip() == f"{parent}:"]
    if len(parents) != 1:
        raise ContractError(f"expected exactly one top-level {parent!r} mapping")
    lines = text.splitlines()
    values: list[str] = []
    for line in lines[parents[0] + 1 :]:
        if line and not line[0].isspace() and not line.lstrip().startswith("#"):
            break
        if line.startswith(f"  {key}:"):
            values.append(line.split(":", 1)[1].strip().strip("\"'"))
    if len(values) != 1 or not values[0]:
        raise ContractError(f"expected exactly one non-empty {parent}.{key} scalar")
    return values[0]


def validate_snapshot(files: Mapping[str, str]) -> ReleaseIntent:
    required = {"VERSION", "chart/Chart.yaml", "chart/values.yaml", "CHANGELOG.md"}
    missing = sorted(required.difference(files))
    if missing:
        raise ContractError(f"release snapshot is missing: {', '.join(missing)}")

    version = Version.parse(files["VERSION"])
    chart = files["chart/Chart.yaml"]
    values = files["chart/values.yaml"]
    if Version.parse(_top_level_scalar(chart, "version")) != version:
        raise ContractError("chart version does not equal VERSION")
    if Version.parse(_top_level_scalar(chart, "appVersion")) != version:
        raise ContractError("chart appVersion does not equal VERSION")
    if _direct_child_scalar(values, "image", "tag") != version.tag:
        raise ContractError("human image tag does not equal v<VERSION>")

    escaped = re.escape(str(version))
    headings = re.findall(rf"^## \[{escaped}\] - ([0-9]{{4}}-[0-9]{{2}}-[0-9]{{2}})$", files["CHANGELOG.md"], re.MULTILINE)
    if len(headings) != 1:
        raise ContractError("changelog must contain exactly one dated current-version heading")
    try:
        dt.date.fromisoformat(headings[0])
    except ValueError as exc:
        raise ContractError("changelog release date is not a real ISO date") from exc
    top = re.compile(rf"^## \[Unreleased\]\s*\n+## \[{escaped}\] - {re.escape(headings[0])}$", re.MULTILINE)
    if not top.search(files["CHANGELOG.md"]):
        raise ContractError("current release must immediately follow an empty Unreleased heading")
    return ReleaseIntent(source_sha="", version=version)


def _git(repository: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repository), *args],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    )
    if completed.returncode != 0:
        raise ContractError(f"git {' '.join(args)} failed")
    return completed.stdout.strip()


def _git_file(repository: Path, revision: str, path: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repository), "show", f"{revision}:{path}"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    )
    if completed.returncode != 0:
        raise ContractError(f"{path} is absent at {revision}")
    return completed.stdout


def _linear_commits(repository: Path, base_sha: str, head_sha: str) -> list[str]:
    """Return every commit in one contiguous, merge-free base..head range."""
    _git(repository, "merge-base", "--is-ancestor", base_sha, head_sha)
    raw = _git(repository, "rev-list", "--first-parent", "--reverse", f"{base_sha}..{head_sha}")
    commits = raw.splitlines() if raw else []
    if not commits or commits[-1] != head_sha:
        raise ContractError("release range is empty or does not end at the exact head")
    previous = base_sha
    for commit in commits:
        fields = _git(repository, "rev-list", "--parents", "-n", "1", commit).split()
        if len(fields) != 2 or fields[0] != commit or fields[1] != previous:
            raise ContractError("release range must be one contiguous linear commit chain")
        previous = commit
    return commits


def validate_transition(repository: Path, base_sha: str, head_sha: str, *, first_parent: bool) -> ReleaseIntent:
    base_sha = require_sha(base_sha, "base SHA")
    head_sha = require_sha(head_sha, "head SHA")
    if _git(repository, "rev-parse", f"{base_sha}^{{commit}}") != base_sha:
        raise ContractError("base SHA did not resolve exactly")
    if _git(repository, "rev-parse", f"{head_sha}^{{commit}}") != head_sha:
        raise ContractError("head SHA did not resolve exactly")
    _linear_commits(repository, base_sha, head_sha)
    base_version = Version.parse(_git_file(repository, base_sha, "VERSION"))
    head_files = {
        path: _git_file(repository, head_sha, path)
        for path in ("VERSION", "chart/Chart.yaml", "chart/values.yaml", "CHANGELOG.md")
    }
    head = validate_snapshot(head_files)
    # A squash merge is a one-commit range; GitHub's enabled rebase merge can
    # install several commits atomically. The source identity is the complete
    # final tree, while the exact base -> head patch step remains one release
    # intent regardless of how many linear commits carried that tree there.
    require_next_patch(base_version, head.version)
    return ReleaseIntent(source_sha=head_sha, version=head.version)


def discover_transition_window(repository: Path, head_sha: str) -> TransitionWindow:
    """Recover the exact main-push range whose first commit advanced VERSION."""
    head_sha = require_sha(head_sha, "head SHA")
    if _git(repository, "rev-parse", f"{head_sha}^{{commit}}") != head_sha:
        raise ContractError("head SHA did not resolve exactly")
    head_version = Version.parse(_git_file(repository, head_sha, "VERSION"))
    cursor = head_sha
    while True:
        fields = _git(repository, "rev-list", "--parents", "-n", "1", cursor).split()
        if len(fields) != 2 or fields[0] != cursor:
            raise ContractError("could not recover one linear release boundary")
        parent = fields[1]
        parent_version = Version.parse(_git_file(repository, parent, "VERSION"))
        if parent_version != head_version:
            intent = validate_transition(repository, parent, head_sha, first_parent=True)
            return TransitionWindow(base_sha=parent, intent=intent)
        cursor = parent


def plan_workflow_run(event: Mapping[str, object], expected_repository: str) -> str:
    repository = event.get("repository")
    run = event.get("workflow_run")
    if not isinstance(repository, Mapping) or repository.get("full_name") != expected_repository:
        raise ContractError("workflow_run repository identity mismatch")
    if not isinstance(run, Mapping):
        raise ContractError("workflow_run payload is absent")
    exact = {
        "name": EXPECTED_WORKFLOW,
        "event": "push",
        "status": "completed",
        "conclusion": "success",
        "head_branch": "main",
    }
    for key, expected in exact.items():
        if run.get(key) != expected:
            raise ContractError(f"workflow_run {key} must equal {expected!r}")
    path = run.get("path")
    if not isinstance(path, str) or path.split("@", 1)[0] != EXPECTED_WORKFLOW_PATH:
        raise ContractError("workflow_run path is not the protected PR gate")
    head_repository = run.get("head_repository")
    if not isinstance(head_repository, Mapping) or head_repository.get("full_name") != expected_repository:
        raise ContractError("workflow_run head repository identity mismatch")
    return require_sha(run.get("head_sha"), "workflow_run head SHA")


def validate_main_run_record(
    run: Mapping[str, object],
    *,
    expected_repository: str,
    expected_run_id: int,
    expected_source_sha: str,
) -> str:
    """Bind a publisher request to one authoritative successful main run."""
    if (
        isinstance(expected_run_id, bool)
        or not isinstance(expected_run_id, int)
        or expected_run_id <= 0
        or run.get("id") != expected_run_id
    ):
        raise ContractError("Actions run ID is not the exact positive requested run ID")
    repository = _object(run.get("repository"), "Actions run repository")
    head_repository = _object(run.get("head_repository"), "Actions run head repository")
    if repository.get("full_name") != expected_repository:
        raise ContractError("Actions run repository identity mismatch")
    if head_repository.get("full_name") != expected_repository:
        raise ContractError("Actions run head repository identity mismatch")
    exact = {
        "name": EXPECTED_WORKFLOW,
        "path": EXPECTED_WORKFLOW_PATH,
        "event": "push",
        "status": "completed",
        "conclusion": "success",
        "head_branch": "main",
    }
    for key, expected in exact.items():
        if run.get(key) != expected:
            raise ContractError(f"Actions run {key} must equal {expected!r}")
    source_sha = require_sha(expected_source_sha, "publisher source SHA")
    if require_sha(run.get("head_sha"), "Actions run head SHA") != source_sha:
        raise ContractError("successful main run does not bind the requested source SHA")
    return source_sha


def validate_publisher(
    root: Path,
    source_sha: str,
    checkout_sha: str,
    ref: str,
    event_name: str,
    repository: str,
    workflow_ref: str,
) -> ReleaseIntent:
    source_sha = require_sha(source_sha, "publisher source SHA")
    checkout_sha = require_sha(checkout_sha, "publisher checkout SHA")
    if event_name != "workflow_dispatch":
        raise ContractError("publisher accepts only explicit workflow_dispatch")
    if ref != "refs/heads/main":
        raise ContractError("publisher workflow must be selected from protected main")
    expected_workflow_ref = f"{repository}/{EXPECTED_PUBLISHER_PATH}@refs/heads/main"
    if workflow_ref != expected_workflow_ref:
        raise ContractError("publisher workflow identity is not protected main")
    if source_sha != checkout_sha:
        raise ContractError("publisher source SHA does not equal the authorized checkout")
    files = {path: (root / path).read_text(encoding="utf-8") for path in ("VERSION", "chart/Chart.yaml", "chart/values.yaml", "CHANGELOG.md")}
    intent = validate_snapshot(files)
    return ReleaseIntent(source_sha=source_sha, version=intent.version)


def _object(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ContractError(f"{field} must be a JSON object")
    return value


def _array(value: object, field: str) -> list[object]:
    if not isinstance(value, list):
        raise ContractError(f"{field} must be a JSON array")
    return value


def _string_set(value: object, field: str) -> set[str]:
    values = _array(value, field)
    if any(not isinstance(item, str) or not item for item in values):
        raise ContractError(f"{field} must contain only non-empty strings")
    result = set(values)
    if len(result) != len(values):
        raise ContractError(f"{field} must not contain duplicates")
    return result


def _status_check_set(value: object) -> set[tuple[str, int]]:
    checks: set[tuple[str, int]] = set()
    values = _array(value, "required status checks")
    for item in values:
        record = _object(item, "required status check")
        if set(record) != {"context", "integration_id"}:
            raise ContractError("required status check fields are missing or foreign")
        context = record.get("context")
        integration_id = record.get("integration_id")
        if not isinstance(context, str) or not context:
            raise ContractError("required status check context must be non-empty")
        if isinstance(integration_id, bool) or not isinstance(integration_id, int):
            raise ContractError("required status check integration_id must be an integer")
        check = (context, integration_id)
        if check in checks:
            raise ContractError("required status checks must not contain duplicates")
        checks.add(check)
    return checks


def validate_settings_receipt(receipt: Mapping[str, object], repository: str) -> None:
    """Validate the closed, value-only release-readiness receipt."""
    fields = {
        "allow_deletions",
        "allow_force_pushes",
        "branch",
        "bypass_actors",
        "immutable_releases",
        "merge_methods",
        "repository",
        "require_linear_history",
        "require_pull_request",
        "required_status_checks",
        "restrict_updates",
        "strict_status_checks",
    }
    if set(receipt) != fields:
        raise ContractError("settings receipt fields are missing or foreign")
    if receipt.get("repository") != repository or receipt.get("branch") != "main":
        raise ContractError("settings receipt repository or branch is not exact")
    if _string_set(receipt.get("merge_methods"), "merge methods") != {"rebase", "squash"}:
        raise ContractError("only squash and rebase merge methods may be enabled")
    expected_checks = {
        (context, GITHUB_ACTIONS_INTEGRATION_ID) for context in REQUIRED_STATUS_CHECKS
    }
    if _status_check_set(receipt.get("required_status_checks")) != expected_checks:
        raise ContractError("required GitHub Actions checks are missing, foreign, or unbound")
    for field, expected in (
        ("immutable_releases", True),
        ("strict_status_checks", True),
        ("require_pull_request", True),
        ("require_linear_history", True),
        ("allow_force_pushes", False),
        ("allow_deletions", False),
        ("restrict_updates", False),
    ):
        if receipt.get(field) is not expected:
            raise ContractError(f"settings receipt {field} must be {expected}")
    if receipt.get("bypass_actors") != []:
        raise ContractError("protected-main rules must have no bypass actors")


def _select_main_ruleset_id(summaries: object, repository: str) -> int:
    candidates: list[Mapping[str, object]] = []
    for value in _array(summaries, "repository rulesets"):
        summary = _object(value, "repository ruleset summary")
        if (
            summary.get("target") == "branch"
            and summary.get("enforcement") == "active"
            and summary.get("source_type") == "Repository"
            and summary.get("source") == repository
        ):
            candidates.append(summary)
    if len(candidates) != 1 or candidates[0].get("name") != EXPECTED_MAIN_RULESET:
        raise ContractError("expected exactly one active repository-owned Protect-Main ruleset")
    ruleset_id = candidates[0].get("id")
    if isinstance(ruleset_id, bool) or not isinstance(ruleset_id, int) or ruleset_id <= 0:
        raise ContractError("Protect-Main ruleset has no authoritative numeric ID")
    return ruleset_id


def build_settings_receipt(
    repository: str,
    repository_record: Mapping[str, object],
    immutable_record: Mapping[str, object],
    ruleset_id: int,
    ruleset_record: Mapping[str, object],
) -> dict[str, object]:
    """Derive and validate a privacy-bounded receipt from authoritative REST."""
    if repository_record.get("full_name") != repository or repository_record.get("default_branch") != "main":
        raise ContractError("repository settings identity or default branch is not exact")
    merge_methods: list[str] = []
    for field, method in (
        ("allow_merge_commit", "merge"),
        ("allow_rebase_merge", "rebase"),
        ("allow_squash_merge", "squash"),
    ):
        enabled = repository_record.get(field)
        if not isinstance(enabled, bool):
            raise ContractError(f"repository setting {field} is not boolean")
        if enabled:
            merge_methods.append(method)
    if not isinstance(immutable_record.get("enabled"), bool) or not isinstance(
        immutable_record.get("enforced_by_owner"), bool
    ):
        raise ContractError("immutable-release settings response is malformed")

    if (
        ruleset_record.get("id") != ruleset_id
        or ruleset_record.get("name") != EXPECTED_MAIN_RULESET
        or ruleset_record.get("target") != "branch"
        or ruleset_record.get("source_type") != "Repository"
        or ruleset_record.get("source") != repository
        or ruleset_record.get("enforcement") != "active"
    ):
        raise ContractError("Protect-Main ruleset identity or enforcement is not exact")
    conditions = _object(ruleset_record.get("conditions"), "Protect-Main conditions")
    if set(conditions) != {"ref_name"}:
        raise ContractError("Protect-Main conditions are missing or foreign")
    ref_name = _object(conditions.get("ref_name"), "Protect-Main ref condition")
    if set(ref_name) != {"exclude", "include"} or ref_name.get("exclude") != [] or ref_name.get(
        "include"
    ) != ["refs/heads/main"]:
        raise ContractError("Protect-Main must target only refs/heads/main")

    bypass = _array(ruleset_record.get("bypass_actors"), "Protect-Main bypass actors")
    rules_by_type: dict[str, Mapping[str, object]] = {}
    for value in _array(ruleset_record.get("rules"), "Protect-Main rules"):
        rule = _object(value, "Protect-Main rule")
        rule_type = rule.get("type")
        if not isinstance(rule_type, str) or not rule_type or rule_type in rules_by_type:
            raise ContractError("Protect-Main rule types must be non-empty and unique")
        rules_by_type[rule_type] = rule

    pull_request = rules_by_type.get("pull_request")
    if pull_request is None:
        raise ContractError("Protect-Main must require pull requests")
    pull_parameters = _object(pull_request.get("parameters"), "pull-request rule parameters")
    allowed_merge_methods = _string_set(
        pull_parameters.get("allowed_merge_methods"), "ruleset merge methods"
    )
    if allowed_merge_methods != set(merge_methods):
        raise ContractError("repository and ruleset merge methods do not match")

    status_rule = rules_by_type.get("required_status_checks")
    if status_rule is None:
        raise ContractError("Protect-Main must require exact status checks")
    status_parameters = _object(status_rule.get("parameters"), "status-check rule parameters")
    if status_parameters.get("do_not_enforce_on_create") is not False:
        raise ContractError("required checks must also apply when the ref is created")
    status_checks = _status_check_set(status_parameters.get("required_status_checks"))

    receipt: dict[str, object] = {
        "repository": repository,
        "branch": "main",
        "merge_methods": sorted(merge_methods),
        "required_status_checks": [
            {"context": context, "integration_id": integration_id}
            for context, integration_id in sorted(status_checks)
        ],
        "strict_status_checks": status_parameters.get("strict_required_status_checks_policy"),
        "require_pull_request": True,
        "require_linear_history": "required_linear_history" in rules_by_type,
        "allow_force_pushes": "non_fast_forward" not in rules_by_type,
        "allow_deletions": "deletion" not in rules_by_type,
        "restrict_updates": "update" in rules_by_type,
        # Do not serialize actor details or ruleset IDs. Presence alone is the
        # safety fact, and the only acceptable value is the empty set.
        "bypass_actors": [] if not bypass else ["present"],
        "immutable_releases": immutable_record.get("enabled"),
    }
    validate_settings_receipt(receipt, repository)
    return receipt


def _github_api_get(endpoint: str, *, paginate: bool = False) -> object:
    command = [
        "gh",
        "api",
        "--method",
        "GET",
        "--header",
        "Accept: application/vnd.github+json",
        "--header",
        f"X-GitHub-Api-Version: {GITHUB_API_VERSION}",
    ]
    if paginate:
        command.extend(("--paginate", "--slurp"))
    command.append(endpoint)
    completed = subprocess.run(
        command,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    )
    if completed.returncode != 0:
        raise ContractError("read-only GitHub settings query failed")
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise ContractError("read-only GitHub settings query returned malformed JSON") from exc
    if not paginate:
        return value
    flattened: list[object] = []
    for page in _array(value, "paginated GitHub settings response"):
        flattened.extend(_array(page, "paginated GitHub settings page"))
    return flattened


def observe_live_settings(repository: str) -> dict[str, object]:
    """Query only GET endpoints and emit a receipt only for exact live state."""
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise ContractError("repository must be an exact owner/name pair")
    repository_record = _object(_github_api_get(f"repos/{repository}"), "repository settings")
    immutable_record = _object(
        _github_api_get(f"repos/{repository}/immutable-releases"),
        "immutable-release settings",
    )
    summaries = _github_api_get(f"repos/{repository}/rulesets", paginate=True)
    ruleset_id = _select_main_ruleset_id(summaries, repository)
    ruleset_record = _object(
        _github_api_get(f"repos/{repository}/rulesets/{ruleset_id}"),
        "Protect-Main ruleset",
    )
    return build_settings_receipt(
        repository,
        repository_record,
        immutable_record,
        ruleset_id,
        ruleset_record,
    )


def _same_instant(actual: object, expected: str, field: str) -> None:
    if not isinstance(actual, str):
        raise ContractError(f"{field} must be an ISO-8601 timestamp")
    try:
        actual_time = dt.datetime.fromisoformat(actual.replace("Z", "+00:00"))
        expected_time = dt.datetime.fromisoformat(expected.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ContractError(f"{field} must be an ISO-8601 timestamp") from exc
    if actual_time.tzinfo is None or expected_time.tzinfo is None or actual_time != expected_time:
        raise ContractError(f"{field} does not equal the deterministic source-commit instant")


def validate_tag_record(
    ref_record: Mapping[str, object],
    tag_record: Mapping[str, object],
    *,
    tag: str,
    source_sha: str,
    message: str,
    tagger_name: str,
    tagger_email: str,
    tagger_date: str,
) -> None:
    """Verify the complete annotated-tag identity created by the orchestrator."""
    source_sha = require_sha(source_sha, "tag target SHA")
    ref_object = _object(ref_record.get("object"), "tag ref object")
    tag_object_sha = require_sha(ref_object.get("sha"), "annotated tag object SHA")
    if ref_record.get("ref") != f"refs/tags/{tag}" or ref_object.get("type") != "tag":
        raise ContractError("tag ref is not the exact annotated tag object")
    if tag_record.get("sha") != tag_object_sha or tag_record.get("tag") != tag:
        raise ContractError("annotated tag object identity does not match its ref")
    target = _object(tag_record.get("object"), "annotated tag target")
    if target.get("type") != "commit" or target.get("sha") != source_sha:
        raise ContractError("annotated tag target is not the exact source commit")
    if tag_record.get("message") != message:
        raise ContractError("annotated tag message is not exact")
    tagger = _object(tag_record.get("tagger"), "annotated tagger")
    if tagger.get("name") != tagger_name or tagger.get("email") != tagger_email:
        raise ContractError("annotated tagger identity violates policy")
    _same_instant(tagger.get("date"), tagger_date, "annotated tagger date")


def validate_release_record(
    release_record: Mapping[str, object], *, tag: str, title: str, body: str
) -> None:
    """Verify exact immutable GitHub Release metadata and a closed empty asset set."""
    if release_record.get("tag_name") != tag or release_record.get("name") != title:
        raise ContractError("GitHub Release tag or title is not exact")
    actual_body = release_record.get("body")
    if not isinstance(actual_body, str) or actual_body.rstrip("\r\n") != body.rstrip("\r\n"):
        raise ContractError("GitHub Release notes are not exact")
    if release_record.get("draft") is not False or release_record.get("prerelease") is not False:
        raise ContractError("GitHub Release must be published and non-prerelease")
    if release_record.get("immutable") is not True:
        raise ContractError("GitHub Release must report authoritative immutable state")
    if release_record.get("assets") != []:
        raise ContractError("GitHub Release asset inventory must be exactly empty")


def classify_tag_state(
    http_status: int,
    ref_record: Mapping[str, object] | None,
    tag_record: Mapping[str, object] | None,
    **expected: str,
) -> str:
    """Classify authoritative REST tag state without requiring a local ref."""
    if http_status == 404:
        if ref_record is not None or tag_record is not None:
            raise ContractError("absent tag state cannot carry tag records")
        return "absent"
    if http_status != 200:
        raise ContractError(f"tag ref probe returned unexpected HTTP {http_status}")
    if ref_record is None or tag_record is None:
        raise ContractError("present tag state requires both REST tag records")
    validate_tag_record(ref_record, tag_record, **expected)
    return "exact"


def classify_release_state(
    http_status: int,
    release_record: Mapping[str, object] | None,
    *,
    tag: str,
    title: str,
    body: str,
) -> str:
    """Classify authoritative REST Release state for create/retry transactions."""
    if http_status == 404:
        if release_record is not None:
            raise ContractError("absent GitHub Release state cannot carry a record")
        return "absent"
    if http_status != 200:
        raise ContractError(f"GitHub Release probe returned unexpected HTTP {http_status}")
    if release_record is None:
        raise ContractError("present GitHub Release state requires its REST record")
    validate_release_record(release_record, tag=tag, title=title, body=body)
    return "exact"


def require_publication_state(actual: str, required: str) -> str:
    """Turn an API classification into a shell-safe exact-state assertion."""
    if required not in {"absent", "exact"} or actual != required:
        raise ContractError(f"publication state {actual!r} does not equal required {required!r}")
    return actual


def build_attestation_statement(
    predicate: Mapping[str, object],
    *,
    image: str,
    digest: str,
    source: str,
    revision: str,
    platform: str,
) -> dict[str, object]:
    """Bind one embedded BuildKit predicate to an exact signed release member."""
    match = DIGEST_RE.fullmatch(digest)
    if not match:
        raise ContractError("attestation subject digest must be sha256:<64 lowercase hex>")
    require_sha(revision, "attestation source revision")
    if not image or "@" in image or not source.startswith("https://github.com/"):
        raise ContractError("attestation image or source identity is malformed")
    if not re.fullmatch(r"linux/[a-z0-9_-]+", platform):
        raise ContractError("attestation platform identity is malformed")

    normalized = copy.deepcopy(dict(predicate))
    build = _object(normalized.get("buildDefinition"), "SLSA buildDefinition")
    run = _object(normalized.get("runDetails"), "SLSA runDetails")
    builder = _object(run.get("builder"), "SLSA builder")
    metadata = _object(run.get("metadata"), "SLSA metadata")
    buildkit = _object(metadata.get("buildkit_metadata"), "BuildKit metadata")
    vcs = _object(buildkit.get("vcs"), "BuildKit vcs metadata")
    if not isinstance(builder.get("id"), str) or not builder["id"].startswith(source + "/actions/runs/"):
        raise ContractError("embedded predicate builder is not this repository's Actions run")
    if vcs.get("source") != source or vcs.get("revision") != revision:
        raise ContractError("embedded predicate source or revision is foreign")

    internal = build.get("internalParameters")
    if internal is None:
        internal = {}
        build["internalParameters"] = internal
    internal = _object(internal, "SLSA internalParameters")
    if "release" in internal:
        raise ContractError("embedded predicate already carries a release binding")
    internal["release"] = {
        "source": source,
        "revision": revision,
        "platform": platform,
    }
    return {
        "_type": INTOTO_STATEMENT_TYPE,
        "subject": [{"name": image, "digest": {"sha256": match.group(1)}}],
        "predicateType": SLSA_PREDICATE_TYPE,
        "predicate": normalized,
    }


def _verified_statements(text: str) -> list[Mapping[str, object]]:
    decoder = json.JSONDecoder()
    values: list[object] = []
    position = 0
    while position < len(text):
        while position < len(text) and text[position].isspace():
            position += 1
        if position == len(text):
            break
        value, position = decoder.raw_decode(text, position)
        values.append(value)
    if len(values) == 1 and isinstance(values[0], list):
        values = values[0]
    statements: list[Mapping[str, object]] = []
    for value in values:
        record = _object(value, "verified cosign record")
        payload = record.get("payload")
        if not isinstance(payload, str):
            raise ContractError("verified cosign record has no signed payload")
        try:
            decoded = base64.b64decode(payload, validate=True).decode("utf-8")
            statement = json.loads(decoded)
        except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ContractError("verified cosign payload is not canonical JSON evidence") from exc
        statements.append(_object(statement, "verified in-toto statement"))
    return statements


def validate_attestation_set(
    verified_output: str, expected_by_platform: Mapping[str, Mapping[str, object]]
) -> int:
    """Accept only the exact authenticated per-platform statement set."""
    if not expected_by_platform:
        raise ContractError("expected attestation platform set is empty")
    statements = _verified_statements(verified_output)
    if len(statements) != len(expected_by_platform):
        raise ContractError("verified attestation count does not equal the required platform set")
    actual: dict[str, Mapping[str, object]] = {}
    for statement in statements:
        predicate = _object(statement.get("predicate"), "verified SLSA predicate")
        build = _object(predicate.get("buildDefinition"), "verified SLSA buildDefinition")
        internal = _object(build.get("internalParameters"), "verified SLSA internalParameters")
        release = _object(internal.get("release"), "verified release binding")
        platform = release.get("platform")
        if not isinstance(platform, str) or platform in actual:
            raise ContractError("verified attestation platform is absent or duplicated")
        actual[platform] = statement
    if set(actual) != set(expected_by_platform):
        raise ContractError("verified attestation platforms are missing or foreign")
    for platform, expected in expected_by_platform.items():
        if actual[platform] != expected:
            raise ContractError(f"verified {platform} subject or predicate is not exact")
    return len(statements)


def classify_artifact(*, present: bool, source_match: bool, signature_match: bool, evidence_count: int, expected_evidence: int) -> str:
    if expected_evidence < 0 or evidence_count < 0:
        raise ContractError("evidence counts cannot be negative")
    if not present:
        if source_match or signature_match or evidence_count:
            raise ContractError("absent artifact cannot carry positive evidence")
        return "absent"
    if source_match and signature_match and evidence_count == expected_evidence:
        return "complete"
    return "burned"


def classify_registry_response(http_status: int) -> str:
    """Distinguish authoritative absence from every fail-closed registry error."""
    if http_status == 200:
        return "present"
    if http_status == 404:
        return "absent"
    raise ContractError(f"registry manifest probe returned unexpected HTTP {http_status}")


def _emit(intent: ReleaseIntent) -> None:
    print(json.dumps({"source_sha": intent.source_sha, "version": str(intent.version), "tag": intent.tag}, sort_keys=True))


def _read_object(path: Path) -> Mapping[str, object]:
    return _object(json.loads(path.read_text(encoding="utf-8")), str(path))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    transition = commands.add_parser("transition")
    transition.add_argument("--repository", type=Path, required=True)
    transition.add_argument("--base", required=True)
    transition.add_argument("--head", required=True)
    transition.add_argument("--first-parent", action="store_true")
    window = commands.add_parser("release-window")
    window.add_argument("--repository", type=Path, required=True)
    window.add_argument("--head", required=True)
    event = commands.add_parser("workflow-run")
    event.add_argument("--event", type=Path, required=True)
    event.add_argument("--repository", required=True)
    main_run = commands.add_parser("main-run-record")
    main_run.add_argument("--run-json", type=Path, required=True)
    main_run.add_argument("--run-id", type=int, required=True)
    main_run.add_argument("--repository", required=True)
    main_run.add_argument("--source-sha", required=True)
    publisher = commands.add_parser("publisher")
    publisher.add_argument("--root", type=Path, required=True)
    publisher.add_argument("--source-sha", required=True)
    publisher.add_argument("--checkout-sha", required=True)
    publisher.add_argument("--ref", required=True)
    publisher.add_argument("--event-name", required=True)
    publisher.add_argument("--repository", required=True)
    publisher.add_argument("--workflow-ref", required=True)
    settings_receipt = commands.add_parser("settings-receipt")
    settings_receipt.add_argument("--receipt", type=Path, required=True)
    settings_receipt.add_argument("--repository", required=True)
    settings_preflight = commands.add_parser("settings-preflight")
    settings_preflight.add_argument("--repository", required=True)
    tag_record = commands.add_parser("tag-record")
    tag_record.add_argument("--ref-json", type=Path, required=True)
    tag_record.add_argument("--tag-json", type=Path, required=True)
    tag_record.add_argument("--tag", required=True)
    tag_record.add_argument("--source-sha", required=True)
    tag_record.add_argument("--message", required=True)
    tag_record.add_argument("--tagger-name", required=True)
    tag_record.add_argument("--tagger-email", required=True)
    tag_record.add_argument("--tagger-date", required=True)
    tag_state = commands.add_parser("tag-state")
    tag_state.add_argument("--http-status", type=int, required=True)
    tag_state.add_argument("--require", choices=("absent", "exact"))
    tag_state.add_argument("--ref-json", type=Path)
    tag_state.add_argument("--tag-json", type=Path)
    tag_state.add_argument("--tag", required=True)
    tag_state.add_argument("--source-sha", required=True)
    tag_state.add_argument("--message", required=True)
    tag_state.add_argument("--tagger-name", required=True)
    tag_state.add_argument("--tagger-email", required=True)
    tag_state.add_argument("--tagger-date", required=True)
    release_record = commands.add_parser("release-record")
    release_record.add_argument("--release-json", type=Path, required=True)
    release_record.add_argument("--tag", required=True)
    release_record.add_argument("--title", required=True)
    release_record.add_argument("--body", type=Path, required=True)
    release_state = commands.add_parser("release-state")
    release_state.add_argument("--http-status", type=int, required=True)
    release_state.add_argument("--require", choices=("absent", "exact"))
    release_state.add_argument("--release-json", type=Path)
    release_state.add_argument("--tag", required=True)
    release_state.add_argument("--title", required=True)
    release_state.add_argument("--body", type=Path, required=True)
    statement = commands.add_parser("attestation-statement")
    statement.add_argument("--predicate", type=Path, required=True)
    statement.add_argument("--output", type=Path, required=True)
    statement.add_argument("--image", required=True)
    statement.add_argument("--digest", required=True)
    statement.add_argument("--source", required=True)
    statement.add_argument("--revision", required=True)
    statement.add_argument("--platform", required=True)
    attestations = commands.add_parser("attestation-set")
    attestations.add_argument("--verified", type=Path, required=True)
    attestations.add_argument("--expected", action="append", required=True)
    artifact = commands.add_parser("artifact-state")
    artifact.add_argument("--present", choices=("true", "false"), required=True)
    artifact.add_argument("--source-match", choices=("true", "false"), required=True)
    artifact.add_argument("--signature-match", choices=("true", "false"), required=True)
    artifact.add_argument("--evidence-count", type=int, required=True)
    artifact.add_argument("--expected-evidence", type=int, required=True)
    registry = commands.add_parser("registry-state")
    registry.add_argument("--http-status", type=int, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "transition":
            _emit(validate_transition(args.repository, args.base, args.head, first_parent=args.first_parent))
        elif args.command == "release-window":
            window = discover_transition_window(args.repository, args.head)
            print(
                json.dumps(
                    {
                        "base_sha": window.base_sha,
                        "source_sha": window.intent.source_sha,
                        "version": str(window.intent.version),
                        "tag": window.intent.tag,
                    },
                    sort_keys=True,
                )
            )
        elif args.command == "workflow-run":
            event = json.loads(args.event.read_text(encoding="utf-8"))
            print(plan_workflow_run(event, args.repository))
        elif args.command == "main-run-record":
            print(
                validate_main_run_record(
                    _read_object(args.run_json),
                    expected_repository=args.repository,
                    expected_run_id=args.run_id,
                    expected_source_sha=args.source_sha,
                )
            )
        elif args.command == "publisher":
            _emit(
                validate_publisher(
                    args.root,
                    args.source_sha,
                    args.checkout_sha,
                    args.ref,
                    args.event_name,
                    args.repository,
                    args.workflow_ref,
                )
            )
        elif args.command == "settings-receipt":
            validate_settings_receipt(_read_object(args.receipt), args.repository)
            print("exact")
        elif args.command == "settings-preflight":
            print(json.dumps(observe_live_settings(args.repository), indent=2, sort_keys=True))
        elif args.command == "tag-record":
            validate_tag_record(
                _read_object(args.ref_json),
                _read_object(args.tag_json),
                tag=args.tag,
                source_sha=args.source_sha,
                message=args.message,
                tagger_name=args.tagger_name,
                tagger_email=args.tagger_email,
                tagger_date=args.tagger_date,
            )
            print("exact")
        elif args.command == "tag-state":
            state = classify_tag_state(
                args.http_status,
                _read_object(args.ref_json) if args.ref_json else None,
                _read_object(args.tag_json) if args.tag_json else None,
                tag=args.tag,
                source_sha=args.source_sha,
                message=args.message,
                tagger_name=args.tagger_name,
                tagger_email=args.tagger_email,
                tagger_date=args.tagger_date,
            )
            print(require_publication_state(state, args.require) if args.require else state)
        elif args.command == "release-record":
            validate_release_record(
                _read_object(args.release_json),
                tag=args.tag,
                title=args.title,
                body=args.body.read_text(encoding="utf-8"),
            )
            print("exact")
        elif args.command == "release-state":
            state = classify_release_state(
                args.http_status,
                _read_object(args.release_json) if args.release_json else None,
                tag=args.tag,
                title=args.title,
                body=args.body.read_text(encoding="utf-8"),
            )
            print(require_publication_state(state, args.require) if args.require else state)
        elif args.command == "attestation-statement":
            statement = build_attestation_statement(
                _read_object(args.predicate),
                image=args.image,
                digest=args.digest,
                source=args.source,
                revision=args.revision,
                platform=args.platform,
            )
            args.output.write_text(json.dumps(statement, sort_keys=True) + "\n", encoding="utf-8")
        elif args.command == "attestation-set":
            expected: dict[str, Mapping[str, object]] = {}
            for item in args.expected:
                platform, separator, raw_path = item.partition("=")
                if not separator or not platform or platform in expected:
                    raise ContractError("expected attestation arguments must be unique platform=path pairs")
                expected[platform] = _read_object(Path(raw_path))
            print(validate_attestation_set(args.verified.read_text(encoding="utf-8"), expected))
        elif args.command == "artifact-state":
            state = classify_artifact(
                present=args.present == "true",
                source_match=args.source_match == "true",
                signature_match=args.signature_match == "true",
                evidence_count=args.evidence_count,
                expected_evidence=args.expected_evidence,
            )
            print(state)
            if state == "burned":
                return 1
        elif args.command == "registry-state":
            print(classify_registry_response(args.http_status))
        else:  # pragma: no cover - argparse owns this path
            raise ContractError("unknown command")
    except (ContractError, OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        print(f"DENY: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
