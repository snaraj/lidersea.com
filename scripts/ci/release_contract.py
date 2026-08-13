#!/usr/bin/env python3
"""Fail-closed release identity and GitHub event policy.

This module is intentionally standard-library only.  CI and its hostile tests
use the same functions, so event, version, and immutable-artifact decisions
cannot drift into prose-only conventions.
"""

from __future__ import annotations

import argparse
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


def validate_transition(repository: Path, base_sha: str, head_sha: str, *, first_parent: bool) -> ReleaseIntent:
    base_sha = require_sha(base_sha, "base SHA")
    head_sha = require_sha(head_sha, "head SHA")
    if _git(repository, "rev-parse", f"{base_sha}^{{commit}}") != base_sha:
        raise ContractError("base SHA did not resolve exactly")
    if _git(repository, "rev-parse", f"{head_sha}^{{commit}}") != head_sha:
        raise ContractError("head SHA did not resolve exactly")
    if first_parent:
        if _git(repository, "rev-parse", f"{head_sha}^1") != base_sha:
            raise ContractError("main release base must be the head commit's first parent")
        if _git(repository, "rev-list", "--first-parent", "--count", f"{base_sha}..{head_sha}") != "1":
            raise ContractError("one main publication event must cover exactly one first-parent commit")
    else:
        _git(repository, "merge-base", "--is-ancestor", base_sha, head_sha)

    base_version = Version.parse(_git_file(repository, base_sha, "VERSION"))
    head_files = {
        path: _git_file(repository, head_sha, path)
        for path in ("VERSION", "chart/Chart.yaml", "chart/values.yaml", "CHANGELOG.md")
    }
    head = validate_snapshot(head_files)
    require_next_patch(base_version, head.version)
    return ReleaseIntent(source_sha=head_sha, version=head.version)


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


def validate_publisher(root: Path, source_sha: str, github_sha: str, ref: str, event_name: str) -> ReleaseIntent:
    source_sha = require_sha(source_sha, "publisher source SHA")
    github_sha = require_sha(github_sha, "publisher GitHub SHA")
    if event_name != "workflow_dispatch":
        raise ContractError("publisher accepts only explicit workflow_dispatch")
    if source_sha != github_sha:
        raise ContractError("publisher source SHA does not equal checked-out tag commit")
    files = {path: (root / path).read_text(encoding="utf-8") for path in ("VERSION", "chart/Chart.yaml", "chart/values.yaml", "CHANGELOG.md")}
    intent = validate_snapshot(files)
    if ref != f"refs/tags/{intent.tag}":
        raise ContractError("publisher ref is not the exact plain semantic version tag")
    return ReleaseIntent(source_sha=source_sha, version=intent.version)


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


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    transition = commands.add_parser("transition")
    transition.add_argument("--repository", type=Path, required=True)
    transition.add_argument("--base", required=True)
    transition.add_argument("--head", required=True)
    transition.add_argument("--first-parent", action="store_true")
    event = commands.add_parser("workflow-run")
    event.add_argument("--event", type=Path, required=True)
    event.add_argument("--repository", required=True)
    publisher = commands.add_parser("publisher")
    publisher.add_argument("--root", type=Path, required=True)
    publisher.add_argument("--source-sha", required=True)
    publisher.add_argument("--github-sha", required=True)
    publisher.add_argument("--ref", required=True)
    publisher.add_argument("--event-name", required=True)
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
        elif args.command == "workflow-run":
            event = json.loads(args.event.read_text(encoding="utf-8"))
            print(plan_workflow_run(event, args.repository))
        elif args.command == "publisher":
            _emit(validate_publisher(args.root, args.source_sha, args.github_sha, args.ref, args.event_name))
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
    except (ContractError, OSError, json.JSONDecodeError) as exc:
        print(f"DENY: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
