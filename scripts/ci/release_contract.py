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
import hashlib
import json
import os
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
EXPECTED_CODEQL_WORKFLOW = "CodeQL"
EXPECTED_CODEQL_WORKFLOW_PATH = ".github/workflows/codeql.yml"
EXPECTED_PUBLISHER_PATH = ".github/workflows/release-publisher.yml"
# cosign's attest.go signs via --predicate/--type, never --statement (dead on
# image attest in every checked release). A --type value that is a URI takes
# the generateCustomStatement path, which embeds the predicate verbatim and
# always stamps this exact literal _type — not the newer
# https://in-toto.io/Statement/v1 this repository does not control.
INTOTO_STATEMENT_TYPE = "https://in-toto.io/Statement/v0.1"
SLSA_PREDICATE_TYPE = "https://slsa.dev/provenance/v1"
SPDX_PREDICATE_TYPE = "https://spdx.dev/Document"
DIGEST_RE = re.compile(r"^sha256:([0-9a-f]{64})$")
# A GitHub Actions run ID as the API and the runner environment spell it:
# a positive decimal with no sign, padding, separator, or whitespace.
ACTIONS_RUN_ID_RE = re.compile(r"[1-9][0-9]*")
# BuildKit's GitHub Actions provenance ALWAYS stamps the attempt: it builds
# runDetails.builder.id as
#   <server>/<owner>/<repo>/actions/runs/<GITHUB_RUN_ID>/attempts/<GITHUB_RUN_ATTEMPT>
# Measured on this repository's own published images (v0.1.24, v0.1.27,
# v0.1.28, v0.1.29, v0.1.30 -- both linux/amd64 and linux/arm64), every
# builder ID carries the suffix and every run ID equals the publisher run
# that built those bytes. The attempt is therefore REQUIRED, not optional:
# a builder ID without it is not something BuildKit emits here and is
# denied. The attempt NUMBER stays a pattern rather than a bound value
# because GitHub's "re-run" recovery keeps GITHUB_RUN_ID and only
# increments the attempt -- the run is the identity this binds, and a
# later attempt of the same run is still that run.
BUILDER_ATTEMPT_SUFFIX = r"/attempts/[1-9][0-9]*"
# The COMMITTED chart keeps this all-zeros digest forever: no registry can
# resolve it, so a chart that reached a cluster without the publisher's
# substitution fails closed at pull time instead of running unidentified bytes.
# Only the PACKAGED artifact carries a real digest, embedded by the publisher
# from the one image digest that the Trivy HIGH/CRITICAL gate, cosign signing,
# and the SLSA/SPDX attestations already accepted (ADR 0016 step 1).
CHART_IMAGE_DIGEST_SENTINEL = "sha256:" + "0" * 64
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
RELEASE_MANIFEST_SCHEMA = "lidersea.release-manifest/v1"
RELEASE_MANIFEST_NAME = "release-manifest.json"
EXPECTED_REPOSITORY = "snaraj/lidersea.com"
EXPECTED_IMAGE = "ghcr.io/snaraj/lidersea-com"
EXPECTED_CHART = "ghcr.io/snaraj/charts/lidersea-com"
GITHUB_ACTIONS_BOT_LOGIN = "github-actions[bot]"
GITHUB_ACTIONS_BOT_ID = 41898282
COSIGN_ISSUER = "https://token.actions.githubusercontent.com"
RELEASE_PLATFORMS = ("linux/amd64", "linux/arm64")
# The exact conclusion every PR-gate job reports on a PROTECTED-MAIN push, and
# the count is a closed six. `container` and `dependency-review` are the two
# `pull_request`-only jobs, so on a push they report `skipped` and the inventory
# requires precisely that: a `success` for either one means the PR-only
# condition was dropped from the workflow and the identical merged tree was
# rebuilt after merge authority had already been exercised. Both remain REQUIRED
# pull-request checks in the protected-main ruleset (REQUIRED_STATUS_CHECKS
# above) — skipping on the push does not relax what must pass before a merge.
PR_GATE_MAIN_JOBS = {
    "application": "success",
    "chart": "success",
    "container": "skipped",
    "coverage-badges": "success",
    "dependency-review": "skipped",
    "security": "success",
}
CODEQL_MAIN_JOBS = {
    "analyze (go, manual)": "success",
    "analyze (javascript-typescript, none)": "success",
}


class ContractError(ValueError):
    """A release input cannot satisfy the immutable publication contract."""


def _reject_duplicate_members(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Reject duplicate object members recursively at every JSON boundary."""
    value: dict[str, object] = {}
    for key, member in pairs:
        if key in value:
            raise ContractError(f"duplicate JSON member {key!r}")
        value[key] = member
    return value


def _reject_nonfinite_constant(raw: str) -> object:
    raise ContractError(f"non-finite JSON constant {raw!r} is forbidden")


def parse_json(text: str, field: str) -> object:
    """Decode one strict JSON value with recursive duplicate-member denial."""
    try:
        return json.loads(
            text,
            object_pairs_hook=_reject_duplicate_members,
            parse_constant=_reject_nonfinite_constant,
        )
    except json.JSONDecodeError as exc:
        raise ContractError(f"{field} is malformed JSON") from exc


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


def _direct_child_entries(text: str, parent: str, key: str) -> list[tuple[int, str]]:
    """Locate every direct child scalar of one top-level mapping, by line."""
    parents = [index for index, line in enumerate(text.splitlines()) if line.rstrip() == f"{parent}:"]
    if len(parents) != 1:
        raise ContractError(f"expected exactly one top-level {parent!r} mapping")
    lines = text.splitlines()
    entries: list[tuple[int, str]] = []
    for offset, line in enumerate(lines[parents[0] + 1 :], start=parents[0] + 1):
        if line and not line[0].isspace() and not line.lstrip().startswith("#"):
            break
        if line.startswith(f"  {key}:"):
            entries.append((offset, line.split(":", 1)[1].strip().strip("\"'")))
    return entries


def _direct_child_entry(text: str, parent: str, key: str) -> tuple[int, str]:
    entries = _direct_child_entries(text, parent, key)
    if len(entries) != 1 or not entries[0][1]:
        raise ContractError(f"expected exactly one non-empty {parent}.{key} scalar")
    return entries[0]


def _direct_child_scalar(text: str, parent: str, key: str) -> str:
    return _direct_child_entry(text, parent, key)[1]


#: One dated release heading in the Keep a Changelog file. The date group is
#: shape-only: `dt.date.fromisoformat` decides whether it is a real calendar
#: date, so 2026-02-31 parses here and is refused below.
CHANGELOG_RELEASE_RE = re.compile(
    r"^## \[(?P<version>[0-9]+\.[0-9]+\.[0-9]+)\] - (?P<date>[0-9]{4}-[0-9]{2}-[0-9]{2})$",
    re.MULTILINE,
)

#: What an author must do instead of editing a section that already shipped.
#: It is printed by every append-only refusal, because a refusal that does not
#: name the sanctioned path teaches the reader to look for a way around it.
CHANGELOG_ERRATUM_INSTRUCTION = (
    "CHANGELOG.md is the human-readable half of the release ledger and its "
    "released sections are APPEND-ONLY: a new version block goes above the "
    "newest released heading and nothing at or below that heading may change. "
    "Correct a shipped entry by writing a NEW erratum entry under the version "
    "this range releases — naming the release it corrects — never by editing "
    "the section that already shipped. Restore the released bytes exactly and "
    "move the correction into the new block."
)


@dataclass(frozen=True)
class ChangelogRelease:
    """One dated release heading and where it starts in the file."""

    version: Version
    date: dt.date
    start: int


def parse_changelog_releases(text: str) -> list[ChangelogRelease]:
    """Return every dated release heading, in the order the file lists them."""
    releases: list[ChangelogRelease] = []
    for match in CHANGELOG_RELEASE_RE.finditer(text):
        version = Version.parse(match.group("version"))
        try:
            date = dt.date.fromisoformat(match.group("date"))
        except ValueError as exc:
            raise ContractError(
                f"changelog release {version} is dated {match.group('date')!r}, "
                "which is not a real ISO date"
            ) from exc
        releases.append(ChangelogRelease(version=version, date=date, start=match.start()))
    return releases


def validate_changelog_history(text: str) -> list[ChangelogRelease]:
    """Refuse a changelog whose released headings are not one descending ledger.

    Shape only: duplicates, a reordered pair, and a historical date that
    postdates a newer release all deny here, on any single snapshot. It cannot
    see a DELETED heading — nothing in one file says what used to be in it —
    which is why `require_changelog_append_only` compares base to head.
    """
    releases = parse_changelog_releases(text)
    if not releases:
        raise ContractError("changelog carries no dated release heading")
    previous = releases[0]
    for entry in releases[1:]:
        if entry.version == previous.version:
            raise ContractError(
                f"changelog lists release {entry.version} more than once"
            )
        if entry.version > previous.version:
            raise ContractError(
                f"changelog release {entry.version} appears below the older "
                f"{previous.version}; released headings read newest first"
            )
        if entry.date > previous.date:
            raise ContractError(
                f"changelog release {entry.version} is dated {entry.date}, after "
                f"the newer {previous.version} dated {previous.date}"
            )
        previous = entry
    return releases


def released_changelog_history(text: str) -> str:
    """Return the exact bytes a released changelog may never change again.

    Everything from the NEWEST dated heading to end of file: every released
    section plus any undated tail block below them, which is equally released
    history. An empty result means nothing has been released yet.
    """
    releases = parse_changelog_releases(text)
    if not releases:
        return ""
    return text[releases[0].start :]


def _changelog_sections(text: str) -> dict[Version, str]:
    """Map each dated release to its bytes, for refusal diagnostics only.

    The OLDEST section runs to end of file, so an edit to an undated tail
    block ("## [0.1.3] and earlier") is reported against the oldest dated
    release. That is a message-precision detail: the byte comparison in
    `require_changelog_append_only` covers those bytes either way.
    """
    releases = parse_changelog_releases(text)
    sections: dict[Version, str] = {}
    for index, entry in enumerate(releases):
        end = releases[index + 1].start if index + 1 < len(releases) else len(text)
        sections[entry.version] = text[entry.start : end]
    return sections


def require_changelog_append_only(base_text: str, head_text: str) -> None:
    """Refuse any head that rewrites changelog history the base already shipped.

    The whole property is one byte comparison: the base's released history —
    its newest dated heading through end of file — must survive in the head as
    an exact SUFFIX. That admits exactly one edit shape, inserting above the
    newest released heading, and refuses every other: a deleted heading, a
    reworded historical entry, a mutated historical date, a reordered pair, and
    a new block spliced in below the top. The per-section comparison below
    exists only to say WHICH release was disturbed.
    """
    history = released_changelog_history(base_text)
    if not history:
        return  # nothing has been released yet, so there is no history to keep
    if head_text.endswith(history):
        return
    base_sections = _changelog_sections(base_text)
    head_sections = _changelog_sections(head_text)
    removed = sorted(
        (version for version in base_sections if version not in head_sections),
        reverse=True,
    )
    mutated = sorted(
        (
            version
            for version, section in base_sections.items()
            if version in head_sections and head_sections[version] != section
        ),
        reverse=True,
    )
    if history in head_text:
        # Every shipped byte is still present, in order, but no longer at the
        # end: something was written BELOW the released history. A merely
        # "contains" check would accept this, which is why the test above is a
        # suffix — a version block invented under the oldest release is as much
        # a forged ledger as a deleted one.
        finding = (
            "content was appended below the released history, which must stay "
            "the tail of the file"
        )
    elif removed:
        finding = "released changelog sections deleted: " + ", ".join(
            str(version) for version in removed
        )
    elif mutated:
        finding = "released changelog sections rewritten: " + ", ".join(
            str(version) for version in mutated
        )
    else:
        # Every released section kept its own bytes, so the break is positional:
        # something was inserted or reordered inside the released history.
        finding = (
            "released changelog history was reordered, or a section was inserted "
            "below the newest released heading"
        )
    raise ContractError(f"{finding}. {CHANGELOG_ERRATUM_INSTRUCTION}")


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
    # Everything above reads the CURRENT version's heading only, so every
    # heading below the first was unguarded: a snapshot could repeat, reorder,
    # or misdate its own history and still validate.
    releases = validate_changelog_history(files["CHANGELOG.md"])
    if releases[0].version != version:
        raise ContractError(
            f"changelog's newest release is {releases[0].version}, not the "
            f"released {version}"
        )
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


def _optional_git_file(repository: Path, revision: str, path: str) -> str | None:
    completed = subprocess.run(
        ["git", "-C", str(repository), "show", f"{revision}:{path}"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    )
    if completed.returncode != 0:
        return None
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


def validate_version_states(
    states: list[tuple[str, Version]], *, exact_boundaries: int | None
) -> list[str]:
    """Validate a retain-or-one-patch machine and return its boundary commits."""
    if not states:
        raise ContractError("VERSION state machine has no states")
    boundaries: list[str] = []
    previous = states[0][1]
    for commit, current in states[1:]:
        if current == previous:
            continue
        expected = Version(previous.major, previous.minor, previous.patch + 1)
        if current < previous:
            raise ContractError(
                f"VERSION reversion at {commit}: {previous} -> {current}"
            )
        if current != expected:
            raise ContractError(
                f"VERSION skip or future value at {commit}: "
                f"{previous} -> {current}; expected {expected}"
            )
        boundaries.append(commit)
        previous = current
    if exact_boundaries is not None and len(boundaries) != exact_boundaries:
        raise ContractError(
            f"VERSION range must contain exactly {exact_boundaries} one-patch "
            f"boundary; found {len(boundaries)}"
        )
    return boundaries


DOCUMENTATION_FILES = frozenset({"AGENTS.md", "README.md", ".gitignore"})
DOCUMENTATION_TREE = "docs/"
RELEASE_LOCK_PATHS = ("VERSION", "chart/Chart.yaml", "chart/values.yaml", "CHANGELOG.md")
_DOCUMENTATION_DIFF_MODES = frozenset({"000000", "100644", "100755"})
_DOCUMENTATION_DIFF_STATUSES = frozenset({"A", "D", "M"})


def is_documentation_path(path: str) -> bool:
    """Classify one repo-relative path as documentation-only surface.

    The allowlist is deliberately closed: root AGENTS.md, README.md, and
    .gitignore, plus Markdown files under docs/. Everything else — release
    locks, scripts, workflows, application and chart trees, LICENSE — is an
    artifact surface, so widening this set is itself a released gate change.
    """
    if path in DOCUMENTATION_FILES:
        return True
    return path.startswith(DOCUMENTATION_TREE) and path.endswith(".md")


def _diff_entries(repository: Path, base: str, commit: str) -> list[tuple[str, str, str, str]]:
    """Return (src_mode, dst_mode, status, path) for one commit-over-base diff."""
    completed = subprocess.run(
        ["git", "-C", str(repository), "diff", "--raw", "-z", "--no-renames", "--no-color", base, commit],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if completed.returncode != 0:
        raise ContractError(f"git diff walk failed between {base} and {commit}")
    try:
        raw = completed.stdout.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ContractError(f"diff between {base} and {commit} carries undecodable paths") from exc
    fields = raw.split("\0")
    if fields and fields[-1] == "":
        fields.pop()
    if len(fields) % 2 != 0:
        raise ContractError(f"diff between {base} and {commit} is not meta/path paired")
    entries: list[tuple[str, str, str, str]] = []
    for meta, path in zip(fields[0::2], fields[1::2]):
        # --no-renames guarantees two-field records; an R/C record would
        # carry a second path and silently shift this pairing, so the meta
        # shape is pinned strictly enough that any such record denies.
        if not re.fullmatch(r":[0-7]{6} [0-7]{6} [0-9a-f]{7,64} [0-9a-f]{7,64} [ACDMTUX]", meta) or not path:
            raise ContractError(f"diff entry between {base} and {commit} is malformed")
        parts = meta.split(" ")
        entries.append((parts[0][1:], parts[1], parts[4], path))
    return entries


def _undocumented_paths(repository: Path, base: str, commit: str) -> list[str]:
    """Return every changed path that is not a plain-file documentation edit."""
    offending: list[str] = []
    for src_mode, dst_mode, status, path in _diff_entries(repository, base, commit):
        if status not in _DOCUMENTATION_DIFF_STATUSES:
            offending.append(path)
            continue
        if src_mode not in _DOCUMENTATION_DIFF_MODES or dst_mode not in _DOCUMENTATION_DIFF_MODES:
            offending.append(path)
            continue
        if not is_documentation_path(path):
            offending.append(path)
    return offending


def classify_transition(repository: Path, base_sha: str, head_sha: str, *, first_parent: bool) -> dict[str, object]:
    """Classify one protected range as artifact or no-artifact, fail closed.

    Any path anywhere in the range outside the documentation allowlist puts
    the whole range under the unchanged one-exact-patch release contract via
    ``validate_transition``. Only a range whose every commit is individually
    confined to documentation surfaces — so the artifact cannot have changed —
    classifies as no-artifact, and even then every release lock must be
    byte-identical from base to head and the retained head snapshot must
    still validate. There is no flag, environment variable, or third verdict.
    """
    base_sha = require_sha(base_sha, "base SHA")
    head_sha = require_sha(head_sha, "head SHA")
    if _git(repository, "rev-parse", f"{base_sha}^{{commit}}") != base_sha:
        raise ContractError("base SHA did not resolve exactly")
    if _git(repository, "rev-parse", f"{head_sha}^{{commit}}") != head_sha:
        raise ContractError("head SHA did not resolve exactly")
    commits = _linear_commits(repository, base_sha, head_sha)
    offending: list[str] = []
    previous = base_sha
    for commit in commits:
        offending.extend(_undocumented_paths(repository, previous, commit))
        previous = commit
    if offending:
        states = [(base_sha, Version.parse(_git_file(repository, base_sha, "VERSION")))]
        states.extend(
            (commit, Version.parse(_git_file(repository, commit, "VERSION")))
            for commit in commits
        )
        if not validate_version_states(states, exact_boundaries=None):
            raise ContractError(
                "artifact-surface paths changed without one exact release patch: "
                + ", ".join(sorted(set(offending))[:8])
            )
        intent = validate_transition(repository, base_sha, head_sha, first_parent=first_parent)
        return {
            "class": "artifact",
            "base_sha": base_sha,
            "source_sha": intent.source_sha,
            "version": str(intent.version),
            "tag": intent.tag,
        }
    states = [(base_sha, Version.parse(_git_file(repository, base_sha, "VERSION")))]
    states.extend(
        (commit, Version.parse(_git_file(repository, commit, "VERSION")))
        for commit in commits
    )
    validate_version_states(states, exact_boundaries=0)
    for path in RELEASE_LOCK_PATHS:
        if _git_file(repository, base_sha, path) != _git_file(repository, head_sha, path):
            raise ContractError(f"documentation-only range mutated release lock {path}")
    head_files = {
        path: _git_file(repository, head_sha, path) for path in RELEASE_LOCK_PATHS
    }
    retained = validate_snapshot(head_files)
    return {
        "class": "no-artifact",
        "base_sha": base_sha,
        "source_sha": head_sha,
        "version": str(retained.version),
        "tag": retained.tag,
        "commits": len(commits),
    }


def validate_transition(repository: Path, base_sha: str, head_sha: str, *, first_parent: bool) -> ReleaseIntent:
    base_sha = require_sha(base_sha, "base SHA")
    head_sha = require_sha(head_sha, "head SHA")
    if _git(repository, "rev-parse", f"{base_sha}^{{commit}}") != base_sha:
        raise ContractError("base SHA did not resolve exactly")
    if _git(repository, "rev-parse", f"{head_sha}^{{commit}}") != head_sha:
        raise ContractError("head SHA did not resolve exactly")
    commits = _linear_commits(repository, base_sha, head_sha)
    base_version = Version.parse(_git_file(repository, base_sha, "VERSION"))
    states = [(base_sha, base_version)]
    states.extend(
        (commit, Version.parse(_git_file(repository, commit, "VERSION")))
        for commit in commits
    )
    validate_version_states(states, exact_boundaries=1)
    head_files = {
        path: _git_file(repository, head_sha, path)
        for path in ("VERSION", "chart/Chart.yaml", "chart/values.yaml", "CHANGELOG.md")
    }
    head = validate_snapshot(head_files)
    # Only a base-to-head comparison can prove the changelog is append-only:
    # the head snapshot alone cannot say what the base already published, so a
    # range that deletes or rewrites a released section satisfies every other
    # check in this module.
    require_changelog_append_only(
        _git_file(repository, base_sha, "CHANGELOG.md"), head_files["CHANGELOG.md"]
    )
    # The endpoint check remains a useful independent assertion, while the
    # shared state machine above also examines every intermediate commit.
    require_next_patch(base_version, head.version)
    return ReleaseIntent(source_sha=head_sha, version=head.version)


def discover_transition_window(repository: Path, head_sha: str) -> TransitionWindow:
    """Recover the latest release boundary only after validating full history."""
    head_sha = require_sha(head_sha, "head SHA")
    if _git(repository, "rev-parse", f"{head_sha}^{{commit}}") != head_sha:
        raise ContractError("head SHA did not resolve exactly")
    raw_history = _git(repository, "rev-list", "--first-parent", "--reverse", head_sha)
    history = raw_history.splitlines() if raw_history else []
    states: list[tuple[str, Version]] = []
    version_seen = False
    for commit in history:
        raw_version = _optional_git_file(repository, commit, "VERSION")
        if raw_version is None:
            if version_seen:
                raise ContractError(f"VERSION disappeared after initialization at {commit}")
            continue
        version_seen = True
        states.append((commit, Version.parse(raw_version)))
    boundaries = validate_version_states(states, exact_boundaries=None)
    if not boundaries:
        raise ContractError("no recoverable one-patch VERSION boundary exists")
    boundary = boundaries[-1]
    fields = _git(repository, "rev-list", "--parents", "-n", "1", boundary).split()
    if len(fields) < 2 or fields[0] != boundary:
        raise ContractError("latest VERSION boundary has no first-parent base")
    base_sha = fields[1]
    intent = validate_transition(repository, base_sha, head_sha, first_parent=True)
    return TransitionWindow(base_sha=base_sha, intent=intent)


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


def validate_review_receipt(text: str, *, expected_head: str, role: str) -> str:
    """Validate exact-head textual receipts without inventing GitHub principals."""
    expected_head = require_sha(expected_head, "receipt head SHA")
    lines = text.splitlines()
    if role == "adversarial":
        if len(lines) < 3 or lines[0] != f"HEAD: {expected_head}":
            raise ContractError("adversarial receipt HEAD is absent or stale")
        if lines[1] not in {"VERDICT: APPROVE", "VERDICT: REQUEST-CHANGES"}:
            raise ContractError("adversarial receipt VERDICT syntax is not canonical")
        if sum(line.startswith("HEAD:") for line in lines) != 1 or sum(
            line.startswith("VERDICT:") for line in lines
        ) != 1:
            raise ContractError("adversarial receipt headers must occur exactly once")
        if sum(line.startswith("Mutation audit:") for line in lines) != 1 or sum(
            line.startswith("Claim audit:") for line in lines
        ) != 1:
            raise ContractError(
                "adversarial receipt must report exactly one mutation and claim audit"
            )
        signature = re.fullmatch(
            r"- ([A-Za-z0-9][A-Za-z0-9 ._-]{0,63}) \(adversarial reviewer\)",
            lines[-1],
        )
        if signature is None or signature.group(1) in {"Agent", "distinct context"}:
            raise ContractError("adversarial receipt signature is not distinct or bounded")
        return lines[1][len("VERDICT: ") :]
    # `adversarial` is the only receipt role: that APPROVE at the exact final
    # head, plus green required checks, is the complete review evidence before
    # the coordinator flips Ready. Any other role is refused rather than
    # defaulted.
    raise ContractError("receipt role must be adversarial")


def _positive_actions_id(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ContractError(f"{field} must be a positive integer")
    return value


def _validate_actions_run_identity(
    run: Mapping[str, object],
    *,
    expected_repository: str,
    expected_run_id: int,
    expected_source_sha: str,
    expected_name: str,
    expected_path: str,
) -> str:
    """Bind an Actions record to one exact workflow, repository, and main SHA."""
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
        "name": expected_name,
        "path": expected_path,
        "event": "push",
        "head_branch": "main",
    }
    for key, expected in exact.items():
        if run.get(key) != expected:
            raise ContractError(f"Actions run {key} must equal {expected!r}")
    source_sha = require_sha(expected_source_sha, "publisher source SHA")
    if require_sha(run.get("head_sha"), "Actions run head SHA") != source_sha:
        raise ContractError("successful main run does not bind the requested source SHA")
    return source_sha


def _require_completed_success(run: Mapping[str, object], label: str) -> None:
    if run.get("status") != "completed":
        raise ContractError(f"{label} status must equal 'completed'")
    if run.get("conclusion") != "success":
        raise ContractError(f"{label} conclusion must equal 'success'")


def validate_main_run_record(
    run: Mapping[str, object],
    *,
    expected_repository: str,
    expected_run_id: int,
    expected_source_sha: str,
) -> str:
    """Bind a publisher request to one authoritative successful PR-gate run."""
    source_sha = _validate_actions_run_identity(
        run,
        expected_repository=expected_repository,
        expected_run_id=expected_run_id,
        expected_source_sha=expected_source_sha,
        expected_name=EXPECTED_WORKFLOW,
        expected_path=EXPECTED_WORKFLOW_PATH,
    )
    _require_completed_success(run, "PR-gate main run")
    return source_sha


def validate_codeql_run_record(
    run: Mapping[str, object],
    *,
    expected_repository: str,
    expected_run_id: int,
    expected_source_sha: str,
) -> str:
    """Bind publication to one completed successful exact-SHA CodeQL main run."""
    source_sha = _validate_actions_run_identity(
        run,
        expected_repository=expected_repository,
        expected_run_id=expected_run_id,
        expected_source_sha=expected_source_sha,
        expected_name=EXPECTED_CODEQL_WORKFLOW,
        expected_path=EXPECTED_CODEQL_WORKFLOW_PATH,
    )
    _require_completed_success(run, "CodeQL main run")
    return source_sha


def _paginated_records(value: object, member: str, field: str) -> list[Mapping[str, object]]:
    """Flatten a complete ``gh api --paginate --slurp`` response exactly."""
    pages = _array(value, f"{field} pages")
    records: list[Mapping[str, object]] = []
    total_counts: list[int] = []
    for index, raw_page in enumerate(pages):
        page = _object(raw_page, f"{field} page {index}")
        total = page.get("total_count")
        if isinstance(total, bool) or not isinstance(total, int) or total < 0:
            raise ContractError(f"{field} page total_count is malformed")
        total_counts.append(total)
        for item in _array(page.get(member), f"{field} page {member}"):
            records.append(_object(item, f"{field} record"))
    if total_counts and (
        len(set(total_counts)) != 1 or total_counts[0] != len(records)
    ):
        raise ContractError(f"{field} pagination is incomplete or inconsistent")
    return records


def validate_workflow_job_inventory(
    value: object, *, workflow: str, expected_run_id: int
) -> int:
    """Require the exact latest-attempt job names and event-specific conclusions."""
    expected_by_name = {
        "pr-gate": PR_GATE_MAIN_JOBS,
        "codeql": CODEQL_MAIN_JOBS,
    }.get(workflow)
    if expected_by_name is None:
        raise ContractError("job inventory workflow must be pr-gate or codeql")
    expected_run_id = _positive_actions_id(expected_run_id, "job inventory run ID")
    records = _paginated_records(value, "jobs", f"{workflow} job inventory")
    if len(records) != len(expected_by_name):
        raise ContractError(f"{workflow} job count does not equal the exact main inventory")
    actual: dict[str, str] = {}
    for job in records:
        _positive_actions_id(job.get("id"), f"{workflow} job ID")
        if job.get("run_id") != expected_run_id:
            raise ContractError(f"{workflow} job belongs to a foreign Actions run")
        name = job.get("name")
        if not isinstance(name, str) or name not in expected_by_name:
            raise ContractError(f"{workflow} job name is absent or foreign")
        if name in actual:
            raise ContractError(f"{workflow} job name is duplicated")
        if job.get("status") != "completed":
            raise ContractError(f"{workflow} job {name!r} is not completed")
        conclusion = job.get("conclusion")
        if conclusion != expected_by_name[name]:
            raise ContractError(
                f"{workflow} job {name!r} conclusion must equal {expected_by_name[name]!r}"
            )
        actual[name] = str(conclusion)
    if actual != expected_by_name:
        raise ContractError(f"{workflow} job inventory is missing or foreign")
    return len(actual)


def select_codeql_main_run(
    value: object, *, expected_repository: str, expected_source_sha: str
) -> tuple[str, int | None]:
    """Classify one bounded-poll CodeQL list response without ignoring mutants."""
    records = _paginated_records(value, "workflow_runs", "CodeQL run list")
    if not records:
        return "absent", None
    if len(records) != 1:
        raise ContractError("CodeQL exact-SHA main run is duplicated")
    run = records[0]
    run_id = _positive_actions_id(run.get("id"), "CodeQL run ID")
    _validate_actions_run_identity(
        run,
        expected_repository=expected_repository,
        expected_run_id=run_id,
        expected_source_sha=expected_source_sha,
        expected_name=EXPECTED_CODEQL_WORKFLOW,
        expected_path=EXPECTED_CODEQL_WORKFLOW_PATH,
    )
    status = run.get("status")
    conclusion = run.get("conclusion")
    if status == "completed":
        if conclusion != "success":
            raise ContractError("CodeQL main run conclusion must equal 'success'")
        return "success", run_id
    if status in {"queued", "in_progress", "pending", "requested", "waiting"}:
        if conclusion is not None:
            raise ContractError("pending CodeQL main run carries a conclusion")
        return "pending", run_id
    raise ContractError("CodeQL main run status is malformed")


def validate_publisher(
    root: Path,
    source_sha: str,
    checkout_sha: str,
    ref: str,
    event_name: str,
    repository: str,
    workflow_ref: str,
    image: str,
    chart: str,
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
    validate_release_destinations(repository, image, chart)
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
        "actions_allowed",
        "actions_enabled",
        "actions_sha_pinning",
        "allow_deletions",
        "allow_force_pushes",
        "branch",
        "can_approve_pull_request_reviews",
        "code_coverage_max_drop",
        "code_coverage_minimum",
        "code_quality_severity",
        "code_scanning_tools",
        "default_workflow_permissions",
        "dismiss_stale_reviews_on_push",
        "immutable_releases",
        "merge_methods",
        "private_vulnerability_reporting",
        "repository",
        "require_linear_history",
        "require_code_owner_review",
        "require_last_push_approval",
        "require_pull_request",
        "require_signatures",
        "required_status_checks",
        "required_approving_review_count",
        "required_review_thread_resolution",
        "required_reviewers",
        "restrict_updates",
        "secret_scanning",
        "secret_scanning_push_protection",
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
    if receipt.get("actions_allowed") != "all":
        raise ContractError("Actions allow policy must remain exactly all")
    if receipt.get("default_workflow_permissions") != "read":
        raise ContractError("default workflow token permissions must be read-only")
    for field, expected in (
        ("actions_enabled", True),
        ("actions_sha_pinning", True),
        ("can_approve_pull_request_reviews", False),
        ("dismiss_stale_reviews_on_push", False),
        ("immutable_releases", True),
        ("private_vulnerability_reporting", True),
        ("strict_status_checks", True),
        ("require_pull_request", True),
        ("require_linear_history", True),
        ("require_code_owner_review", False),
        ("require_last_push_approval", False),
        ("require_signatures", True),
        ("required_review_thread_resolution", True),
        ("allow_force_pushes", False),
        ("allow_deletions", False),
        ("restrict_updates", False),
        ("secret_scanning", True),
        ("secret_scanning_push_protection", True),
    ):
        if receipt.get(field) is not expected:
            raise ContractError(f"settings receipt {field} must be {expected}")
    # No bypass_actors assertion: the field is absent from the receipt because
    # REST withholds it from the Administration-read-only credential that builds
    # it (see build_settings_receipt). The closed field set above now rejects it
    # as foreign, so no dangling value can be smuggled past this validator.
    if receipt.get("required_approving_review_count") != 0 or isinstance(
        receipt.get("required_approving_review_count"), bool
    ):
        raise ContractError("formal approving-review count must remain exactly zero")
    if receipt.get("required_reviewers") != []:
        raise ContractError("team required-reviewer rules must remain absent")
    if receipt.get("code_scanning_tools") != [
        {
            "alerts_threshold": "errors",
            "security_alerts_threshold": "high_or_higher",
            "tool": "CodeQL",
        }
    ]:
        raise ContractError("CodeQL scanning thresholds are not exact")
    if receipt.get("code_quality_severity") != "errors":
        raise ContractError("code-quality threshold must remain errors")
    coverage_minimum = receipt.get("code_coverage_minimum")
    if isinstance(coverage_minimum, bool) or coverage_minimum != 80:
        raise ContractError("repository code-coverage threshold must remain 80")
    if receipt.get("code_coverage_max_drop") is not None:
        raise ContractError("repository code-coverage max drop must remain null")


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
    actions_record: Mapping[str, object],
    workflow_permissions_record: Mapping[str, object],
    private_reporting_record: Mapping[str, object],
    ruleset_id: int,
    ruleset_record: Mapping[str, object],
) -> dict[str, object]:
    """Derive and validate a privacy-bounded receipt from authoritative REST."""
    if repository_record.get("full_name") != repository or repository_record.get("default_branch") != "main":
        raise ContractError("repository settings identity or default branch is not exact")
    # Merge methods are read from the Protect-Main ruleset below, never from the
    # repository record's allow_merge_commit/allow_rebase_merge/allow_squash_merge
    # booleans. REST returns those booleans only to credentials holding Contents
    # write, and the settings jobs mint a repository-scoped App token with
    # Administration read as its ONLY permission, so the booleans are absent for
    # every authorized caller of this path. The ruleset is also the authoritative
    # source: it is what actually constrains merges into protected main.
    if not isinstance(immutable_record.get("enabled"), bool) or not isinstance(
        immutable_record.get("enforced_by_owner"), bool
    ):
        raise ContractError("immutable-release settings response is malformed")
    if (
        not isinstance(actions_record.get("enabled"), bool)
        or actions_record.get("allowed_actions") not in {"all", "local_only", "selected"}
        or not isinstance(actions_record.get("sha_pinning_required"), bool)
    ):
        raise ContractError("Actions policy response is malformed")
    if (
        workflow_permissions_record.get("default_workflow_permissions")
        not in {"read", "write"}
        or not isinstance(
            workflow_permissions_record.get("can_approve_pull_request_reviews"), bool
        )
    ):
        raise ContractError("workflow-token permissions response is malformed")
    if not isinstance(private_reporting_record.get("enabled"), bool):
        raise ContractError("private vulnerability reporting response is malformed")
    security = _object(
        repository_record.get("security_and_analysis"),
        "repository security_and_analysis",
    )

    def security_enabled(name: str) -> bool:
        record = _object(security.get(name), f"security setting {name}")
        if record.get("status") not in {"enabled", "disabled"}:
            raise ContractError(f"security setting {name} status is malformed")
        return record.get("status") == "enabled"

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

    # bypass_actors is deliberately NOT read here. GitHub's "Get a repository
    # ruleset" contract states: "To prevent leaking sensitive information, the
    # bypass_actors property is only returned if the user making the API request
    # has write access to the ruleset." The settings jobs mint a
    # repository-scoped App token with Administration read as its ONLY
    # permission, so the property is absent from every response this path can
    # observe, exactly as the repository merge booleans are. A conditional or
    # best-effort assertion would be a control whose strength depends on the
    # caller, which is not a fail-closed control at all. The no-bypass invariant
    # is not abandoned: it is proven in the owner preflight column recorded in
    # docs/release-governance.md, under a credential REST will answer.
    rules_by_type: dict[str, Mapping[str, object]] = {}
    for value in _array(ruleset_record.get("rules"), "Protect-Main rules"):
        rule = _object(value, "Protect-Main rule")
        rule_type = rule.get("type")
        if not isinstance(rule_type, str) or not rule_type or rule_type in rules_by_type:
            raise ContractError("Protect-Main rule types must be non-empty and unique")
        rules_by_type[rule_type] = rule
    expected_rule_types = {
        "creation",
        "code_coverage",
        "code_quality",
        "code_scanning",
        "deletion",
        "non_fast_forward",
        "pull_request",
        "required_linear_history",
        "required_signatures",
        "required_status_checks",
    }
    if set(rules_by_type) != expected_rule_types:
        raise ContractError("Protect-Main rule types are missing or foreign")

    pull_request = rules_by_type.get("pull_request")
    if pull_request is None:
        raise ContractError("Protect-Main must require pull requests")
    pull_parameters = _object(pull_request.get("parameters"), "pull-request rule parameters")
    expected_pull_fields = {
        "allowed_merge_methods",
        "dismiss_stale_reviews_on_push",
        "require_code_owner_review",
        "require_extra_approval_for_unattributed_changes",
        "require_last_push_approval",
        "required_approving_review_count",
        "required_review_thread_resolution",
        "required_reviewers",
    }
    if set(pull_parameters) != expected_pull_fields:
        raise ContractError("pull-request rule parameter fields are missing or foreign")
    # Sole source of the receipt's merge methods. _string_set fails closed on a
    # missing, non-list, non-string, empty-string, or duplicated value, and the
    # exact {rebase, squash} set is enforced by validate_settings_receipt below.
    merge_methods = _string_set(
        pull_parameters.get("allowed_merge_methods"), "ruleset merge methods"
    )
    # require_extra_approval_for_unattributed_changes is pinned here, at the rule,
    # and deliberately does NOT enter the receipt. The receipt is the value-only
    # artifact the owner posts; it already omits rule parameters whose invariant is
    # asserted at the rule alone (do_not_enforce_on_create is the standing
    # precedent), and projecting this one would only duplicate the assertion below
    # while changing the externally pinned receipt shape. The receipt's own closed
    # field set keeps rejecting the name as foreign, so no dangling copy can be
    # smuggled past validate_settings_receipt either way.
    for field, expected in (
        ("dismiss_stale_reviews_on_push", False),
        ("require_code_owner_review", False),
        ("require_extra_approval_for_unattributed_changes", True),
        ("require_last_push_approval", False),
        ("required_review_thread_resolution", True),
    ):
        if pull_parameters.get(field) is not expected:
            raise ContractError(f"pull-request rule {field} must be {expected}")
    approving_count = pull_parameters.get("required_approving_review_count")
    if isinstance(approving_count, bool) or approving_count != 0:
        raise ContractError("pull-request rule formal approval count must be zero")
    if pull_parameters.get("required_reviewers") != []:
        raise ContractError("pull-request rule required reviewers must be empty")

    code_scanning = _object(
        rules_by_type["code_scanning"].get("parameters"),
        "code-scanning rule parameters",
    )
    if set(code_scanning) != {"code_scanning_tools"}:
        raise ContractError("code-scanning rule parameters are missing or foreign")
    tools = _array(code_scanning.get("code_scanning_tools"), "code-scanning tools")
    expected_tools = [
        {
            "alerts_threshold": "errors",
            "security_alerts_threshold": "high_or_higher",
            "tool": "CodeQL",
        }
    ]
    if tools != expected_tools:
        raise ContractError("code-scanning tool and thresholds are not exact")
    code_quality = _object(
        rules_by_type["code_quality"].get("parameters"),
        "code-quality rule parameters",
    )
    if code_quality != {"severity": "errors"}:
        raise ContractError("code-quality rule parameters are not exact")
    code_coverage = _object(
        rules_by_type["code_coverage"].get("parameters"),
        "code-coverage rule parameters",
    )
    if code_coverage != {"minimum_coverage": 80, "max_coverage_drop": None}:
        raise ContractError("code-coverage rule parameters are not exact")

    status_rule = rules_by_type.get("required_status_checks")
    if status_rule is None:
        raise ContractError("Protect-Main must require exact status checks")
    status_parameters = _object(status_rule.get("parameters"), "status-check rule parameters")
    if set(status_parameters) != {
        "do_not_enforce_on_create",
        "required_status_checks",
        "strict_required_status_checks_policy",
    }:
        raise ContractError("required-status-check parameter fields are missing or foreign")
    if status_parameters.get("do_not_enforce_on_create") is not False:
        raise ContractError("required checks must also apply when the ref is created")
    status_checks = _status_check_set(status_parameters.get("required_status_checks"))

    receipt: dict[str, object] = {
        "repository": repository,
        "branch": "main",
        "actions_enabled": actions_record.get("enabled"),
        "actions_allowed": actions_record.get("allowed_actions"),
        "actions_sha_pinning": actions_record.get("sha_pinning_required"),
        "default_workflow_permissions": workflow_permissions_record.get(
            "default_workflow_permissions"
        ),
        "can_approve_pull_request_reviews": workflow_permissions_record.get(
            "can_approve_pull_request_reviews"
        ),
        "code_coverage_max_drop": code_coverage.get("max_coverage_drop"),
        "code_coverage_minimum": code_coverage.get("minimum_coverage"),
        "code_quality_severity": code_quality.get("severity"),
        "code_scanning_tools": expected_tools,
        "dismiss_stale_reviews_on_push": pull_parameters.get(
            "dismiss_stale_reviews_on_push"
        ),
        "merge_methods": sorted(merge_methods),
        "required_status_checks": [
            {"context": context, "integration_id": integration_id}
            for context, integration_id in sorted(status_checks)
        ],
        "strict_status_checks": status_parameters.get("strict_required_status_checks_policy"),
        "require_pull_request": True,
        "require_linear_history": "required_linear_history" in rules_by_type,
        "require_code_owner_review": pull_parameters.get("require_code_owner_review"),
        "require_last_push_approval": pull_parameters.get("require_last_push_approval"),
        "require_signatures": "required_signatures" in rules_by_type,
        "required_approving_review_count": approving_count,
        "required_review_thread_resolution": pull_parameters.get(
            "required_review_thread_resolution"
        ),
        "required_reviewers": pull_parameters.get("required_reviewers"),
        "allow_force_pushes": "non_fast_forward" not in rules_by_type,
        "allow_deletions": "deletion" not in rules_by_type,
        "restrict_updates": "update" in rules_by_type,
        "immutable_releases": immutable_record.get("enabled"),
        "private_vulnerability_reporting": private_reporting_record.get("enabled"),
        "secret_scanning": security_enabled("secret_scanning"),
        "secret_scanning_push_protection": security_enabled(
            "secret_scanning_push_protection"
        ),
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
    value = parse_json(completed.stdout, "read-only GitHub settings response")
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
    actions_record = _object(
        _github_api_get(f"repos/{repository}/actions/permissions"),
        "Actions policy",
    )
    workflow_permissions_record = _object(
        _github_api_get(f"repos/{repository}/actions/permissions/workflow"),
        "workflow-token permissions",
    )
    private_reporting_record = _object(
        _github_api_get(f"repos/{repository}/private-vulnerability-reporting"),
        "private vulnerability reporting",
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
        actions_record,
        workflow_permissions_record,
        private_reporting_record,
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


def tag_ref_object_sha(ref_record: Mapping[str, object], tag: str) -> str:
    ref_object = _object(ref_record.get("object"), "tag ref object")
    if ref_record.get("ref") != f"refs/tags/{tag}" or ref_object.get("type") != "tag":
        raise ContractError("tag ref is not the exact annotated tag object")
    return require_sha(ref_object.get("sha"), "annotated tag object SHA")


def tag_created_object_sha(
    tag_record: Mapping[str, object], **expected: str
) -> str:
    tag_object_sha = require_sha(tag_record.get("sha"), "created tag object SHA")
    ref_record = {
        "ref": f"refs/tags/{expected['tag']}",
        "object": {"type": "tag", "sha": tag_object_sha},
    }
    validate_tag_record(ref_record, tag_record, **expected)
    return tag_object_sha


def require_digest(raw: object, field: str) -> str:
    if not isinstance(raw, str) or not DIGEST_RE.fullmatch(raw):
        raise ContractError(f"{field} must be sha256:<64 lowercase hex>")
    return raw


def require_released_image_digest(digest: object) -> str:
    """Accept only a well-formed digest that is not the fail-closed sentinel."""
    resolved = require_digest(digest, "chart image digest")
    if resolved == CHART_IMAGE_DIGEST_SENTINEL:
        raise ContractError("chart image digest must not be the fail-closed sentinel")
    return resolved


def embed_chart_image_digest(text: str, digest: object) -> str:
    """Bind one packaged chart to the exact scanned, signed, attested digest.

    The committed tree keeps the sentinel (requirement 4), so the ONLY
    accepted starting values are the sentinel itself or this same digest —
    the latter because both packaging paths in the publisher run the identical
    substitution and a re-applied embed must be a no-op rather than a second,
    unreviewed rewrite. Any other value means the working copy already carries
    a foreign digest, which denies instead of being overwritten.
    """
    resolved = require_released_image_digest(digest)
    lines = text.split("\n")
    # _direct_child_entries indexes by str.splitlines(), which also breaks on
    # \r, \x0b, \x0c and the Unicode separators. Rewriting by that index into a
    # \n-split list would edit the WRONG line for any such file, so an ambiguous
    # line structure denies rather than being silently normalized.
    if text.splitlines() != (lines[:-1] if text.endswith("\n") else lines):
        raise ContractError("chart values are not exactly newline separated")
    index, current = _direct_child_entry(text, "image", "digest")
    if current not in (CHART_IMAGE_DIGEST_SENTINEL, resolved):
        raise ContractError("chart values image.digest is neither the sentinel nor this release digest")
    lines[index] = f"  digest: {resolved}"
    return "\n".join(lines)


def require_embedded_chart_digest(text: str, digest: object) -> str:
    """Prove a PACKAGED chart carries the exact released image digest."""
    resolved = require_released_image_digest(digest)
    observed = _direct_child_scalar(text, "image", "digest")
    if observed == CHART_IMAGE_DIGEST_SENTINEL:
        raise ContractError("packaged chart still carries the fail-closed digest sentinel")
    require_digest(observed, "packaged chart image digest")
    if observed != resolved:
        raise ContractError("packaged chart image digest is not the released image digest")
    return observed


def validate_release_destinations(repository: str, image: str, chart: str) -> None:
    """Bind dotted repository identity to explicit, non-derived GHCR packages."""
    if repository != EXPECTED_REPOSITORY:
        raise ContractError("release repository identity is not exact")
    if image != EXPECTED_IMAGE:
        raise ContractError("release image package identity is not exact")
    if chart != EXPECTED_CHART:
        raise ContractError("release chart package identity is not exact")


def validate_registry_manifest_response(
    http_status: int,
    body: bytes,
    headers: str,
    *,
    expected_digest: str | None = None,
) -> str:
    """Authenticate one exact registry representation by header and raw bytes."""
    if http_status != 200:
        raise ContractError(f"registry alias resolve returned unexpected HTTP {http_status}")
    try:
        body_text = body.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ContractError("registry manifest body is not UTF-8 JSON") from exc
    _object(parse_json(body_text, "registry manifest body"), "registry manifest body")
    observed_values: list[str] = []
    for line in headers.splitlines():
        match = re.fullmatch(
            r"(?i)docker-content-digest:[ \t]*(\S+)[ \t]*", line
        )
        if match:
            observed_values.append(match.group(1))
    if len(observed_values) != 1:
        raise ContractError("registry response must carry exactly one Docker-Content-Digest")
    observed = require_digest(observed_values[0], "registry response digest")
    computed = "sha256:" + hashlib.sha256(body).hexdigest()
    if computed != observed:
        raise ContractError("registry manifest body digest does not equal its response header")
    if expected_digest is not None and observed != require_digest(
        expected_digest, "expected registry alias digest"
    ):
        raise ContractError("registry alias was absent or retargeted after publication")
    return observed


def canonical_json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
        + "\n"
    ).encode("utf-8")


def build_release_manifest(
    *,
    repository: str,
    source_sha: str,
    version: Version,
    image: str,
    image_digest: str,
    chart: str,
    chart_digest: str,
) -> dict[str, object]:
    """Build the sole canonical machine identity for external release artifacts."""
    validate_release_destinations(repository, image, chart)
    source_sha = require_sha(source_sha, "manifest source SHA")
    image_digest = require_digest(image_digest, "manifest image digest")
    chart_digest = require_digest(chart_digest, "manifest chart digest")
    registry = re.compile(r"^ghcr\.io/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+$")
    if not registry.fullmatch(image) or not registry.fullmatch(chart):
        raise ContractError("manifest registry identity is malformed")
    identity = (
        f"https://github.com/{repository}/.github/workflows/"
        "release-publisher.yml@refs/heads/main"
    )
    signature = {
        "certificate_identity": identity,
        "oidc_issuer": COSIGN_ISSUER,
        "required": True,
    }
    return {
        "artifacts": {
            "chart": {
                "alias": f"{chart}:{version}",
                "digest": chart_digest,
                "digest_reference": f"{chart}@{chart_digest}",
                "display_reference": f"{chart}:{version}@{chart_digest}",
                "provenance": {
                    "platforms": [],
                    "predicate_type": "",
                    "required": False,
                },
                "registry": chart,
                "sbom": {
                    "platforms": [],
                    "predicate_type": "",
                    "required": False,
                    "signed": False,
                },
                "signature": signature,
            },
            "image": {
                "alias": f"{image}:{version.tag}",
                "digest": image_digest,
                "digest_reference": f"{image}@{image_digest}",
                "display_reference": f"{image}:{version.tag}@{image_digest}",
                "provenance": {
                    "platforms": list(RELEASE_PLATFORMS),
                    "predicate_type": SLSA_PREDICATE_TYPE,
                    "required": True,
                },
                "registry": image,
                "sbom": {
                    "platforms": list(RELEASE_PLATFORMS),
                    "predicate_type": SPDX_PREDICATE_TYPE,
                    "required": True,
                    "signed": True,
                },
                "signature": signature,
            },
        },
        "repository": repository,
        "schema": RELEASE_MANIFEST_SCHEMA,
        "source_sha": source_sha,
        "tag": version.tag,
        "version": str(version),
        "workflow_identity": identity,
    }


def validate_release_manifest(
    value: Mapping[str, object], *, expected_repository: str | None = None
) -> dict[str, object]:
    """Validate the closed manifest schema by reconstructing its exact value."""
    if set(value) != {
        "artifacts",
        "repository",
        "schema",
        "source_sha",
        "tag",
        "version",
        "workflow_identity",
    }:
        raise ContractError("release manifest fields are missing or foreign")
    if value.get("schema") != RELEASE_MANIFEST_SCHEMA:
        raise ContractError("release manifest schema is not supported")
    repository = value.get("repository")
    if not isinstance(repository, str):
        raise ContractError("release manifest repository is absent")
    if expected_repository is not None and repository != expected_repository:
        raise ContractError("release manifest repository is foreign")
    version_raw = value.get("version")
    if not isinstance(version_raw, str):
        raise ContractError("release manifest version is absent")
    version = Version.parse(version_raw)
    if value.get("tag") != version.tag:
        raise ContractError("release manifest tag does not equal v<VERSION>")
    artifacts = _object(value.get("artifacts"), "release manifest artifacts")
    if set(artifacts) != {"chart", "image"}:
        raise ContractError("release manifest artifact set must be exactly image and chart")
    image = _object(artifacts.get("image"), "release manifest image")
    chart = _object(artifacts.get("chart"), "release manifest chart")
    expected = build_release_manifest(
        repository=repository,
        source_sha=require_sha(value.get("source_sha"), "manifest source SHA"),
        version=version,
        image=str(image.get("registry", "")),
        image_digest=require_digest(image.get("digest"), "manifest image digest"),
        chart=str(chart.get("registry", "")),
        chart_digest=require_digest(chart.get("digest"), "manifest chart digest"),
    )
    if value != expected:
        raise ContractError("release manifest content is missing, foreign, or reordered")
    return expected


def read_release_manifest(
    path: Path, *, expected_repository: str | None = None, require_mode: bool = True
) -> tuple[dict[str, object], bytes]:
    raw = path.read_bytes()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ContractError("release manifest is not UTF-8") from exc
    value = _object(parse_json(text, "release manifest"), "release manifest")
    manifest = validate_release_manifest(value, expected_repository=expected_repository)
    if raw != canonical_json_bytes(manifest):
        raise ContractError("release manifest bytes are not canonical")
    # Windows does not expose POSIX owner/group/other mode bits. Every release
    # job runs on Linux, where this is a strict 0600 assertion; Windows hosts
    # still validate the same canonical bytes and schema for local tests.
    if require_mode and os.name != "nt" and (path.stat().st_mode & 0o777) != 0o600:
        raise ContractError("release manifest mode must be exactly 0600")
    return manifest, raw


def write_release_manifest(path: Path, manifest: Mapping[str, object]) -> None:
    raw = canonical_json_bytes(validate_release_manifest(manifest))
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(descriptor, 0o600)
        os.write(descriptor, raw)
    finally:
        os.close(descriptor)


def _release_asset(release_record: Mapping[str, object]) -> Mapping[str, object]:
    assets = _array(release_record.get("assets"), "GitHub Release assets")
    if len(assets) != 1:
        raise ContractError("GitHub Release must contain exactly one manifest asset")
    asset = _object(assets[0], "GitHub Release manifest asset")
    asset_id = asset.get("id")
    if isinstance(asset_id, bool) or not isinstance(asset_id, int) or asset_id <= 0:
        raise ContractError("GitHub Release manifest asset ID is not positive")
    if asset.get("name") != RELEASE_MANIFEST_NAME:
        raise ContractError("GitHub Release manifest asset name is not exact")
    if asset.get("state") != "uploaded":
        raise ContractError("GitHub Release manifest asset is not fully uploaded")
    if asset.get("content_type") != "application/json":
        raise ContractError("GitHub Release manifest asset content type is not exact")
    uploader = _object(asset.get("uploader"), "GitHub Release manifest asset uploader")
    if (
        uploader.get("login") != GITHUB_ACTIONS_BOT_LOGIN
        or uploader.get("id") != GITHUB_ACTIONS_BOT_ID
    ):
        raise ContractError("GitHub Release manifest asset uploader is not the workflow bot")
    size = asset.get("size")
    if isinstance(size, bool) or not isinstance(size, int) or size <= 0:
        raise ContractError("GitHub Release manifest asset size is not positive")
    require_digest(asset.get("digest"), "GitHub Release manifest asset digest")
    return asset


def release_asset_id(release_record: Mapping[str, object]) -> int:
    return int(_release_asset(release_record)["id"])


def validate_release_record(
    release_record: Mapping[str, object],
    *,
    manifest: Mapping[str, object],
    manifest_bytes: bytes,
    asset_bytes: bytes | None,
) -> str:
    """Classify an exact draft/immutable Release around one manifest asset."""
    expected = validate_release_manifest(manifest)
    if release_record.get("tag_name") != expected["tag"]:
        raise ContractError("GitHub Release tag is not exact")
    author = _object(release_record.get("author"), "GitHub Release author")
    if (
        author.get("login") != GITHUB_ACTIONS_BOT_LOGIN
        or author.get("id") != GITHUB_ACTIONS_BOT_ID
    ):
        raise ContractError("GitHub Release author is not the workflow bot")
    if release_record.get("prerelease") is not False:
        raise ContractError("GitHub Release must be non-prerelease")
    draft = release_record.get("draft")
    immutable = release_record.get("immutable")
    if not isinstance(draft, bool) or not isinstance(immutable, bool):
        raise ContractError("GitHub Release draft/immutable state is malformed")
    assets = _array(release_record.get("assets"), "GitHub Release assets")
    if not assets:
        if draft is True and immutable is False and asset_bytes is None:
            return "draft-empty"
        raise ContractError("published GitHub Release is missing its manifest asset")
    asset = _release_asset(release_record)
    if asset_bytes is None:
        raise ContractError("GitHub Release manifest asset content was not verified")
    expected_digest = "sha256:" + hashlib.sha256(manifest_bytes).hexdigest()
    if asset.get("size") != len(manifest_bytes):
        raise ContractError("GitHub Release manifest asset size is not exact")
    if asset.get("digest") != expected_digest:
        raise ContractError("GitHub Release manifest asset digest is not exact")
    if asset_bytes != manifest_bytes:
        raise ContractError("GitHub Release manifest asset content is not exact")
    if draft is True and immutable is False:
        return "draft-ready"
    if draft is False and immutable is True:
        return "exact"
    raise ContractError("GitHub Release is neither resumable draft nor immutable published state")


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
    manifest: Mapping[str, object],
    manifest_bytes: bytes,
    asset_bytes: bytes | None,
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
    return validate_release_record(
        release_record,
        manifest=manifest,
        manifest_bytes=manifest_bytes,
        asset_bytes=asset_bytes,
    )


def select_release_by_tag(
    releases: object, *, tag: str, repository: str
) -> tuple[str, Mapping[str, object] | None]:
    """Select one GitHub Release by tag_name from the plural list endpoint.

    The by-tag REST endpoint (``GET /repos/{repo}/releases/tags/{tag}``)
    never returns an unpublished draft Release, so ``observe_release`` falls
    back to this plural listing -- which DOES include drafts -- on a by-tag
    404 and matches locally. Zero matches is absent, the same classification
    a genuine 404 already carries. More than one match is a stray-draft
    ambiguity this function refuses to resolve silently: it fails closed so
    a human resolves the duplicate by hand.
    """
    records = [_object(item, "releases list record") for item in _array(releases, "releases list")]
    matches = [record for record in records if record.get("tag_name") == tag]
    if not matches:
        return "absent", None
    if len(matches) != 1:
        raise ContractError(
            f"{len(matches)} GitHub Releases share tag_name {tag!r} in {repository}; "
            f"inspect GET /repos/{repository}/releases and resolve the stray "
            "duplicate draft by hand before retrying"
        )
    return "one", matches[0]


def require_publication_state(actual: str, required: str) -> str:
    """Turn an API classification into a shell-safe exact-state assertion."""
    if required not in {"absent", "draft-empty", "draft-ready", "exact"} or actual != required:
        raise ContractError(f"publication state {actual!r} does not equal required {required!r}")
    return actual


def builder_identity_pattern(source: str, builder_run_id: str) -> re.Pattern[str]:
    """Anchor one exact Actions run as the only builder identity accepted.

    The whole builder ID is matched, so nothing after the run ID can be
    smuggled in: a path traversal (``.../runs/1/../../999``), a longer run ID
    sharing the prefix (``.../runs/1234`` against run ``123``), or trailing
    junk after the attempt all fail the full match. Only the attempt segment
    is a pattern, and it is mandatory.
    """
    if not ACTIONS_RUN_ID_RE.fullmatch(builder_run_id):
        raise ContractError(
            "attestation builder run ID must be a positive decimal Actions run ID"
        )
    return re.compile(
        re.escape(f"{source}/actions/runs/{builder_run_id}") + BUILDER_ATTEMPT_SUFFIX
    )


def build_attestation_statement(
    predicate: Mapping[str, object],
    *,
    image: str,
    digest: str,
    source: str,
    revision: str,
    platform: str,
    builder_run_id: str,
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
    expected_builder = builder_identity_pattern(source, builder_run_id)

    normalized = copy.deepcopy(dict(predicate))
    build = _object(normalized.get("buildDefinition"), "SLSA buildDefinition")
    run = _object(normalized.get("runDetails"), "SLSA runDetails")
    builder = _object(run.get("builder"), "SLSA builder")
    metadata = _object(run.get("metadata"), "SLSA metadata")
    buildkit = _object(metadata.get("buildkit_metadata"), "BuildKit metadata")
    vcs = _object(buildkit.get("vcs"), "BuildKit vcs metadata")
    builder_id = builder.get("id")
    if not isinstance(builder_id, str) or not expected_builder.fullmatch(builder_id):
        raise ContractError(
            "embedded predicate builder is not Actions run "
            f"{builder_run_id} of this repository"
        )
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


def read_attestation_builder_run(predicate: Mapping[str, object], *, source: str) -> str:
    """Recover the single Actions run ID an ALREADY-BUILT image's predicate names.

    Two callers cannot name the builder run from their own environment,
    because the bytes they inspect were built by an EARLIER run: the
    publisher's existing-image classifier (a re-dispatch after a partial
    release gets a new run ID, so its own GITHUB_RUN_ID would deny a
    legitimate reuse) and the scheduled integrity audit (the closed
    release-manifest schema records no run ID). Neither has an independent
    record to compare against -- their authority is the verified certificate
    identity over the digest -- so this recovers the run ID from the FIRST
    platform's predicate and the caller passes that same value for EVERY
    platform.

    What that buys, precisely, and no more: the builder ID must be a
    well-formed Actions run of this exact repository WITH its attempt
    segment, and all platforms of one image must name ONE run. Before this,
    linux/amd64 and linux/arm64 could name different runs and both pass.
    It is not an independent attestation that the run was authorized; the
    fresh-build path is where GITHUB_RUN_ID makes that binding, and the
    signed statements this reproduces were produced under it.
    """
    if not source.startswith("https://github.com/"):
        raise ContractError("attestation source identity is malformed")
    run = _object(predicate.get("runDetails"), "SLSA runDetails")
    builder = _object(run.get("builder"), "SLSA builder")
    builder_id = builder.get("id")
    if not isinstance(builder_id, str):
        raise ContractError("embedded predicate builder ID is absent or not a string")
    match = re.fullmatch(
        re.escape(f"{source}/actions/runs/")
        + f"({ACTIONS_RUN_ID_RE.pattern})"
        + BUILDER_ATTEMPT_SUFFIX,
        builder_id,
    )
    if not match:
        raise ContractError(
            "embedded predicate builder is not an Actions run of this repository"
        )
    return match.group(1)


def _verified_statements(text: str) -> list[Mapping[str, object]]:
    decoder = json.JSONDecoder(
        object_pairs_hook=_reject_duplicate_members,
        parse_constant=_reject_nonfinite_constant,
    )
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
            statement = parse_json(decoded, "verified cosign payload")
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


def validate_spdx_document(value: object, field: str = "SPDX SBOM") -> dict[str, object]:
    """Require a non-null, non-empty SPDX document rather than a platform key."""
    document = _object(value, field)
    if document.get("SPDXID") != "SPDXRef-DOCUMENT":
        raise ContractError(f"{field} SPDXID is not SPDXRef-DOCUMENT")
    if document.get("spdxVersion") not in {"SPDX-2.2", "SPDX-2.3"}:
        raise ContractError(f"{field} SPDX version is not supported")
    if document.get("dataLicense") != "CC0-1.0":
        raise ContractError(f"{field} data license is not CC0-1.0")
    for key in ("name", "documentNamespace"):
        member = document.get(key)
        if not isinstance(member, str) or not member.strip():
            raise ContractError(f"{field} {key} is absent")
    namespace = str(document["documentNamespace"])
    if not namespace.startswith(("https://", "http://")):
        raise ContractError(f"{field} documentNamespace is malformed")
    creation = _object(document.get("creationInfo"), f"{field} creationInfo")
    created = creation.get("created")
    if not isinstance(created, str) or not created.strip():
        raise ContractError(f"{field} creation timestamp is absent")
    creators = _array(creation.get("creators"), f"{field} creators")
    if not creators or any(not isinstance(item, str) or not item.strip() for item in creators):
        raise ContractError(f"{field} creators are empty or malformed")
    packages = _array(document.get("packages"), f"{field} packages")
    if not packages:
        raise ContractError(f"{field} package evidence is empty")
    for index, raw_package in enumerate(packages):
        package = _object(raw_package, f"{field} package {index}")
        if not isinstance(package.get("name"), str) or not package["name"]:
            raise ContractError(f"{field} package {index} name is absent")
        spdx_id = package.get("SPDXID")
        if not isinstance(spdx_id, str) or not spdx_id.startswith("SPDXRef-"):
            raise ContractError(f"{field} package {index} SPDXID is malformed")
    return copy.deepcopy(dict(document))


def validate_sbom_platform_map(value: object) -> dict[str, dict[str, object]]:
    """Require exactly one valid Buildx SPDX payload for each release platform."""
    platform_map = _object(value, "Buildx SBOM platform map")
    if set(platform_map) != set(RELEASE_PLATFORMS):
        raise ContractError("Buildx SBOM platforms are missing, duplicated, or foreign")
    documents: dict[str, dict[str, object]] = {}
    for platform in RELEASE_PLATFORMS:
        record = _object(platform_map.get(platform), f"Buildx SBOM {platform}")
        if set(record) != {"SPDX"}:
            raise ContractError(f"Buildx SBOM {platform} fields are missing or foreign")
        documents[platform] = validate_spdx_document(
            record.get("SPDX"), f"Buildx SBOM {platform} SPDX"
        )
    return documents


def build_sbom_statement(
    document: Mapping[str, object], *, image: str, digest: str, platform: str
) -> dict[str, object]:
    """Bind one exact SPDX payload to the immutable index digest and platform."""
    match = DIGEST_RE.fullmatch(digest)
    if not match:
        raise ContractError("SBOM subject digest must be sha256:<64 lowercase hex>")
    if not image or "@" in image or platform not in RELEASE_PLATFORMS:
        raise ContractError("SBOM image or platform identity is malformed")
    predicate = validate_spdx_document(document)
    # cosign generates the subject itself from the CLI target
    # ("${IMAGE}@${DIGEST}", never platform-qualified): the bare image repo
    # plus the digest map below. The platform argument stays validated above
    # for defense in depth and file naming, but it is not embeddable here —
    # mirroring anything else would desync this expected statement from what
    # cosign actually signs, which is exactly the class of bug this fixes.
    return {
        "_type": INTOTO_STATEMENT_TYPE,
        "subject": [{"name": image, "digest": {"sha256": match.group(1)}}],
        "predicateType": SPDX_PREDICATE_TYPE,
        "predicate": predicate,
    }


def validate_sbom_attestation_set(
    verified_output: str, expected_by_platform: Mapping[str, Mapping[str, object]]
) -> int:
    """Accept only the exact authenticated two-platform SPDX statement set."""
    if set(expected_by_platform) != set(RELEASE_PLATFORMS):
        raise ContractError("expected SBOM platform set is missing or foreign")
    statements = _verified_statements(verified_output)
    if len(statements) != len(expected_by_platform):
        raise ContractError("verified SBOM count does not equal the required platform set")
    expected: dict[bytes, str] = {}
    for platform, statement in expected_by_platform.items():
        expected[canonical_json_bytes(statement)] = platform
    if len(expected) != len(expected_by_platform):
        raise ContractError("expected SBOM statements are duplicated")
    seen: set[str] = set()
    for statement in statements:
        if statement.get("_type") != INTOTO_STATEMENT_TYPE:
            raise ContractError("verified SBOM statement type is foreign")
        if statement.get("predicateType") != SPDX_PREDICATE_TYPE:
            raise ContractError("verified SBOM predicate type is foreign")
        subjects = _array(statement.get("subject"), "verified SBOM subjects")
        if len(subjects) != 1:
            raise ContractError("verified SBOM must carry exactly one subject")
        subject = _object(subjects[0], "verified SBOM subject")
        digest = _object(subject.get("digest"), "verified SBOM subject digest")
        require_digest(f"sha256:{digest.get('sha256')}", "verified SBOM subject digest")
        validate_spdx_document(statement.get("predicate"), "verified SPDX predicate")
        key = canonical_json_bytes(statement)
        platform = expected.get(key)
        if platform is None:
            raise ContractError("verified SBOM subject, platform, or payload is not exact")
        if platform in seen:
            raise ContractError("verified SBOM platform is duplicated")
        seen.add(platform)
    if seen != set(expected_by_platform):
        raise ContractError("verified SBOM platforms are missing or foreign")
    return len(statements)


def validate_trivy_source_report(
    report: Mapping[str, object], package_document: Mapping[str, object]
) -> int:
    """Prove the frontend build graph entered the recurring HIGH/CRITICAL scan."""
    # Trivy v0.73.0 identifies `trivy fs ... .` JSON as a repository artifact.
    # Pin that real emitter identity so a synthetic or wrong scanner report
    # cannot satisfy the frontend dependency-inventory proof.
    if (
        report.get("SchemaVersion") != 2
        or report.get("ArtifactName") != "."
        or report.get("ArtifactType") != "repository"
    ):
        raise ContractError("Trivy source report identity is malformed")
    dev_dependencies = _object(
        package_document.get("devDependencies"), "frontend devDependencies"
    )
    if not dev_dependencies:
        raise ContractError("frontend devDependencies are empty")
    expected: dict[str, str] = {}
    for name, version in dev_dependencies.items():
        if not isinstance(name, str) or not name or not isinstance(version, str) or not version:
            raise ContractError("frontend devDependency identity is malformed")
        expected[name] = version

    results = _array(report.get("Results"), "Trivy source Results")
    frontend_results: list[Mapping[str, object]] = []
    findings: list[tuple[str, str, str]] = []
    for raw_result in results:
        result = _object(raw_result, "Trivy source result")
        target = result.get("Target")
        if isinstance(target, str) and target.replace("\\", "/") == "frontend/package-lock.json":
            if result.get("Class") != "lang-pkgs" or result.get("Type") not in {
                "npm",
                "node-pkg",
            }:
                raise ContractError("Trivy frontend result class or type is malformed")
            frontend_results.append(result)
        vulnerabilities = result.get("Vulnerabilities", [])
        if vulnerabilities is None:
            vulnerabilities = []
        for raw_vulnerability in _array(vulnerabilities, "Trivy vulnerabilities"):
            vulnerability = _object(raw_vulnerability, "Trivy vulnerability")
            severity = vulnerability.get("Severity")
            if severity in {"HIGH", "CRITICAL"}:
                identifier = vulnerability.get("VulnerabilityID")
                package = vulnerability.get("PkgName")
                if not isinstance(identifier, str) or not identifier or not isinstance(package, str) or not package:
                    raise ContractError("Trivy HIGH/CRITICAL finding identity is malformed")
                findings.append((str(severity), identifier, package))
    if len(frontend_results) != 1:
        raise ContractError("Trivy report must contain exactly one frontend/package-lock.json result")
    packages = _array(frontend_results[0].get("Packages"), "Trivy frontend packages")
    actual: dict[str, list[tuple[str, object]]] = {}
    for raw_package in packages:
        package = _object(raw_package, "Trivy frontend package")
        name = package.get("Name")
        version = package.get("Version")
        if isinstance(name, str) and isinstance(version, str):
            actual.setdefault(name, []).append((version, package.get("Relationship")))
    for name, version in expected.items():
        if actual.get(name) != [(version, "direct")]:
            raise ContractError(
                f"Trivy source scan omitted exact direct frontend devDependency {name}@{version}"
            )
    if findings:
        severity, identifier, package = sorted(findings)[0]
        raise ContractError(
            f"Trivy source scan found {severity} {identifier} in frontend build dependency {package}"
        )
    return len(expected)


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
    return _object(parse_json(path.read_text(encoding="utf-8"), str(path)), str(path))


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
    codeql_run = commands.add_parser("codeql-run-record")
    codeql_run.add_argument("--run-json", type=Path, required=True)
    codeql_run.add_argument("--run-id", type=int, required=True)
    codeql_run.add_argument("--repository", required=True)
    codeql_run.add_argument("--source-sha", required=True)
    codeql_list = commands.add_parser("codeql-run-list")
    codeql_list.add_argument("--runs-json", type=Path, required=True)
    codeql_list.add_argument("--repository", required=True)
    codeql_list.add_argument("--source-sha", required=True)
    workflow_jobs = commands.add_parser("workflow-jobs")
    workflow_jobs.add_argument("--jobs-json", type=Path, required=True)
    workflow_jobs.add_argument("--workflow", choices=("pr-gate", "codeql"), required=True)
    workflow_jobs.add_argument("--run-id", type=int, required=True)
    publisher = commands.add_parser("publisher")
    publisher.add_argument("--root", type=Path, required=True)
    publisher.add_argument("--source-sha", required=True)
    publisher.add_argument("--checkout-sha", required=True)
    publisher.add_argument("--ref", required=True)
    publisher.add_argument("--event-name", required=True)
    publisher.add_argument("--repository", required=True)
    publisher.add_argument("--workflow-ref", required=True)
    publisher.add_argument("--image", required=True)
    publisher.add_argument("--chart", required=True)
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
    tag_ref_object = commands.add_parser("tag-ref-object")
    tag_ref_object.add_argument("--ref-json", type=Path, required=True)
    tag_ref_object.add_argument("--tag", required=True)
    tag_created = commands.add_parser("tag-created-object")
    tag_created.add_argument("--tag-json", type=Path, required=True)
    tag_created.add_argument("--tag", required=True)
    tag_created.add_argument("--source-sha", required=True)
    tag_created.add_argument("--message", required=True)
    tag_created.add_argument("--tagger-name", required=True)
    tag_created.add_argument("--tagger-email", required=True)
    tag_created.add_argument("--tagger-date", required=True)
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
    release_state = commands.add_parser("release-state")
    release_state.add_argument("--http-status", type=int, required=True)
    release_state.add_argument(
        "--require", choices=("absent", "draft-empty", "draft-ready", "exact")
    )
    release_state.add_argument("--release-json", type=Path)
    release_state.add_argument("--manifest", type=Path, required=True)
    release_state.add_argument("--asset-content", type=Path)
    release_state.add_argument("--repository", required=True)
    release_asset = commands.add_parser("release-asset-id")
    release_asset.add_argument("--release-json", type=Path, required=True)
    release_tag_select = commands.add_parser("release-tag-select")
    release_tag_select.add_argument("--releases-json", type=Path, required=True)
    release_tag_select.add_argument("--tag", required=True)
    release_tag_select.add_argument("--repository", required=True)
    release_tag_select.add_argument("--output", type=Path, required=True)
    manifest = commands.add_parser("release-manifest")
    manifest.add_argument("--output", type=Path, required=True)
    manifest.add_argument("--repository", required=True)
    manifest.add_argument("--source-sha", required=True)
    manifest.add_argument("--version", required=True)
    manifest.add_argument("--image", required=True)
    manifest.add_argument("--image-digest", required=True)
    manifest.add_argument("--chart", required=True)
    manifest.add_argument("--chart-digest", required=True)
    manifest_record = commands.add_parser("manifest-record")
    manifest_record.add_argument("--manifest", type=Path, required=True)
    manifest_record.add_argument("--repository", required=True)
    manifest_record.add_argument("--github-output", type=Path)
    registry_token = commands.add_parser("registry-token")
    registry_token.add_argument("--token-json", type=Path, required=True)
    registry_manifest = commands.add_parser("registry-manifest")
    registry_manifest.add_argument("--http-status", type=int, required=True)
    registry_manifest.add_argument("--body", type=Path, required=True)
    registry_manifest.add_argument("--headers", type=Path, required=True)
    registry_manifest.add_argument("--expected-digest")
    chart_digest_embed = commands.add_parser("chart-digest-embed")
    chart_digest_embed.add_argument("--values", type=Path, required=True)
    chart_digest_embed.add_argument("--digest", required=True)
    chart_digest_verify = commands.add_parser("chart-digest-verify")
    chart_digest_verify.add_argument("--values", type=Path, required=True)
    chart_digest_verify.add_argument("--digest", required=True)
    json_keys = commands.add_parser("json-keys")
    json_keys.add_argument("--json", type=Path, required=True)
    statement = commands.add_parser("attestation-statement")
    statement.add_argument("--predicate", type=Path, required=True)
    statement.add_argument("--output", type=Path, required=True)
    statement.add_argument("--predicate-output", type=Path, required=True)
    statement.add_argument("--image", required=True)
    statement.add_argument("--digest", required=True)
    statement.add_argument("--source", required=True)
    statement.add_argument("--revision", required=True)
    statement.add_argument("--platform", required=True)
    statement.add_argument("--builder-run-id", required=True)
    builder_run = commands.add_parser("attestation-builder-run")
    builder_run.add_argument("--predicate", type=Path, required=True)
    builder_run.add_argument("--source", required=True)
    attestations = commands.add_parser("attestation-set")
    attestations.add_argument("--verified", type=Path, required=True)
    attestations.add_argument("--expected", action="append", required=True)
    sbom_platforms = commands.add_parser("sbom-platforms")
    sbom_platforms.add_argument("--json", type=Path, required=True)
    sbom_statement = commands.add_parser("sbom-statement")
    sbom_statement.add_argument("--spdx", type=Path, required=True)
    sbom_statement.add_argument("--output", type=Path, required=True)
    sbom_statement.add_argument("--predicate-output", type=Path, required=True)
    sbom_statement.add_argument("--image", required=True)
    sbom_statement.add_argument("--digest", required=True)
    sbom_statement.add_argument("--platform", required=True)
    sbom_set = commands.add_parser("sbom-set")
    sbom_set.add_argument("--verified", type=Path, required=True)
    sbom_set.add_argument("--expected", action="append", required=True)
    trivy_source = commands.add_parser("trivy-source")
    trivy_source.add_argument("--report", type=Path, required=True)
    trivy_source.add_argument("--package-json", type=Path, required=True)
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
            print(
                json.dumps(
                    classify_transition(
                        args.repository, args.base, args.head, first_parent=args.first_parent
                    ),
                    sort_keys=True,
                )
            )
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
            event = _read_object(args.event)
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
        elif args.command == "codeql-run-record":
            print(
                validate_codeql_run_record(
                    _read_object(args.run_json),
                    expected_repository=args.repository,
                    expected_run_id=args.run_id,
                    expected_source_sha=args.source_sha,
                )
            )
        elif args.command == "codeql-run-list":
            state, run_id = select_codeql_main_run(
                parse_json(args.runs_json.read_text(encoding="utf-8"), str(args.runs_json)),
                expected_repository=args.repository,
                expected_source_sha=args.source_sha,
            )
            print(json.dumps({"run_id": run_id, "state": state}, sort_keys=True))
        elif args.command == "workflow-jobs":
            print(
                validate_workflow_job_inventory(
                    parse_json(args.jobs_json.read_text(encoding="utf-8"), str(args.jobs_json)),
                    workflow=args.workflow,
                    expected_run_id=args.run_id,
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
                    args.image,
                    args.chart,
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
        elif args.command == "tag-ref-object":
            print(tag_ref_object_sha(_read_object(args.ref_json), args.tag))
        elif args.command == "tag-created-object":
            print(
                tag_created_object_sha(
                    _read_object(args.tag_json),
                    tag=args.tag,
                    source_sha=args.source_sha,
                    message=args.message,
                    tagger_name=args.tagger_name,
                    tagger_email=args.tagger_email,
                    tagger_date=args.tagger_date,
                )
            )
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
        elif args.command == "release-state":
            manifest, manifest_bytes = read_release_manifest(
                args.manifest, expected_repository=args.repository
            )
            state = classify_release_state(
                args.http_status,
                _read_object(args.release_json) if args.release_json else None,
                manifest=manifest,
                manifest_bytes=manifest_bytes,
                asset_bytes=args.asset_content.read_bytes()
                if args.asset_content
                else None,
            )
            print(require_publication_state(state, args.require) if args.require else state)
        elif args.command == "release-asset-id":
            print(release_asset_id(_read_object(args.release_json)))
        elif args.command == "release-tag-select":
            state, record = select_release_by_tag(
                parse_json(
                    args.releases_json.read_text(encoding="utf-8"),
                    str(args.releases_json),
                ),
                tag=args.tag,
                repository=args.repository,
            )
            if record is not None:
                args.output.write_text(
                    json.dumps(record, sort_keys=True) + "\n", encoding="utf-8"
                )
            print(state)
        elif args.command == "release-manifest":
            write_release_manifest(
                args.output,
                build_release_manifest(
                    repository=args.repository,
                    source_sha=args.source_sha,
                    version=Version.parse(args.version),
                    image=args.image,
                    image_digest=args.image_digest,
                    chart=args.chart,
                    chart_digest=args.chart_digest,
                ),
            )
            print(RELEASE_MANIFEST_NAME)
        elif args.command == "manifest-record":
            manifest, raw = read_release_manifest(
                args.manifest, expected_repository=args.repository
            )
            artifacts = _object(manifest["artifacts"], "release manifest artifacts")
            image = _object(artifacts["image"], "release manifest image")
            chart = _object(artifacts["chart"], "release manifest chart")
            record = {
                "asset_digest": "sha256:" + hashlib.sha256(raw).hexdigest(),
                "asset_name": RELEASE_MANIFEST_NAME,
                "asset_size": len(raw),
                "chart_alias": chart["alias"],
                "chart_digest": chart["digest"],
                "image_alias": image["alias"],
                "image_digest": image["digest"],
                "source_sha": manifest["source_sha"],
                "tag": manifest["tag"],
                "version": manifest["version"],
                "workflow_identity": manifest["workflow_identity"],
            }
            if args.github_output:
                with args.github_output.open("a", encoding="utf-8", newline="\n") as output:
                    for key, value in sorted(record.items()):
                        output.write(f"{key}={value}\n")
            else:
                print(json.dumps(record, sort_keys=True))
        elif args.command == "registry-token":
            record = _read_object(args.token_json)
            candidates = [
                value
                for key in ("token", "access_token")
                if isinstance((value := record.get(key)), str) and value
            ]
            if len(candidates) != 1:
                raise ContractError("registry token response must carry exactly one token")
            print(candidates[0])
        elif args.command == "registry-manifest":
            print(
                validate_registry_manifest_response(
                    args.http_status,
                    args.body.read_bytes(),
                    args.headers.read_text(encoding="utf-8"),
                    expected_digest=args.expected_digest,
                )
            )
        elif args.command == "chart-digest-embed":
            # The runner's working copy only. Nothing is committed: the
            # reviewed tree keeps the sentinel, and the writer re-reads its
            # own output so a successful exit already proves the postcondition
            # the packaged archive is about to inherit.
            embedded = embed_chart_image_digest(
                args.values.read_text(encoding="utf-8"), args.digest
            )
            args.values.write_text(embedded, encoding="utf-8", newline="\n")
            print(
                require_embedded_chart_digest(
                    args.values.read_text(encoding="utf-8"), args.digest
                )
            )
        elif args.command == "chart-digest-verify":
            print(
                require_embedded_chart_digest(
                    args.values.read_text(encoding="utf-8"), args.digest
                )
            )
        elif args.command == "json-keys":
            # Security evidence emitted by Buildx is still untrusted input.
            # _read_object applies the same recursive duplicate-member and
            # non-finite-value rejection used for every REST/event boundary.
            keys = sorted(_read_object(args.json))
            sys.stdout.buffer.write("".join(f"{key}\n" for key in keys).encode("utf-8"))
        elif args.command == "attestation-statement":
            statement = build_attestation_statement(
                _read_object(args.predicate),
                image=args.image,
                digest=args.digest,
                source=args.source,
                revision=args.revision,
                platform=args.platform,
                builder_run_id=args.builder_run_id,
            )
            # The predicate-output file is the exact bytes cosign embeds when
            # signing via --predicate/--type: it is what the workflow passes
            # to `cosign attest`, while --output stays the full expected
            # in-toto statement used only to validate cosign's later verified
            # output (never fed to cosign itself — --statement is dead on
            # image attest).
            args.predicate_output.write_text(
                json.dumps(statement["predicate"], sort_keys=True) + "\n", encoding="utf-8"
            )
            args.output.write_text(json.dumps(statement, sort_keys=True) + "\n", encoding="utf-8")
        elif args.command == "attestation-builder-run":
            print(read_attestation_builder_run(_read_object(args.predicate), source=args.source))
        elif args.command == "attestation-set":
            expected: dict[str, Mapping[str, object]] = {}
            for item in args.expected:
                platform, separator, raw_path = item.partition("=")
                if not separator or not platform or platform in expected:
                    raise ContractError("expected attestation arguments must be unique platform=path pairs")
                expected[platform] = _read_object(Path(raw_path))
            print(validate_attestation_set(args.verified.read_text(encoding="utf-8"), expected))
        elif args.command == "sbom-platforms":
            documents = validate_sbom_platform_map(_read_object(args.json))
            sys.stdout.buffer.write(
                "".join(f"{platform}\n" for platform in documents).encode("utf-8")
            )
        elif args.command == "sbom-statement":
            statement = build_sbom_statement(
                _read_object(args.spdx),
                image=args.image,
                digest=args.digest,
                platform=args.platform,
            )
            args.predicate_output.write_text(
                json.dumps(statement["predicate"], sort_keys=True) + "\n", encoding="utf-8"
            )
            args.output.write_text(
                json.dumps(statement, sort_keys=True) + "\n", encoding="utf-8"
            )
        elif args.command == "sbom-set":
            expected_sboms: dict[str, Mapping[str, object]] = {}
            for item in args.expected:
                platform, separator, raw_path = item.partition("=")
                if not separator or not platform or platform in expected_sboms:
                    raise ContractError(
                        "expected SBOM arguments must be unique platform=path pairs"
                    )
                expected_sboms[platform] = _read_object(Path(raw_path))
            print(
                validate_sbom_attestation_set(
                    args.verified.read_text(encoding="utf-8"), expected_sboms
                )
            )
        elif args.command == "trivy-source":
            print(
                validate_trivy_source_report(
                    _read_object(args.report), _read_object(args.package_json)
                )
            )
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
