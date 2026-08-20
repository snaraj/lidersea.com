#!/usr/bin/env python3
"""Fail-closed schema validator for .github/dependabot.yml.

Nothing in this repository validated the Dependabot config file: actionlint
covers `.github/workflows/*.yml` only, and the release contract's own
workflow sweep globs the same path. A schema-invalid `groups` stanza (typoed
key, unknown field) therefore reached `main` unchallenged and would only
surface as a Dependabot service error, post-merge, off-repository. The
adversarial review of PR #55 proved this gap with a live mutant (finding 1):
renaming `patterns:` to `patternz:` and adding a `bogus-key: 12345` under a
group survived every existing gate. This module closes it.

Standard-library only, same discipline as `release_contract.py`: CI and its
hostile tests share these functions, so the schema cannot drift into
prose-only convention. There is no PyYAML in this repository (requirement 9,
dependency-free); the hand-rolled indentation reader in
`scripts/ci/chart-ingress-pin.sh` is the existing precedent for reading YAML
without a parser dependency. This module follows the same approach in
Python: a small block-style (mappings and sequences by indentation) reader
scoped to exactly the subset `dependabot.yml` uses, then a schema-specific
semantic pass. It is deliberately not a general YAML parser: flow-style
collections (`[...]`, `{...}`), anchors, aliases, tags, and block scalars
are all unsupported and rejected rather than approximated, and any line the
reader cannot place is rejected outright. Conservative and fail-closed:
"unparseable" and "invalid" are the same outcome.

This reader is narrower than general YAML in ways worth stating rather
than discovering by accident (each pinned by a dedicated rejection test
in test_dependabot_contract.py):

- Comments are not supported anywhere -- full-line or trailing, quoted
  context or not -- and a `#` character anywhere in the source is
  rejected outright rather than stripped. A trailing `#` was previously
  silently folded into the scalar it followed (an adversarial review of
  this module found it: a `- # comment` null item was accepted as
  literal pattern text). Distinguishing a real comment start from a
  literal `#` inside a quoted scalar is real parser work this module
  does not attempt, so every `#` refuses the file instead of guessing.
  dependabot.yml carries no comments today.
- Scalars reject C0/C1 control characters, DEL, and the Unicode line and
  paragraph separators, matching real YAML's printable-character rule.
- Mapping keys, including group names under `groups:`, are restricted to
  `[A-Za-z][A-Za-z0-9_.-]*` with no quoting escape hatch -- narrower than
  Dependabot's own arbitrary-string group names.
- A block sequence must be indented STRICTLY deeper than its key; the
  same-indent form (`patterns:` then `- x` at the same column -- valid,
  idiomatic YAML) is rejected as a bare key with no value.
- A UTF-8 byte-order mark at the start of the file is named and rejected
  rather than left to surface as an unrelated, confusing parse error.

Every one of these fails closed -- narrower than necessary, never wider.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import NoReturn


class ContractError(ValueError):
    """The Dependabot config does not satisfy the fail-closed schema."""


# ---------------------------------------------------------------------------
# The block tree: every node remembers the source line it came from, so every
# rejection cites an exact line, never a byte offset or a vague "somewhere".
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Scalar:
    line: int
    text: str
    quoted: bool


@dataclass(frozen=True)
class Sequence:
    line: int
    items: list["Node"]


@dataclass(frozen=True)
class Mapping:
    line: int
    items: dict[str, "Node"] = field(default_factory=dict)
    key_lines: dict[str, int] = field(default_factory=dict)


Node = Scalar | Sequence | Mapping


@dataclass(frozen=True)
class _Line:
    no: int
    indent: int
    content: str


KEY_RE = re.compile(r"^([A-Za-z][A-Za-z0-9_.-]*):(?: (.*))?$")


def _fail(line: int, message: str) -> NoReturn:
    raise ContractError(f"line {line}: {message}")


BOM = "\ufeff"


def _tokenize(text: str) -> list[_Line]:
    if text.startswith(BOM):
        _fail(1, "a UTF-8 byte-order mark is not supported; save the file without a BOM")
    if "\t" in text:
        line_no = next(i for i, raw in enumerate(text.split("\n"), start=1) if "\t" in raw)
        _fail(line_no, "tab characters are not allowed; use spaces")
    if "\r" in text:
        line_no = next(i for i, raw in enumerate(text.split("\n"), start=1) if "\r" in raw)
        _fail(line_no, "carriage returns are not allowed; use bare LF line endings")
    if "#" in text:
        # Full-line AND inline, every position, quoted context or not: see
        # the module docstring. A prior version treated only a line whose
        # first non-space character was "#" as a comment and skipped it,
        # which silently folded every OTHER "#" (a trailing comment on real
        # content, or a bare "- # x" null item) into the scalar it followed
        # instead of rejecting it -- accept-what-it-cannot-place, exactly
        # what this reader promises never to do.
        line_no = next(i for i, raw in enumerate(text.split("\n"), start=1) if "#" in raw)
        _fail(line_no, "'#' comments are not supported, full-line or inline; remove the comment")

    lines: list[_Line] = []
    for no, raw in enumerate(text.split("\n"), start=1):
        if raw.strip() == "":
            continue
        stripped = raw.lstrip(" ")
        indent = len(raw) - len(stripped)
        content = stripped.rstrip()
        lines.append(_Line(no=no, indent=indent, content=content))
    return lines


# C0/C1 controls, DEL, and the Unicode line/paragraph separators: real YAML
# restricts scalars to printable characters, and none of these can appear in
# the shipped dependabot.yml, so treat them the same as any other construct
# this reader refuses rather than approximates.
_FORBIDDEN_SCALAR_RE = re.compile(
    "[\x00-\x1f\x7f-\x9f\u2028\u2029]"
)


def _reject_control_characters(text: str, line_no: int) -> None:
    match = _FORBIDDEN_SCALAR_RE.search(text)
    if match:
        _fail(line_no, f"scalar contains a forbidden control character U+{ord(match.group()):04X}")


def _parse_scalar_value(raw: str, line_no: int) -> Scalar:
    # `raw` is always the single-space-delimited remainder of an already
    # rstripped, non-blank tokenized line: KEY_RE's `(?: (.*))?` group only
    # captures after one literal space (so a bare "key:" with nothing after
    # never reaches here), and the sequence reader requires content[2] to be
    # non-space before slicing a scalar item's remainder. `value` below can
    # therefore never be empty -- proven, not merely assumed, by the review
    # fuzz campaign that found the redundant guard this comment replaces
    # (230,009 inputs, zero hits) -- so indexing value[0] is safe.
    value = raw.strip()
    if value[0] in "[{":
        _fail(line_no, "flow-style collections are not supported; use a block list or mapping")
    if value[0] in "&*!|>%@`?":
        _fail(line_no, f"unsupported YAML construct starting with {value[0]!r}")
    if value[0] in "\"'":
        quote = value[0]
        if len(value) < 2 or value[-1] != quote:
            _fail(line_no, "unterminated quoted scalar")
        inner = value[1:-1]
        if quote in inner:
            _fail(line_no, "quoted scalar contains an unescaped quote character")
        _reject_control_characters(inner, line_no)
        return Scalar(line=line_no, text=inner, quoted=True)
    if '"' in value or "'" in value:
        _fail(line_no, "unquoted scalar contains a quote character")
    _reject_control_characters(value, line_no)
    return Scalar(line=line_no, text=value, quoted=False)


def _parse_key_value(
    lines: list[_Line],
    i: int,
    indent: int,
    items: dict[str, Node],
    key_lines: dict[str, int],
) -> int:
    """Parse one `key:` or `key: value` line at lines[i] into items/key_lines.

    Consumes a nested block for a bare key. Returns the next index.
    """
    line = lines[i]
    match = KEY_RE.fullmatch(line.content)
    if not match:
        _fail(line.no, "expected a mapping key in the form 'key:' or 'key: value'")
    key, rest = match.group(1), match.group(2)
    if key in items:
        _fail(line.no, f"duplicate key {key!r}")
    key_lines[key] = line.no
    if rest is None:
        if i + 1 < len(lines) and lines[i + 1].indent > indent:
            child, next_i = _parse_node(lines, i + 1, lines[i + 1].indent)
            items[key] = child
            return next_i
        _fail(line.no, f"key {key!r} has no value")
    items[key] = _parse_scalar_value(rest, line.no)
    return i + 1


def _parse_mapping(lines: list[_Line], i: int, indent: int) -> tuple[Mapping, int]:
    start_line = lines[i].no
    items: dict[str, Node] = {}
    key_lines: dict[str, int] = {}
    while i < len(lines) and lines[i].indent == indent:
        if lines[i].content == "-" or lines[i].content.startswith("- "):
            _fail(lines[i].no, "expected a mapping key, found a sequence item")
        i = _parse_key_value(lines, i, indent, items, key_lines)
    if i < len(lines) and lines[i].indent > indent:
        _fail(lines[i].no, "unexpected indentation")
    return Mapping(line=start_line, items=items, key_lines=key_lines), i


def _parse_sequence(lines: list[_Line], i: int, indent: int) -> tuple[Sequence, int]:
    start_line = lines[i].no
    items: list[Node] = []
    while i < len(lines) and lines[i].indent == indent:
        content = lines[i].content
        if not (content == "-" or content.startswith("- ")):
            _fail(lines[i].no, "expected a sequence item, found a mapping key")
        line_no = lines[i].no

        if content == "-":
            if i + 1 < len(lines) and lines[i + 1].indent > indent:
                child, next_i = _parse_node(lines, i + 1, lines[i + 1].indent)
                items.append(child)
                i = next_i
                continue
            _fail(line_no, "sequence item has no value")

        if len(content) < 3 or content[1] != " " or content[2] == " ":
            _fail(line_no, "sequence item must be '- ' (dash, one space) followed by content")
        rest = content[2:]
        if rest[0] == "-" and (len(rest) == 1 or rest[1] == " "):
            _fail(line_no, "nested inline sequence markers are not supported")

        item_indent = indent + 2
        match = KEY_RE.fullmatch(rest)
        if match is None:
            items.append(_parse_scalar_value(rest, line_no))
            i += 1
            continue

        # Compact block mapping: "- key: value" opens a mapping whose first
        # key sits right after the dash; further keys of the SAME mapping
        # follow on their own lines, aligned to that column.
        key, value_rest = match.group(1), match.group(2)
        sub_items: dict[str, Node] = {}
        sub_key_lines: dict[str, int] = {key: line_no}
        if value_rest is None:
            if i + 1 < len(lines) and lines[i + 1].indent > item_indent:
                child, next_i = _parse_node(lines, i + 1, lines[i + 1].indent)
                sub_items[key] = child
                i = next_i
            else:
                _fail(line_no, f"key {key!r} has no value")
        else:
            sub_items[key] = _parse_scalar_value(value_rest, line_no)
            i += 1
        while i < len(lines) and lines[i].indent == item_indent:
            i = _parse_key_value(lines, i, item_indent, sub_items, sub_key_lines)
        if i < len(lines) and lines[i].indent > item_indent:
            _fail(lines[i].no, "unexpected indentation")
        items.append(Mapping(line=line_no, items=sub_items, key_lines=sub_key_lines))

    if i < len(lines) and lines[i].indent > indent:
        _fail(lines[i].no, "unexpected indentation")
    return Sequence(line=start_line, items=items), i


def _parse_node(lines: list[_Line], i: int, indent: int) -> tuple[Node, int]:
    content = lines[i].content
    if content == "-" or content.startswith("- "):
        return _parse_sequence(lines, i, indent)
    return _parse_mapping(lines, i, indent)


def parse_yaml_subset(text: str) -> Mapping:
    """Parse the block-style YAML subset this schema needs into a tree.

    Fails closed: any construct outside plain block mappings, block
    sequences, and quoted-or-plain scalars is rejected, never guessed at.
    """
    lines = _tokenize(text)
    if not lines:
        _fail(1, "file has no content")
    if lines[0].indent != 0:
        _fail(lines[0].no, "the document must start at column 0")
    node, next_i = _parse_node(lines, 0, 0)
    # next_i always equals len(lines) here: _parse_mapping and _parse_sequence
    # each already fail closed, from inside their own recursion, on any line
    # more indented than their own siblings before ever returning control to
    # their caller -- so no residual, unconsumed line can survive to be
    # inspected at this outer level. That inner enforcement is exercised
    # directly (see test_rejects_orphaned_indentation_not_tied_to_a_key and
    # its sequence-shaped siblings), which is what makes a duplicate check
    # here provably redundant rather than merely assumed safe.
    assert next_i == len(lines)
    if not isinstance(node, Mapping):
        _fail(lines[0].no, "the top-level document must be a mapping")
    return node


# ---------------------------------------------------------------------------
# Semantic schema for the dependabot.yml subset this repository uses.
#
# Every allowlist below is deliberately closed to what this repository's own
# config actually needs, mirroring the repository's other narrow-allowlist
# precedents (the ratings-platform host allowlist in internal/ratings, the
# ingress provider binding): widening one is a reviewed code change here,
# never silent drift. GitHub's real dependabot.yml schema is broader (e.g.
# `target-branch`, `labels`, `ignore`, `registries`); this validator does not
# recognize those keys today, and a PR introducing one must extend this
# schema in the same commit.
# ---------------------------------------------------------------------------

# GitHub's documented package-ecosystem identifiers.
ECOSYSTEMS = frozenset(
    {
        "bun",
        "bundler",
        "cargo",
        "composer",
        "devcontainers",
        "docker",
        "docker-compose",
        "dotnet-sdk",
        "elm",
        "github-actions",
        "gitsubmodule",
        "gomod",
        "gradle",
        "helm",
        "maven",
        "mix",
        "npm",
        "nuget",
        "pip",
        "pub",
        "swift",
        "terraform",
        "uv",
        "vcpkg",
    }
)

TOP_KEYS = frozenset({"version", "updates"})

ENTRY_REQUIRED = frozenset({"package-ecosystem", "directory", "schedule"})
ENTRY_ALLOWED = ENTRY_REQUIRED | frozenset({"open-pull-requests-limit", "groups"})

SCHEDULE_INTERVALS = frozenset({"daily", "weekly", "monthly"})
SCHEDULE_REQUIRED = frozenset({"interval"})
SCHEDULE_ALLOWED = SCHEDULE_REQUIRED | frozenset({"day", "time", "timezone"})
WEEKDAYS = frozenset(
    {"monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"}
)
TIME_RE = re.compile(r"^([01][0-9]|2[0-3]):[0-5][0-9]$")
TIMEZONE_RE = re.compile(r"^[A-Za-z0-9_+-]+(/[A-Za-z0-9_+-]+)*$")

GROUP_REQUIRED = frozenset({"patterns"})
GROUP_ALLOWED = GROUP_REQUIRED | frozenset(
    {"exclude-patterns", "dependency-type", "update-types", "applies-to"}
)
DEPENDENCY_TYPES = frozenset({"production", "development"})
UPDATE_TYPES = frozenset({"major", "minor", "patch"})
APPLIES_TO = frozenset({"version-updates", "security-updates"})

OPEN_PR_LIMIT_RE = re.compile(r"^(0|[1-9][0-9]*)$")


def _as_mapping(node: Node, line: int, what: str) -> Mapping:
    if not isinstance(node, Mapping):
        _fail(line, f"{what} must be a mapping")
    return node


def _as_sequence(node: Node, line: int, what: str) -> Sequence:
    if not isinstance(node, Sequence):
        _fail(line, f"{what} must be a list")
    return node


def _as_scalar(node: Node, line: int, what: str) -> Scalar:
    if not isinstance(node, Scalar):
        _fail(line, f"{what} must be a plain value, not a nested list or mapping")
    return node


def _check_keys(mapping: Mapping, allowed: frozenset[str], required: frozenset[str], what: str) -> None:
    unknown = sorted(set(mapping.items) - allowed)
    if unknown:
        _fail(mapping.key_lines[unknown[0]], f"unknown key {unknown[0]!r} in {what}")
    missing = sorted(required - set(mapping.items))
    if missing:
        _fail(mapping.line, f"{what} is missing required key {missing[0]!r}")


def _string_list(node: Node, line: int, what: str) -> list[Scalar]:
    sequence = _as_sequence(node, line, what)
    # The block-sequence reader can only ever produce a Sequence with at
    # least one item (an empty block sequence has no textual form; the flow
    # form `[]` is rejected earlier as a flow-style collection), so list
    # emptiness is already unrepresentable by construction here — the
    # per-item scalar check below is what remains to prove.
    return [_as_scalar(item, sequence.line, what) for item in sequence.items]


def _validate_schedule(schedule_node: Node, line: int, what: str) -> None:
    schedule = _as_mapping(schedule_node, line, what)
    _check_keys(schedule, SCHEDULE_ALLOWED, SCHEDULE_REQUIRED, what)
    interval = _as_scalar(schedule.items["interval"], schedule.key_lines["interval"], f"{what}.interval")
    if interval.text not in SCHEDULE_INTERVALS:
        _fail(interval.line, f"unknown {what}.interval {interval.text!r}")
    if "day" in schedule.items:
        day = _as_scalar(schedule.items["day"], schedule.key_lines["day"], f"{what}.day")
        if day.text not in WEEKDAYS:
            _fail(day.line, f"unknown {what}.day {day.text!r}")
    if "time" in schedule.items:
        time_value = _as_scalar(schedule.items["time"], schedule.key_lines["time"], f"{what}.time")
        if not TIME_RE.fullmatch(time_value.text):
            _fail(time_value.line, f"{what}.time must be 24-hour HH:MM")
    if "timezone" in schedule.items:
        timezone = _as_scalar(schedule.items["timezone"], schedule.key_lines["timezone"], f"{what}.timezone")
        if not TIMEZONE_RE.fullmatch(timezone.text):
            _fail(timezone.line, f"{what}.timezone is not a recognizable identifier")


def _validate_group(name: str, spec_node: Node, line: int) -> None:
    what = f"groups.{name}"
    spec = _as_mapping(spec_node, line, what)
    _check_keys(spec, GROUP_ALLOWED, GROUP_REQUIRED, what)

    for pattern in _string_list(spec.items["patterns"], spec.key_lines["patterns"], f"{what}.patterns"):
        if not pattern.text:
            _fail(pattern.line, f"{what}.patterns entries must be non-empty strings")

    if "exclude-patterns" in spec.items:
        excludes = _string_list(
            spec.items["exclude-patterns"], spec.key_lines["exclude-patterns"], f"{what}.exclude-patterns"
        )
        for pattern in excludes:
            if not pattern.text:
                _fail(pattern.line, f"{what}.exclude-patterns entries must be non-empty strings")

    if "dependency-type" in spec.items:
        dependency_type = _as_scalar(
            spec.items["dependency-type"], spec.key_lines["dependency-type"], f"{what}.dependency-type"
        )
        if dependency_type.text not in DEPENDENCY_TYPES:
            _fail(dependency_type.line, f"unknown {what}.dependency-type {dependency_type.text!r}")

    if "update-types" in spec.items:
        for update_type in _string_list(
            spec.items["update-types"], spec.key_lines["update-types"], f"{what}.update-types"
        ):
            if update_type.text not in UPDATE_TYPES:
                _fail(update_type.line, f"unknown {what}.update-types entry {update_type.text!r}")

    if "applies-to" in spec.items:
        applies_to = _as_scalar(spec.items["applies-to"], spec.key_lines["applies-to"], f"{what}.applies-to")
        if applies_to.text not in APPLIES_TO:
            _fail(applies_to.line, f"unknown {what}.applies-to {applies_to.text!r}")


def validate_dependabot(tree: Mapping) -> tuple[int, int]:
    """Validate a parsed tree against the dependabot.yml schema.

    Returns (update entry count, group count) for a friendly summary.
    Raises ContractError, citing an exact source line, on any violation.
    """
    _check_keys(tree, TOP_KEYS, TOP_KEYS, "the top-level document")

    version = _as_scalar(tree.items["version"], tree.key_lines["version"], "version")
    if version.quoted or version.text != "2":
        _fail(version.line, "version must be the unquoted integer 2")

    updates = _as_sequence(tree.items["updates"], tree.key_lines["updates"], "updates")
    # As with patterns/exclude-patterns/update-types above: the reader can
    # only produce a non-empty Sequence here, so "updates must be non-empty"
    # is already enforced by construction — an empty `updates:` (no items,
    # or the rejected flow form `[]`) never reaches this point as a Sequence
    # at all.

    group_count = 0
    for index, entry_node in enumerate(updates.items):
        what = f"updates[{index}]"
        entry = _as_mapping(entry_node, entry_node.line, what)
        _check_keys(entry, ENTRY_ALLOWED, ENTRY_REQUIRED, what)

        ecosystem = _as_scalar(
            entry.items["package-ecosystem"], entry.key_lines["package-ecosystem"], f"{what}.package-ecosystem"
        )
        if ecosystem.text not in ECOSYSTEMS:
            _fail(ecosystem.line, f"unknown package-ecosystem {ecosystem.text!r}")

        directory = _as_scalar(entry.items["directory"], entry.key_lines["directory"], f"{what}.directory")
        if not directory.text.startswith("/"):
            _fail(directory.line, f"{what}.directory must start with '/'")

        _validate_schedule(entry.items["schedule"], entry.key_lines["schedule"], f"{what}.schedule")

        if "open-pull-requests-limit" in entry.items:
            limit = _as_scalar(
                entry.items["open-pull-requests-limit"],
                entry.key_lines["open-pull-requests-limit"],
                f"{what}.open-pull-requests-limit",
            )
            if limit.quoted or not OPEN_PR_LIMIT_RE.fullmatch(limit.text):
                _fail(limit.line, f"{what}.open-pull-requests-limit must be an unquoted non-negative integer")

        if "groups" in entry.items:
            groups = _as_mapping(entry.items["groups"], entry.key_lines["groups"], f"{what}.groups")
            for name, spec_node in groups.items.items():
                _validate_group(name, spec_node, groups.key_lines[name])
                group_count += 1

    return len(updates.items), group_count


def check_text(text: str) -> tuple[int, int]:
    """Parse and validate dependabot.yml source text. Raises ContractError."""
    return validate_dependabot(parse_yaml_subset(text))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Fail-closed schema validator for a Dependabot config file."
    )
    parser.add_argument("path", type=Path, help="path to the dependabot.yml file to validate")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        text = args.path.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"DENY: {args.path}: {exc}", file=sys.stderr)
        return 2
    except UnicodeDecodeError as exc:
        print(f"DENY: {args.path}: {exc}", file=sys.stderr)
        return 2

    try:
        entry_count, group_count = check_text(text)
    except ContractError as exc:
        print(f"DENY: {args.path}: {exc}", file=sys.stderr)
        return 2

    entry_word = "entry" if entry_count == 1 else "entries"
    group_word = "group" if group_count == 1 else "groups"
    print(f"dependabot_contract: OK - {args.path}: {entry_count} update {entry_word}, {group_count} {group_word}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
