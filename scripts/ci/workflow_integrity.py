"""Narrow workflow-integrity rules for ``.github/workflows``.

WHAT THIS MODULE IS FOR
=======================

Three specific, dangerous constructs can each turn a red gate green — or run
an unpinned tool — while every other check in this repository stays green and
every pinned value still *reads* correct:

  R1  ``continue-on-error: true`` on a job (or a step) that belongs to the
      required-checks set.  GitHub reports the job as a success, so branch
      protection is satisfied by a job that actually failed.
  R2  A step-level ``env:`` key that captures a pin — either by SHADOWING a
      workflow-level or job-level ``env:`` key of the same name, or by
      re-binding one of the tool-version/checksum variables that
      ``scripts/ci/install-tools.sh`` pins.  The pin at the top of the file
      still reads correct; the step runs with a different value.
  R3  A custom ``shell:`` on a step of a required-checks job.  The default
      Linux shell is ``bash -e {0}``; a custom shell can change failure
      semantics — most importantly it can drop ``pipefail``, so the exit
      status of a pipeline stops being the status of the command that failed.

WHAT THIS MODULE DELIBERATELY IS *NOT*
======================================

**There is no closed step inventory here, and one must never be added.**

It is tempting to "finish" this gate by asserting that job ``security``
contains exactly steps A, B, C, ... in exactly that order.  Do not.  That is
an INVENTORY PIN, and inventory pins are the failure mode this file exists to
avoid:

  * Every legitimate step addition breaks it.  Adding a test suite, a
    checkout option, or a new scanner is ordinary active development, but an
    inventory pin turns each one into a red build in a file nobody was
    editing.
  * It teaches the wrong reflex.  The cheapest way past a broken inventory
    pin is to update the inventory, so agents learn to re-record whatever the
    workflow now says instead of asking whether the change was safe.  A pin
    that is routinely rubber-stamped has negative value: it costs CI cycles
    and buys a signature nobody reads.
  * It pins the wrong thing.  "These are the steps" is not a security
    property.  "No gate step may silently swallow its own failure" is.

So every rule below refuses a NAMED DANGEROUS CONSTRUCT and is silent about
everything else.  A workflow may grow any number of steps without touching
this file.  If a rule here ever needs to be widened, that is what the
allowlist is for — see below — not a new inventory.

THE LIFT MECHANISM
==================

Every rule ships with a documented way to lift it: one line in
``scripts/ci/ci_gate_allowlist.toml`` under ``[workflow_integrity]``, carrying
a written reason.  Widening it is a one-line change in one PR and a normal
part of active development.  Every failure message below prints the exact
line to add, so an agent that trips a rule is told precisely how to proceed
rather than left to reverse-engineer the gate.

READER SCOPE
============

Requirements 1 and 9 leave no PyYAML and no yq, so this module reads the
block-YAML subset that GitHub workflow files actually use, and REFUSES what it
cannot read rather than guessing — an unreadable workflow is a red gate, never
a quiet pass.  It deliberately does not evaluate ``run:`` bodies: block
scalars are consumed opaquely, so a shell script that merely contains the text
``shell:`` or ``env:`` can never be mistaken for workflow structure.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
WORKFLOW_DIR = REPO_ROOT / ".github" / "workflows"
ALLOWLIST_PATH = REPO_ROOT / "scripts" / "ci" / "ci_gate_allowlist.toml"
ALLOWLIST_TABLE = "workflow_integrity"
INSTALL_TOOLS = REPO_ROOT / "scripts" / "ci" / "install-tools.sh"

# A pin variable is one `install-tools.sh` assigns at top level. Derived from
# the script on every run, never hand-listed, so a newly pinned tool is
# protected the moment it is pinned.
_PIN_ASSIGNMENT = re.compile(r"^([A-Z][A-Z0-9_]*)=", re.MULTILINE)

_BLOCK_SCALAR = re.compile(r"^[|>][+-]?[0-9]*$")
_KEY = re.compile(
    r"""^
    (?P<key>"[^"]*"|'[^']*'|[^\s:#'"][^:]*?)   # bare, "quoted" or 'quoted'
    \s*:                                        # `key:` and also `key :`
    (?:\s+(?P<value>.*?))?                      # optional inline value
    \s*$
    """,
    re.VERBOSE,
)


class WorkflowIntegrityError(ValueError):
    """A workflow this module cannot read, or an allowlist it cannot trust."""


class Node:
    """One mapping entry: its key, raw inline value, line number, children."""

    __slots__ = ("key", "value", "line", "children", "items")

    def __init__(self, key: str, value: str | None, line: int) -> None:
        self.key = key
        self.value = value
        self.line = line
        self.children: dict[str, Node] = {}
        self.items: list[dict[str, Node]] = []

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"Node({self.key!r}, {self.value!r}, line={self.line})"


def _unquote(key: str) -> str:
    if len(key) >= 2 and key[0] == key[-1] and key[0] in "\"'":
        return key[1:-1]
    return key


def scalar(value: str | None) -> str:
    """Normalize an inline scalar: strip a trailing comment and quotes."""
    if value is None:
        return ""
    text = value
    # A `#` starts a comment only when whitespace precedes it.
    cut = re.search(r"(?:^|\s)#", text)
    if cut:
        text = text[: cut.start()]
    text = text.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        text = text[1:-1]
    return text.strip()


def _ignorable(raw: str) -> bool:
    stripped = raw.strip()
    return not stripped or stripped.startswith("#")


def _indent_of(raw: str) -> int:
    return len(raw) - len(raw.lstrip(" "))


def parse_workflow(text: str, origin: str) -> dict[str, Node]:
    """Read the block-YAML subset workflows use. Refuse anything else."""
    lines = text.split("\n")
    for number, raw in enumerate(lines, start=1):
        if "\t" in raw[: _indent_of(raw) + 1] or raw.startswith("\t"):
            raise WorkflowIntegrityError(
                f"{origin} line {number}: tab in indentation; refusing to guess"
            )
    mapping, index = _read_mapping(lines, 0, 0, origin)
    while index < len(lines) and _ignorable(lines[index]):
        index += 1
    if index < len(lines):
        raise WorkflowIntegrityError(
            f"{origin} line {index + 1}: unreadable trailing content"
        )
    return mapping


def _skip_block_scalar(lines: list[str], index: int, key_indent: int) -> int:
    """Consume an opaque block scalar body: everything indented past the key."""
    while index < len(lines):
        raw = lines[index]
        if raw.strip() and _indent_of(raw) <= key_indent:
            break
        index += 1
    return index


def _read_mapping(
    lines: list[str], index: int, indent: int, origin: str
) -> tuple[dict[str, Node], int]:
    mapping: dict[str, Node] = {}
    while index < len(lines):
        raw = lines[index]
        if _ignorable(raw):
            index += 1
            continue
        here = _indent_of(raw)
        if here < indent:
            break
        if here > indent:
            raise WorkflowIntegrityError(
                f"{origin} line {index + 1}: unexpected indentation {here}, "
                f"expected {indent}; refusing to guess the structure"
            )
        body = raw.strip()
        if body.startswith("- "):
            break
        match = _KEY.match(body)
        if not match:
            raise WorkflowIntegrityError(
                f"{origin} line {index + 1}: not a readable mapping entry: {body!r}"
            )
        key = _unquote(match.group("key").strip())
        value = match.group("value")
        node = Node(key, value, index + 1)
        if key in mapping:
            raise WorkflowIntegrityError(
                f"{origin} line {index + 1}: duplicate key {key!r}; "
                "a duplicate key silently overrides its twin"
            )
        mapping[key] = node
        index += 1
        if value is not None and _BLOCK_SCALAR.match(value.strip()):
            index = _skip_block_scalar(lines, index, here)
            continue
        if value is not None and value.strip():
            continue
        # A key with no inline value owns whatever is indented beneath it.
        index = _read_child(lines, index, here, node, origin)
    return mapping, index


def _read_child(
    lines: list[str], index: int, key_indent: int, node: Node, origin: str
) -> int:
    look = index
    while look < len(lines) and _ignorable(lines[look]):
        look += 1
    if look >= len(lines):
        return look
    child_indent = _indent_of(lines[look])
    if child_indent <= key_indent:
        return index
    if lines[look].strip().startswith("- "):
        node.items, index = _read_sequence(lines, look, child_indent, origin)
        return index
    node.children, index = _read_mapping(lines, look, child_indent, origin)
    return index


def _read_sequence(
    lines: list[str], index: int, indent: int, origin: str
) -> tuple[list[dict[str, Node]], int]:
    items: list[dict[str, Node]] = []
    while index < len(lines):
        raw = lines[index]
        if _ignorable(raw):
            index += 1
            continue
        here = _indent_of(raw)
        if here < indent:
            break
        if here > indent or not raw.strip().startswith("- "):
            raise WorkflowIntegrityError(
                f"{origin} line {index + 1}: unreadable sequence entry"
            )
        # Rewrite `- key: value` as a mapping starting two columns right, so a
        # list item is read by exactly the same code as any other mapping.
        rest = raw[here + 2 :]
        if not _KEY.match(rest.strip()):
            # A scalar list entry (`- completed`). Nothing here to inspect.
            items.append({})
            index += 1
            continue
        shifted = list(lines)
        shifted[index] = " " * (here + 2) + rest
        item, index = _read_mapping(shifted, index, here + 2, origin)
        items.append(item)
    return items, index


def load_allowlist() -> dict[str, str]:
    """Read the shared lift mechanism. A malformed entry is a red gate."""
    if not ALLOWLIST_PATH.exists():
        raise WorkflowIntegrityError(f"missing allowlist file {ALLOWLIST_PATH}")
    data = tomllib.loads(ALLOWLIST_PATH.read_text(encoding="utf-8"))
    table = data.get(ALLOWLIST_TABLE, {})
    if not isinstance(table, dict):
        raise WorkflowIntegrityError(
            f"[{ALLOWLIST_TABLE}] in {ALLOWLIST_PATH} must be a table"
        )
    for entry, reason in table.items():
        if not isinstance(reason, str) or not reason.strip():
            raise WorkflowIntegrityError(
                f"allowlist entry {entry!r} has no written reason; "
                "an entry without a reason is not a decision, it is a hole"
            )
    return dict(table)


def pinned_tool_variables() -> frozenset[str]:
    """Every top-level variable `install-tools.sh` pins, read from the script."""
    if not INSTALL_TOOLS.exists():
        raise WorkflowIntegrityError(f"missing {INSTALL_TOOLS}")
    text = INSTALL_TOOLS.read_text(encoding="utf-8")
    return frozenset(_PIN_ASSIGNMENT.findall(text))


def gate_job_names(required_checks: tuple[str, ...], main_jobs: dict[str, str]) -> frozenset[str]:
    """Jobs whose result a branch-protection rule or the release gate reads.

    Derived from `release_contract.py`'s own constants, never hand-listed. A
    matrix check reads `analyze (go, manual)`; the JOB is `analyze`, so the
    base name before the first ` (` is what a workflow file calls it.
    """
    names = {check.split(" (", 1)[0] for check in required_checks}
    names.update(main_jobs)
    return frozenset(names)


def _lift(entry: str, reason: str = "why this construct is safe here") -> str:
    return (
        f"\n  LIFT: this rule is liftable in one line. Add to the "
        f"[{ALLOWLIST_TABLE}] table of\n"
        f"        {ALLOWLIST_PATH.relative_to(REPO_ROOT)}:\n\n"
        f'          "{entry}" = "{reason}"\n\n'
        "        Widening an allowlist with a written reason is a one-line PR and a\n"
        "        normal part of active development, not a security event."
    )


def check_workflow(
    path: Path,
    document: dict[str, Node],
    gate_jobs: frozenset[str],
    pinned: frozenset[str],
    allowlist: dict[str, str],
) -> list[str]:
    """Return one finding per violated rule. Empty list means green."""
    findings: list[str] = []
    name = path.name
    workflow_env = set(document["env"].children) if "env" in document else set()
    jobs_node = document.get("jobs")
    if jobs_node is None:
        return findings

    for job_name, job in jobs_node.children.items():
        is_gate = job_name in gate_jobs
        job_env = set(job.children["env"].children) if "env" in job.children else set()

        # R1 (job level)
        if is_gate and "continue-on-error" in job.children:
            node = job.children["continue-on-error"]
            if scalar(node.value).lower() == "true":
                entry = f"{name}::{job_name}::continue-on-error"
                if entry not in allowlist:
                    findings.append(
                        f"{name}:{node.line}: job '{job_name}' is in the "
                        f"required-checks set and sets continue-on-error: true.\n"
                        "  A failing required check would report success and "
                        "branch protection would be satisfied by a red gate."
                        + _lift(entry)
                    )

        steps = job.children.get("steps")
        if steps is None:
            continue
        for position, step in enumerate(steps.items, start=1):
            label = scalar(step["name"].value) if "name" in step else f"step {position}"
            anchor = step.get("name") or next(iter(step.values()), None)
            line = anchor.line if anchor is not None else job.line

            # R1 (step level) — same failure mode, one level down.
            if is_gate and "continue-on-error" in step:
                node = step["continue-on-error"]
                if scalar(node.value).lower() == "true":
                    entry = f"{name}::{job_name}::{label}::continue-on-error"
                    if entry not in allowlist:
                        findings.append(
                            f"{name}:{node.line}: step '{label}' of "
                            f"required-checks job '{job_name}' sets "
                            "continue-on-error: true.\n"
                            "  The step can fail while the job — and the "
                            "required check — still reports success."
                            + _lift(entry)
                        )

            # R3 — a custom shell on a gate step.
            if is_gate and "shell" in step:
                node = step["shell"]
                entry = f"{name}::{job_name}::{label}::shell"
                if entry not in allowlist:
                    findings.append(
                        f"{name}:{node.line}: step '{label}' of required-checks "
                        f"job '{job_name}' declares a custom shell "
                        f"({scalar(node.value)!r}).\n"
                        "  A custom shell changes failure semantics — it can drop "
                        "pipefail, so a\n  pipeline reports the exit status of its "
                        "last command instead of the one that failed."
                        + _lift(entry)
                    )

            # R2 — a step-level env that captures a pin.
            if "env" not in step:
                continue
            for var, node in step["env"].children.items():
                shadowed = var in workflow_env or var in job_env
                tool_pin = var in pinned
                if not shadowed and not tool_pin:
                    continue
                entry = f"{name}::{job_name}::{label}::env::{var}"
                if entry in allowlist:
                    continue
                if tool_pin:
                    why = (
                        f"'{var}' is a tool pin assigned in "
                        "scripts/ci/install-tools.sh.\n"
                        "  A step-level binding runs a different tool while the "
                        "pin in that script still reads correct."
                    )
                else:
                    where = "workflow-level" if var in workflow_env else "job-level"
                    why = (
                        f"'{var}' is already pinned by the {where} env: block.\n"
                        "  The step-level binding wins, so the step runs with a "
                        "value the pin above does not state."
                    )
                findings.append(
                    f"{name}:{node.line}: step '{label}' of job '{job_name}' "
                    f"overrides a pinned variable — {why}" + _lift(entry)
                )
    return findings


def audit() -> list[str]:
    """Run every rule over every workflow. Returns the complete finding list."""
    import importlib.util
    import sys

    spec = importlib.util.spec_from_file_location(
        "_release_contract_for_gate", REPO_ROOT / "scripts" / "ci" / "release_contract.py"
    )
    if spec is None or spec.loader is None:  # pragma: no cover - import plumbing
        raise WorkflowIntegrityError("cannot load release_contract.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)

    gate_jobs = gate_job_names(module.REQUIRED_STATUS_CHECKS, module.PR_GATE_MAIN_JOBS)
    pinned = pinned_tool_variables()
    allowlist = load_allowlist()

    findings: list[str] = []
    paths = sorted(WORKFLOW_DIR.glob("*.yml"))
    if not paths:
        raise WorkflowIntegrityError(f"no workflows found under {WORKFLOW_DIR}")
    for path in paths:
        document = parse_workflow(path.read_text(encoding="utf-8"), str(path))
        findings.extend(check_workflow(path, document, gate_jobs, pinned, allowlist))
    return findings
