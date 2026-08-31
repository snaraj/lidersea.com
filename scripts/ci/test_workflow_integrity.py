"""Hostile suite for the narrow workflow-integrity rules.

READ THIS BEFORE ADDING A TEST HERE
===================================

The imported gate pins THREE named dangerous constructs and the reader that
finds them. This suite separately binds every CodeQL init/analyze role to one
release tuple, over the surface GitHub can actually execute: both workflow
extensions, plus every same-repository action a workflow reaches through a
`./` reference, followed transitively. That surface is reachability and not a
directory convention on purpose -- the exact-head reviews got past a
workflows-only sweep with a wrapper under `.github/actions`, and past that
sweep by moving the same wrapper one directory outside it.

Neither rule pins a step inventory, and one must never be added
— not here, and not in `scripts/ci/workflow_integrity.py`.

A step inventory is the assertion "job X contains exactly these steps". It
looks like rigour and behaves like sand:

  * This repository is under active development. Adding a scanner, a suite, or
    a checkout option is ordinary work, and an inventory pin turns every one of
    those into a red build in a file the author was not editing.
  * The cheapest way past it is to re-record it, so agents learn to copy the
    new step list into the pin instead of asking whether the change was safe.
    A pin that is reflexively rubber-stamped costs CI time and buys nothing.
  * It pins a fact that is not a security property. "These are the steps" says
    nothing about whether a gate can fail. "No required-check step may swallow
    its own failure" does, and survives every legitimate step addition.

The lane that motivated this rule spent six releases, six owner merges, and
six cluster slots discovering — one per cycle — that a pinned exhaustive
object shape keeps meeting legitimate additions it never anticipated. Each
refusal was individually correct and collectively a waste. Do not rebuild that
here.

If a rule below is wrong for a specific reviewed case, lift it with one line
in `scripts/ci/ci_gate_allowlist.toml`. That is the intended path, and
`TheOneLineLiftWorksEndToEnd` at the bottom of this file proves the path is
open rather than assuming it. An assertion that the shipped table is EMPTY
belongs to the same family as a step inventory — it is an inventory pin on the
lift mechanism itself, true only until the first legitimate entry — and one
lived here until 0.1.37. Do not put it back.
"""

from __future__ import annotations

import re
import sys
import tempfile
import tomllib
import unittest
from collections.abc import Iterator
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import workflow_integrity as WI  # noqa: E402

GATE_JOBS = frozenset({"security", "application", "chart", "analyze"})
PINNED = frozenset({"TRIVY_VERSION", "TRIVY_SHA256", "HELM_VERSION"})
CODEQL_ROLE_PREFIX = re.compile(
    r"^github/codeql-action/(init|analyze)@",
    re.IGNORECASE,
)
CODEQL_ROLE_REFERENCE = re.compile(
    r"^github/codeql-action/(init|analyze)@([0-9a-f]{40})$",
    re.IGNORECASE,
)
CODEQL_VERSION_COMMENT = re.compile(r"\s+#\s+(v[0-9]+\.[0-9]+\.[0-9]+)\s*$")
# A `uses:` value is a REFERENCE, and `WI.scalar` is a normalizer rather than a
# resolver: it strips a comment and quotes and hands back whatever remains. That
# is safe for a value some rule then compares, and unsafe here, where a value
# this reader does not recognise means an action nothing holds to a release.
# Recognised spellings only; everything else RAISES.
USES_REFERENCE = re.compile(r"^[A-Za-z0-9_.][A-Za-z0-9_./@:+-]*$")


def workflow_files(workflow_dir: Path = WI.WORKFLOW_DIR) -> list[Path]:
    """Return every workflow extension GitHub accepts."""
    return sorted((*workflow_dir.glob("*.yml"), *workflow_dir.glob("*.yaml")))


def resolve_uses(node: WI.Node, origin: str) -> str:
    """Resolve one `uses:` reference, or REFUSE. Never returns a guess.

    The exact-head review beat the previous reader with
    `!!str github/codeql-action/init@<old sha>`: an explicit tag is a spelling
    a real parser and `actionlint` both accept, the tagged text does not START
    with `github/`, and a reader that skips what it does not recognise made
    that spelling the silent pass. Refusing is the only safe direction, and it
    costs nothing -- no workflow or action here writes an exotic reference.
    """
    value = WI.scalar(node.value)
    if not USES_REFERENCE.fullmatch(value):
        raise WI.WorkflowIntegrityError(
            f"{origin}:{node.line}: this reader cannot resolve the `uses:` "
            f"reference `{value}`. It resolves a plain reference or a quoted "
            f"one and refuses everything else, because an action it cannot "
            f"name is an action it cannot hold to a release."
        )
    return value


def local_action_entrypoint(root: Path, reference: str, origin: str, line: int) -> Path:
    """Resolve a `./` reference to the file GitHub executes, or REFUSE.

    A same-repository action lives at ANY repository-relative directory holding
    `action.yml` or `action.yaml`. `.github/actions` is a convention and
    nothing more; following the reference is what makes the sweep below the
    executable namespace rather than a naming habit.

    Both `./` spellings resolve here, because `uses:` carries both: a job-level
    local REUSABLE WORKFLOW names its file (`./.github/workflows/x.yml`), while
    a step-level local ACTION names the directory holding its metadata. Reading
    only the second refused the first, which is a legitimate construct this
    repository may add on any ordinary day -- a gate that reddens on new work
    it never anticipated is the failure this suite's own contract forbids.
    """
    target = root / reference[2:]
    candidates = (
        (target,)
        if target.suffix in (".yml", ".yaml")
        else (target / "action.yml", target / "action.yaml")
    )
    for entrypoint in candidates:
        if entrypoint.is_file():
            return entrypoint
    raise WI.WorkflowIntegrityError(
        f"{origin}:{line}: the same-repository reference `{reference}` names "
        f"neither a workflow file nor a directory holding an `action.yml` or "
        f"`action.yaml`, so this reader cannot see what runs."
    )


def walk_nodes(mapping: dict[str, WI.Node]) -> Iterator[WI.Node]:
    """Yield every structurally parsed mapping node at every sequence depth."""
    for node in mapping.values():
        yield node
        yield from walk_nodes(node.children)
        for item in node.items:
            yield from walk_nodes(item)


def codeql_lockstep_problems(workflow_dir: Path = WI.WORKFLOW_DIR) -> list[str]:
    """Require every CodeQL role to resolve to one full SHA/version tuple.

    Reads from disk and expands as it goes: the workflows GitHub runs, then
    every same-repository action they reach through a `./` reference,
    transitively, because a composite can call another composite. There is no
    injectable text mapping -- WHAT THIS FINDS is half of what the rule
    asserts, and a dict handed in by a test proves nothing about a tree on
    disk. The exact-head review displaced the executed init into a composite
    behind an unreachable, version-matched direct call; a workflows-only sweep
    saw the decoy and called it lockstep.
    """
    root = workflow_dir.parents[1]
    texts = {
        path.relative_to(root).as_posix(): path.read_text(encoding="utf-8")
        for path in workflow_files(workflow_dir)
    }
    pending = sorted(texts)

    problems: list[str] = []
    references: list[tuple[str, str, str, str]] = []
    while pending:
        name = pending.pop()
        for node in walk_nodes(WI.parse_workflow(texts[name], name)):
            if node.key != "uses":
                continue
            value = resolve_uses(node, name)
            if value.startswith("./"):
                entrypoint = local_action_entrypoint(root, value, name, node.line)
                reached = entrypoint.relative_to(root).as_posix()
                if reached not in texts:
                    texts[reached] = entrypoint.read_text(encoding="utf-8")
                    pending.append(reached)
                continue
            if not CODEQL_ROLE_PREFIX.match(value):
                continue
            reference = CODEQL_ROLE_REFERENCE.fullmatch(value)
            version = CODEQL_VERSION_COMMENT.search(node.value or "")
            if reference is None or version is None:
                problems.append(
                    f"{name}:{node.line}: CodeQL role must use a full lowercase "
                    "SHA and trailing vX.Y.Z comment"
                )
                continue
            role, sha = reference.groups()
            references.append((role.lower(), sha, version[1], f"{name}:{node.line}"))

    roles = {role for role, _, _, _ in references}
    missing = {"init", "analyze"} - roles
    if missing:
        problems.append(f"missing CodeQL role references: {', '.join(sorted(missing))}")

    tuples = {(sha, version) for _, sha, version, _ in references}
    if len(tuples) != 1:
        rendered = ", ".join(
            f"{location}={role}@{sha}#{version}"
            for role, sha, version, location in references
        )
        problems.append(
            "CodeQL init/analyze roles must share one SHA/version tuple; " + rendered
        )
    return problems

#: The tracked allowlist exactly as it sits on disk at import time, captured
#: before any test can run. Two classes below rewrite that REAL file and put it
#: back in `finally`. A per-test "before" snapshot cannot police that restore:
#: it is read AFTER any earlier damage has already landed, and rewriting an
#: already-damaged file reproduces it byte for byte, so the comparison holds on
#: a corrupted tree. Deleting the restore in `audit_with` left this suite fully
#: green while stripping the whole `[commit_identity]` table — five recorded
#: historical exceptions — out of the working tree. `tearDown` compares against
#: these bytes instead, on every test in both classes.
ALLOWLIST_BASELINE = WI.ALLOWLIST_PATH.read_bytes()


def entry_under_own_header(document: str, table: str, line: str) -> str:
    """Insert `line` directly beneath `table`'s OWN header.

    Never appended to the end of the document. This allowlist holds several
    tables, and a key appended to the end joins whichever one happens to be
    LAST — which is `[commit_identity]`, not this gate's table. The pin for
    this helper drives it against a document whose target table is not last,
    because that is the only arrangement in which the two spellings differ.
    """
    header = f"[{table}]\n"
    if header not in document:
        raise AssertionError(f"the table {table!r} is missing from the document")
    return document.replace(header, header + line, 1)


def entries_named(findings: list[str]) -> frozenset[str]:
    """The allowlist key each finding tells an agent to add.

    Read back out of the rendered LIFT block rather than recomputed, so this
    compares what an agent would actually paste with what the stale-entry rule
    would accept.
    """
    return frozenset(
        re.findall(r'^\s*"([^"]+)" = ', "\n".join(findings), re.MULTILINE)
    )


def run(text: str, allowlist: dict[str, str] | None = None) -> list[str]:
    """Parse a synthetic workflow and return its findings."""
    document = WI.parse_workflow(text, "synthetic.yml")
    return WI.check_workflow(
        Path("synthetic.yml"), document, GATE_JOBS, PINNED, allowlist or {}
    )


BASE = """\
name: Synthetic
on:
  pull_request:
permissions: {}
jobs:
  security:
    runs-on: ubuntu-24.04
    steps:
      - name: Scan
        run: ./scripts/ci/scan.sh
"""


class TheRealWorkflowsPass(unittest.TestCase):
    def test_the_repository_is_green(self) -> None:
        findings = WI.audit()
        self.assertEqual(findings, [], "\n\n".join(findings))

    def test_the_audit_entrypoint_can_actually_report_a_finding(self) -> None:
        """Positive control for `audit()` itself, not for the repository.

        The assertion above requires an EMPTY finding list, and an `audit()`
        that returned nothing at all would satisfy it for free — the classic
        guard no input can fail. This points the same entrypoint at a directory
        holding one violating workflow and requires the finding, so a silently
        no-op audit cannot pass both. The scratch directory is in the system
        temp area, never under the repository, so an interrupted run leaves no
        in-tree debris to commit by accident.
        """
        violation = BASE.replace(
            "  security:\n    runs-on:",
            "  security:\n    continue-on-error: true\n    runs-on:",
        )
        original = WI.WORKFLOW_DIR
        try:
            with tempfile.TemporaryDirectory() as scratch:
                (Path(scratch) / "synthetic.yml").write_text(violation, encoding="utf-8")
                WI.WORKFLOW_DIR = Path(scratch)
                findings = WI.audit()
        finally:
            WI.WORKFLOW_DIR = original
        self.assertEqual(len(findings), 1, findings)
        self.assertIn("continue-on-error: true", findings[0])

    def test_every_workflow_is_readable(self) -> None:
        """An unreadable workflow must be a red gate, never a quiet pass."""
        paths = workflow_files()
        self.assertTrue(paths, "no workflow files were found")
        for path in paths:
            with self.subTest(workflow=path.name):
                document = WI.parse_workflow(
                    path.read_text(encoding="utf-8"), str(path)
                )
                self.assertIn("jobs", document)
                self.assertTrue(document["jobs"].children)

    def test_the_gate_job_set_is_derived_and_non_empty(self) -> None:
        """Derived from release_contract.py's constants, never hand-listed."""
        jobs = WI.gate_job_names(
            ("analyze (go, manual)", "application", "chart"),
            {"security": "success", "container": "skipped"},
        )
        self.assertEqual(
            jobs, frozenset({"analyze", "application", "chart", "security", "container"})
        )

    def test_the_pinned_tool_variables_come_from_the_install_script(self) -> None:
        pinned = WI.pinned_tool_variables()
        for expected in ("TRIVY_VERSION", "TRIVY_SHA256", "HELM_VERSION"):
            self.assertIn(expected, pinned)

    def test_the_baseline_is_green_so_every_finding_below_is_the_mutation(self) -> None:
        self.assertEqual(run(BASE), [])


class CodeQLRolesStayOnOneRelease(unittest.TestCase):
    """Every executable CodeQL role, on one release, wherever GitHub runs it.

    Each mutant is a real repository tree on disk rather than an injected text
    mapping: discovery IS half of this rule, and a dict the test chose the
    contents of asserts nothing about what the rule finds by itself.
    """

    OLD_SHA = "db488ddef3bf6cb639b32c2e9a7c0a7ea8271d28"
    OLD_VERSION = "v4.37.8"
    COMPOSITE = (
        "name: Initialize CodeQL\n"
        "description: A same-repository wrapper around the real action\n"
        "runs:\n"
        "  using: composite\n"
        "  steps:\n"
        f"    - uses: github/codeql-action/init@{OLD_SHA} # {OLD_VERSION}\n"
    )
    REAL_INIT = re.compile(
        r"(?m)^(\s*)- name: Initialize CodeQL\n"
        r"(\s*)uses: github/codeql-action/init@([0-9a-f]{40})"
        r"\s+#\s*(v[0-9]+\.[0-9]+\.[0-9]+)\s*$"
    )

    @staticmethod
    def current() -> str:
        return (WI.WORKFLOW_DIR / "codeql.yml").read_text(encoding="utf-8")

    @staticmethod
    def write_tree(root: Path, files: dict[str, str]) -> Path:
        """Write a whole mutant repository to disk; return its workflow dir."""
        for relative, text in files.items():
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8")
        return root / ".github" / "workflows"

    def displace_init(self, real: str) -> str:
        """Leave the current release where a shallow reader looks; run `real`.

        Every bypass the reviews found has this shape: a syntactically perfect,
        version-matched CodeQL reference that never executes, in front of the
        reference that does.
        """
        mutated, count = self.REAL_INIT.subn(
            lambda match: (
                f"{match[1]}- name: Unreachable current-release decoy\n"
                f"{match[2]}if: ${{{{ github.repository == 'never/real' }}}}\n"
                f"{match[2]}uses: github/codeql-action/init@{match[3]} # {match[4]}\n"
                f"{match[1]}- name: Initialize CodeQL\n"
                f"{match[2]}{real}"
            ),
            self.current(),
            count=1,
        )
        self.assertEqual(count, 1, f"did not displace the real init with `{real}`")
        return mutated

    def rollback(self, role: str) -> str:
        mutated, count = re.subn(
            rf"(uses:\s*github/codeql-action/{role}@)[0-9a-f]{{40}}"
            rf"(\s+#\s+)v[0-9]+\.[0-9]+\.[0-9]+",
            rf"\g<1>{self.OLD_SHA}\g<2>{self.OLD_VERSION}",
            self.current(),
            count=1,
        )
        self.assertEqual(count, 1, f"no CodeQL {role} role exists to mutate")
        return mutated

    def test_the_repository_uses_one_complete_release_tuple(self) -> None:
        self.assertEqual(codeql_lockstep_problems(), [])

    def test_every_known_displacement_is_refused(self) -> None:
        shadow = (
            "name: CodeQL shadow\n"
            "on:\n"
            "  workflow_dispatch:\n"
            "permissions: {}\n"
            "jobs:\n"
            "  analyze:\n"
            "    runs-on: ubuntu-24.04\n"
            "    steps:\n"
            f"      - uses: github/codeql-action/init@{self.OLD_SHA} "
            f"# {self.OLD_VERSION}\n"
            f"      - uses: github/codeql-action/analyze@{self.OLD_SHA} "
            f"# {self.OLD_VERSION}\n"
        )
        mutants = {
            "init-only rollback": (
                {".github/workflows/codeql.yml": self.rollback("init")},
                "share one SHA/version tuple",
            ),
            "analyze-only rollback": (
                {".github/workflows/codeql.yml": self.rollback("analyze")},
                "share one SHA/version tuple",
            ),
            "short ref and no version comment": (
                {".github/workflows/codeql.yml": re.sub(
                    r"github/codeql-action/init@[0-9a-f]{40}\s+#\s+v[0-9]+\.[0-9]+\.[0-9]+",
                    "github/codeql-action/init@v4",
                    self.current(),
                    count=1,
                )},
                "full lowercase SHA",
            ),
            "GitHub's second workflow extension": (
                {
                    ".github/workflows/codeql.yml": self.current(),
                    ".github/workflows/codeql-shadow.yaml": shadow,
                },
                "share one SHA/version tuple",
            ),
            "case-variant owner and repository": (
                {".github/workflows/codeql.yml": self.displace_init(
                    f"uses: GitHub/codeql-action/init@{self.OLD_SHA} # {self.OLD_VERSION}"
                )},
                "share one SHA/version tuple",
            ),
            "quoted real role behind an unquoted decoy": (
                {".github/workflows/codeql.yml": self.displace_init(
                    f'uses: "github/codeql-action/init@{self.OLD_SHA}" # {self.OLD_VERSION}'
                )},
                "share one SHA/version tuple",
            ),
            "composite action at the conventional path": (
                {
                    ".github/workflows/codeql.yml": self.displace_init(
                        "uses: ./.github/actions/codeql-init"
                    ),
                    ".github/actions/codeql-init/action.yml": self.COMPOSITE,
                },
                "share one SHA/version tuple",
            ),
            "composite action outside every convention": (
                {
                    ".github/workflows/codeql.yml": self.displace_init(
                        "uses: ./tools/codeql-init"
                    ),
                    "tools/codeql-init/action.yaml": self.COMPOSITE,
                },
                "share one SHA/version tuple",
            ),
        }
        for label, (files, expected) in mutants.items():
            with self.subTest(bypass=label), tempfile.TemporaryDirectory() as directory:
                problems = codeql_lockstep_problems(
                    self.write_tree(Path(directory), files)
                )
                self.assertTrue(problems, f"the {label} bypass survived")
                self.assertIn(expected, "\n".join(problems))

    def test_a_local_reusable_workflow_is_resolved_not_refused(self) -> None:
        """A legitimate `./…/x.yml` job reference must not redden the gate.

        The negative control for the sweep above. `uses:` names a file at job
        level and a directory at step level, and reading only the directory
        form turned an ordinary, correct workflow RED.
        """
        files = {
            ".github/workflows/reusable.yml": self.current(),
            ".github/workflows/caller.yml": (
                "name: Caller\n"
                "on:\n"
                "  workflow_dispatch:\n"
                "permissions: {}\n"
                "jobs:\n"
                "  analyze:\n"
                "    uses: ./.github/workflows/reusable.yml\n"
            ),
        }
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(
                codeql_lockstep_problems(self.write_tree(Path(directory), files)), []
            )

    def test_a_reference_this_reader_cannot_resolve_is_refused(self) -> None:
        """Fail closed on an unresolved `uses:`, rather than walking past it.

        An explicit tag and a dangling local reference are both spellings a
        real parser accepts and this reader does not. Skipping either is the
        silent pass: the step still runs, and nothing holds it to a release.
        """
        for label, files in {
            "explicitly tagged action reference": {
                ".github/workflows/codeql.yml": self.displace_init(
                    f"uses: !!str github/codeql-action/init@{self.OLD_SHA} "
                    f"# {self.OLD_VERSION}"
                ),
            },
            "local action reference resolving to nothing": {
                ".github/workflows/codeql.yml": self.displace_init(
                    "uses: ./tools/codeql-init"
                ),
            },
        }.items():
            with self.subTest(spelling=label), tempfile.TemporaryDirectory() as directory:
                workflow_dir = self.write_tree(Path(directory), files)
                with self.assertRaises(WI.WorkflowIntegrityError) as caught:
                    codeql_lockstep_problems(workflow_dir)
                self.assertIn("cannot", str(caught.exception))


class ContinueOnErrorIsRefused(unittest.TestCase):
    def test_job_level_true_on_a_gate_job_is_a_finding(self) -> None:
        text = BASE.replace(
            "  security:\n    runs-on:", "  security:\n    continue-on-error: true\n    runs-on:"
        )
        findings = run(text)
        self.assertEqual(len(findings), 1, findings)
        self.assertIn("continue-on-error: true", findings[0])
        self.assertIn("ci_gate_allowlist.toml", findings[0])
        self.assertIn('"synthetic.yml::security::continue-on-error"', findings[0])

    def test_job_level_false_is_not_a_finding(self) -> None:
        text = BASE.replace(
            "  security:\n    runs-on:", "  security:\n    continue-on-error: false\n    runs-on:"
        )
        self.assertEqual(run(text), [])

    def test_a_non_gate_job_is_out_of_scope(self) -> None:
        text = BASE.replace("  security:", "  scratch:")
        text = text.replace(
            "  scratch:\n    runs-on:", "  scratch:\n    continue-on-error: true\n    runs-on:"
        )
        self.assertEqual(run(text), [])

    def test_step_level_true_on_a_gate_job_is_a_finding(self) -> None:
        text = BASE.replace(
            "      - name: Scan\n", "      - name: Scan\n        continue-on-error: true\n"
        )
        findings = run(text)
        self.assertEqual(len(findings), 1, findings)
        self.assertIn("step 'Scan'", findings[0])
        self.assertIn('"synthetic.yml::security::Scan::continue-on-error"', findings[0])

    def test_a_trailing_comment_cannot_hide_the_value(self) -> None:
        text = BASE.replace(
            "  security:\n    runs-on:",
            "  security:\n    continue-on-error: true # flaky, sorry\n    runs-on:",
        )
        self.assertEqual(len(run(text)), 1)

    def test_a_quoted_key_cannot_hide_the_construct(self) -> None:
        text = BASE.replace(
            "  security:\n    runs-on:",
            '  security:\n    "continue-on-error": true\n    runs-on:',
        )
        self.assertEqual(len(run(text)), 1)

    def test_a_space_before_the_colon_cannot_hide_the_construct(self) -> None:
        text = BASE.replace(
            "  security:\n    runs-on:",
            "  security:\n    continue-on-error : true\n    runs-on:",
        )
        self.assertEqual(len(run(text)), 1)

    def test_a_quoted_key_with_a_space_before_the_colon_is_still_read(self) -> None:
        r"""The INTERSECTION of the two cases above, which neither one covers.

        `_KEY` defends the space-before-a-colon shape twice — the `\s*` before
        the colon, and the `.strip()` on the captured key — and exactly one of
        those defences is redundant. On a BARE key the greedy `\s*` sits
        immediately before the colon while the bare alternative is non-greedy,
        so the capture can never carry trailing whitespace and the `.strip()`
        is dead code either way.

        On a QUOTED key they diverge. The quoted alternative `"[^"]*"` is fixed
        and cannot absorb the space, and the bare alternative excludes a
        leading quote, so `.strip()` never gets the chance: without `\s*` the
        reader RAISES on this line instead of reading it. That direction is
        fail-closed — a red gate, never a construct waved through — but it is a
        real behaviour change in an input class the two tests above miss
        between them, and it is what turns removing `\s*` from a surviving
        mutant into a killed one.
        """
        text = BASE.replace(
            "  security:\n    runs-on:",
            '  security:\n    "continue-on-error" : true\n    runs-on:',
        )
        self.assertEqual(len(run(text)), 1)

    def test_the_allowlist_lifts_exactly_the_named_case(self) -> None:
        text = BASE.replace(
            "  security:\n    runs-on:", "  security:\n    continue-on-error: true\n    runs-on:"
        )
        lifted = run(text, {"synthetic.yml::security::continue-on-error": "reviewed"})
        self.assertEqual(lifted, [])
        wrong = run(text, {"synthetic.yml::application::continue-on-error": "reviewed"})
        self.assertEqual(len(wrong), 1, "an entry for another job must not lift this one")


class PinCapturingStepEnvIsRefused(unittest.TestCase):
    def test_a_step_shadowing_a_workflow_level_pin_is_a_finding(self) -> None:
        text = BASE.replace(
            "permissions: {}\n", "permissions: {}\nenv:\n  IMAGE: ghcr.io/owner/app\n"
        )
        text = text.replace(
            "        run: ./scripts/ci/scan.sh\n",
            "        env:\n          IMAGE: ghcr.io/owner/other\n"
            "        run: ./scripts/ci/scan.sh\n",
        )
        findings = run(text)
        self.assertEqual(len(findings), 1, findings)
        self.assertIn("workflow-level env", findings[0])
        self.assertIn('"synthetic.yml::security::Scan::env::IMAGE"', findings[0])

    def test_a_step_shadowing_a_job_level_pin_is_a_finding(self) -> None:
        text = BASE.replace(
            "    runs-on: ubuntu-24.04\n",
            "    runs-on: ubuntu-24.04\n    env:\n      SOURCE_SHA: abc\n",
        )
        text = text.replace(
            "        run: ./scripts/ci/scan.sh\n",
            "        env:\n          SOURCE_SHA: def\n"
            "        run: ./scripts/ci/scan.sh\n",
        )
        findings = run(text)
        self.assertEqual(len(findings), 1, findings)
        self.assertIn("job-level env", findings[0])

    def test_a_step_rebinding_a_pinned_tool_version_is_a_finding(self) -> None:
        text = BASE.replace(
            "        run: ./scripts/ci/scan.sh\n",
            "        env:\n          TRIVY_VERSION: v0.1.0\n"
            "        run: ./scripts/ci/scan.sh\n",
        )
        findings = run(text)
        self.assertEqual(len(findings), 1, findings)
        self.assertIn("scripts/ci/install-tools.sh", findings[0])

    def test_a_tool_pin_is_refused_even_outside_a_gate_job(self) -> None:
        """An unpinned tool runs the same wherever the step lives."""
        text = BASE.replace("  security:", "  scratch:")
        text = text.replace(
            "        run: ./scripts/ci/scan.sh\n",
            "        env:\n          HELM_VERSION: v2.0.0\n"
            "        run: ./scripts/ci/scan.sh\n",
        )
        self.assertEqual(len(run(text)), 1)

    def test_an_ordinary_step_env_is_not_a_finding(self) -> None:
        """The rule is about CAPTURING A PIN, not about step env existing."""
        text = BASE.replace(
            "        run: ./scripts/ci/scan.sh\n",
            "        env:\n          GH_TOKEN: x\n          IMAGE_DIGEST: y\n"
            "        run: ./scripts/ci/scan.sh\n",
        )
        self.assertEqual(run(text), [])


class CustomShellOnAGateStepIsRefused(unittest.TestCase):
    def test_a_custom_shell_on_a_gate_step_is_a_finding(self) -> None:
        text = BASE.replace(
            "        run: ./scripts/ci/scan.sh\n",
            "        shell: sh\n        run: ./scripts/ci/scan.sh\n",
        )
        findings = run(text)
        self.assertEqual(len(findings), 1, findings)
        self.assertIn("pipefail", findings[0])
        self.assertIn('"synthetic.yml::security::Scan::shell"', findings[0])

    def test_a_custom_shell_outside_the_gate_set_is_out_of_scope(self) -> None:
        text = BASE.replace("  security:", "  scratch:").replace(
            "        run: ./scripts/ci/scan.sh\n",
            "        shell: sh\n        run: ./scripts/ci/scan.sh\n",
        )
        self.assertEqual(run(text), [])

    def test_the_allowlist_lifts_it(self) -> None:
        text = BASE.replace(
            "        run: ./scripts/ci/scan.sh\n",
            "        shell: sh\n        run: ./scripts/ci/scan.sh\n",
        )
        self.assertEqual(run(text, {"synthetic.yml::security::Scan::shell": "why"}), [])


class TheReaderRefusesWhatItCannotRead(unittest.TestCase):
    def test_a_run_body_is_opaque(self) -> None:
        """A shell script mentioning `shell:` is not workflow structure."""
        text = BASE.replace(
            "        run: ./scripts/ci/scan.sh\n",
            "        run: |\n"
            "          echo 'shell: sh'\n"
            "          echo 'continue-on-error: true'\n"
            "          printf 'env:\\n  TRIVY_VERSION: v0\\n'\n",
        )
        self.assertEqual(run(text), [])

    def test_a_tab_in_indentation_is_refused(self) -> None:
        text = BASE.replace("      - name: Scan", "\t- name: Scan")
        with self.assertRaises(WI.WorkflowIntegrityError) as caught:
            run(text)
        self.assertIn("tab", str(caught.exception))

    def test_a_duplicate_key_is_refused(self) -> None:
        text = BASE.replace(
            "    runs-on: ubuntu-24.04\n",
            "    runs-on: ubuntu-24.04\n    runs-on: self-hosted\n",
        )
        with self.assertRaises(WI.WorkflowIntegrityError) as caught:
            run(text)
        self.assertIn("duplicate key", str(caught.exception))

    def test_ragged_indentation_is_refused_rather_than_guessed(self) -> None:
        text = BASE.replace("    runs-on: ubuntu-24.04\n", "     runs-on: ubuntu-24.04\n")
        with self.assertRaises(WI.WorkflowIntegrityError):
            run(text)


class TheAllowlistIsTrustworthy(unittest.TestCase):
    def test_the_shipped_allowlist_loads(self) -> None:
        self.assertIsInstance(WI.load_allowlist(), dict)

    def test_the_shipped_allowlist_carries_no_stale_entry(self) -> None:
        """Every entry must still name a construct a workflow really declares.

        This REPLACED an `assertEqual(WI.load_allowlist(), {})` pin on the same
        table. That pin was an inventory pin on the lift mechanism: applying
        verbatim the line a refusal prints silenced the refusal and immediately
        failed the assertion, so the gate's own advertised one-line lift — text
        that lands in a public CI log — turned the build red when an agent
        followed it.

        The rule here is the one the sibling gate in `test_subcommand_callers.py`
        already used: an entry that names no live construct is refused, whether
        that is because the construct was removed, because the key was
        mistyped, or because somebody reserved room for a violation nobody has
        proposed. `load_allowlist` holds the other half — an entry with no
        written reason fails closed.

        Say what this is, exactly, because an earlier version of this docstring
        overstated it. As a predicate over the table's CONTENTS the new rule is
        strictly WEAKER than the empty-table pin: an empty table satisfies "no
        stale entry" vacuously, and the converse fails, since a table holding
        one live correct exemption passes here and failed there. The rule does
        not bound how many entries the table holds, and the tripwire that made
        the FIRST exemption require a reviewed edit to this suite is gone — it
        is now one silent line in a data file. That is the trade the gate design
        doctrine asks for, since a strict check earns its keep only when
        widening it is cheap, and it is made on purpose. It is still a trade.
        """
        failures = WI.stale_allowlist_failures(
            WI.load_allowlist(), WI.refusable_entries()
        )
        self.assertEqual(failures, [], "\n\n".join(failures))

    def tearDown(self) -> None:
        """The blank-reason test rewrites a TRACKED file; prove it puts it back.

        Against `ALLOWLIST_BASELINE` rather than a per-test snapshot, for the
        reason written out at that constant: a snapshot read inside the test
        cannot tell a working restore from a broken one.
        """
        self.assertEqual(
            WI.ALLOWLIST_PATH.read_bytes(),
            ALLOWLIST_BASELINE,
            "a test in this class left the tracked allowlist modified on disk",
        )

    def test_the_blank_reason_fixture_lands_under_its_own_header(self) -> None:
        """`entry_under_own_header` must not degrade into an append.

        The fixture below inserts a blank-reason key to prove `load_allowlist`
        fails closed. Appending it to the end of the file instead would put it
        in whichever table is LAST, which is `[commit_identity]` — so an
        append makes THIS gate's table gain nothing, and the two spellings are
        told apart only by a document whose target table is not last. Driving
        the helper against exactly that arrangement is what keeps the repair
        from silently reverting.
        """
        document = '[first]\n"aaa" = "x"\n\n[second]\n"bbb" = "y"\n'
        parsed = tomllib.loads(entry_under_own_header(document, "first", '"ccc" = ""\n'))
        self.assertIn("ccc", parsed["first"], "the entry missed its own table")
        self.assertNotIn("ccc", parsed["second"], "an appended entry joins the LAST table")

    def test_an_entry_without_a_reason_fails_closed(self) -> None:
        original = WI.ALLOWLIST_PATH.read_text(encoding="utf-8")
        try:
            # Inserted directly under its OWN header, never appended to the end
            # of the file: the allowlist holds several tables, and an appended
            # key belongs to whichever table happens to be last. The helper is
            # pinned by the placement test above; the restore by `tearDown`.
            WI.ALLOWLIST_PATH.write_text(
                entry_under_own_header(
                    original,
                    WI.ALLOWLIST_TABLE,
                    '"synthetic.yml::security::Scan::shell" = ""\n',
                ),
                encoding="utf-8",
            )
            with self.assertRaises(WI.WorkflowIntegrityError) as caught:
                WI.load_allowlist()
            self.assertIn("no written reason", str(caught.exception))
        finally:
            WI.ALLOWLIST_PATH.write_text(original, encoding="utf-8")


class TheStaleEntryRuleRefusesWhatItClaimsTo(unittest.TestCase):
    """Hostile fixtures for the stale-entry rule, which live data cannot reach.

    The shipped table is empty and this repository declares none of the three
    constructs, so `refusable_entries()` is empty too and every branch of the
    rule is unreachable from the repository alone — a rule that refused nothing
    would satisfy `test_the_shipped_allowlist_carries_no_stale_entry` exactly as
    well as one that works. These drive it with inputs the repository
    deliberately does not contain.
    """

    LIVE = "pr-gate.yml::chart::Render the chart::shell"
    REFUSABLE = frozenset({LIVE})

    def test_an_entry_naming_no_live_construct_is_refused(self) -> None:
        messages = WI.stale_allowlist_failures(
            {"pr-gate.yml::security::A step that is gone::shell": "reviewed"},
            self.REFUSABLE,
        )
        self.assertEqual(len(messages), 1, messages)
        self.assertIn("is stale", messages[0])
        self.assertIn("Delete the line", messages[0])
        self.assertIn(f"[{WI.ALLOWLIST_TABLE}]", messages[0])

    def test_a_mistyped_key_fails_through_the_same_door(self) -> None:
        """A key naming nothing is stale whether the cause is drift or a typo."""
        messages = WI.stale_allowlist_failures({self.LIVE[:-1]: "typo"}, self.REFUSABLE)
        self.assertEqual(len(messages), 1, messages)

    def test_an_entry_still_doing_work_is_kept(self) -> None:
        self.assertEqual(
            WI.stale_allowlist_failures({self.LIVE: "reviewed"}, self.REFUSABLE), []
        )

    def test_an_empty_table_is_clean(self) -> None:
        self.assertEqual(WI.stale_allowlist_failures({}, frozenset()), [])

    def test_every_entry_is_reported_rather_than_only_the_first(self) -> None:
        messages = WI.stale_allowlist_failures(
            {"a::b::c::shell": "one", "d::e::f::shell": "two"}, self.REFUSABLE
        )
        self.assertEqual(len(messages), 2, messages)


class TheOneLineLiftWorksEndToEnd(unittest.TestCase):
    """The round trip the gate design doctrine requires, both directions.

    A refusal prints an exact line. Adding that line must silence the refusal
    AND must not then be reported stale; removing the construct must report the
    line stale so the exemption cannot outlive its case. Until 0.1.37 the first
    half failed here: the printed line silenced the refusal and tripped an
    empty-table assertion one file over. A one-line lift that fails when you
    apply it is not a lift mechanism, and the failure text saying "liftable in
    one line" reaches a public CI log where it misinstructs the next agent.

    Driven through `audit()` and `load_allowlist()` — the entrypoints CI runs —
    rather than through the pure functions, because the defect lived in the
    seam between them. The workflow directory is redirected into the system
    temp area so no in-tree debris can survive an interrupted run; the
    allowlist is the real tracked file, rewritten and restored in `finally` as
    the blank-reason test above already does, because `_lift` renders that path
    RELATIVE TO the repository root and a scratch path outside the tree could
    not be rendered at all.
    """

    VIOLATION = BASE.replace(
        "        run: ./scripts/ci/scan.sh\n",
        "        shell: sh\n        run: ./scripts/ci/scan.sh\n",
    )
    ENTRY = "synthetic.yml::security::Scan::shell"
    REASON = "reviewed: this fixture step runs no pipeline"

    def audit_with(self, workflow: str, table: str) -> tuple[list[str], list[str]]:
        """Return `(audit findings, stale-entry failures)` for one scratch state.

        `table` REPLACES this gate's table rather than being appended to it.
        Appending would make these assertions depend on the shipped table being
        empty — which is the very coupling that produced the defect this class
        exists to prevent, one level down: the fixture points the reader at a
        scratch workflow directory, so a shipped entry for a REAL workflow
        would correctly read as stale here and fail a test that is about
        something else entirely.
        """
        original_dir = WI.WORKFLOW_DIR
        original_text = WI.ALLOWLIST_PATH.read_text(encoding="utf-8")
        header = f"[{WI.ALLOWLIST_TABLE}]\n"
        self.assertIn(header, original_text, "the table this rule reads is missing")
        before, _, rest = original_text.partition(header)
        # Everything from the NEXT top-level table header on is carried through
        # untouched; only this gate's own entries are replaced.
        cut = rest.find("\n[")
        tail = rest[cut + 1 :] if cut != -1 else ""
        try:
            WI.ALLOWLIST_PATH.write_text(
                before + header + table + tail, encoding="utf-8"
            )
            with tempfile.TemporaryDirectory() as scratch:
                (Path(scratch) / "synthetic.yml").write_text(workflow, encoding="utf-8")
                WI.WORKFLOW_DIR = Path(scratch)
                findings = WI.audit()
                stale = WI.stale_allowlist_failures(
                    WI.load_allowlist(), WI.refusable_entries()
                )
        finally:
            WI.WORKFLOW_DIR = original_dir
            WI.ALLOWLIST_PATH.write_text(original_text, encoding="utf-8")
        return findings, stale

    def test_the_refusal_prints_a_line_that_actually_lifts_it(self) -> None:
        findings, stale = self.audit_with(self.VIOLATION, "")
        self.assertEqual(len(findings), 1, findings)
        self.assertIn(f'"{self.ENTRY}" = ', findings[0], "the exact line to add")
        self.assertEqual(stale, [], "nothing is exempted yet")

        lifted, stale = self.audit_with(
            self.VIOLATION, f'"{self.ENTRY}" = "{self.REASON}"\n'
        )
        self.assertEqual(lifted, [], "the printed line did not silence the refusal")
        self.assertEqual(stale, [], "the printed line was reported stale on arrival")

    def test_the_entry_is_reported_stale_once_the_construct_is_gone(self) -> None:
        """The other direction: an exemption may not outlive its case."""
        findings, stale = self.audit_with(BASE, f'"{self.ENTRY}" = "{self.REASON}"\n')
        self.assertEqual(findings, [], findings)
        self.assertEqual(len(stale), 1, stale)
        self.assertIn(self.ENTRY, stale[0])
        self.assertIn("is stale", stale[0])

    def test_an_entry_for_another_construct_lifts_nothing(self) -> None:
        findings, _ = self.audit_with(
            self.VIOLATION,
            '"synthetic.yml::application::Scan::shell" = "another job entirely"\n',
        )
        self.assertEqual(len(findings), 1, findings)

    def tearDown(self) -> None:
        """The helper above rewrites a TRACKED file; prove it puts it back.

        This replaces a single test that read its own "before" immediately
        before calling `audit_with`. That test was vacuous, and provably so:
        delete the restore from `audit_with`'s `finally` and the whole suite
        stayed green while `scripts/ci/ci_gate_allowlist.toml` lost its entire
        `[commit_identity]` table and all five recorded historical exceptions.
        Two reasons compounded — the per-test snapshot was taken after an
        earlier test in the class had already done the damage, and rewriting an
        already-damaged file is a fixed point, so the comparison held.

        Comparing every test in this class against `ALLOWLIST_BASELINE`, read
        once at import before any test could run, removes both. It is strictly
        stronger than the test it replaces: four tests are covered instead of
        one, and the reference bytes are pristine rather than possibly damaged.
        """
        self.assertEqual(
            WI.ALLOWLIST_PATH.read_bytes(),
            ALLOWLIST_BASELINE,
            "a test in this class left the tracked allowlist modified on disk",
        )


ALPHA = """\
name: Alpha
on:
  pull_request:
permissions: {}
jobs:
  security:
    runs-on: ubuntu-24.04
    steps:
      - name: Scan
        shell: sh
        run: ./scripts/ci/scan.sh
"""

BETA = """\
name: Beta
on:
  pull_request:
permissions: {}
jobs:
  chart:
    continue-on-error: true
    runs-on: ubuntu-24.04
    steps:
      - name: Render
        run: ./scripts/ci/render.sh
"""

GAMMA = """\
name: Gamma
on:
  pull_request:
permissions: {}
jobs:
  application:
    runs-on: ubuntu-24.04
    steps:
      - name: Build
        env:
          TRIVY_VERSION: v0.0.1
        run: ./scripts/ci/build.sh
  scratch:
    runs-on: ubuntu-24.04
    steps:
      - name: Unwatched
        shell: sh
        run: ./scripts/ci/unwatched.sh
"""


class BothHalvesReadEveryFileAndTheSameGateScope(unittest.TestCase):
    """`audit()` and `refusable_entries()` must agree, across EVERY workflow.

    The two are independent loops over `_workflow_paths()`, each recomputing
    the gate-job set, and three mutants survived the rest of this suite because
    every other fixture here points the reader at a directory holding exactly
    ONE file, in a repository that declares no violation at all:

      * `refusable_entries()` reading only the FIRST path — every entry from
        every other workflow then reads as stale, so a valid exemption is
        refused and the documented one-line lift fails on file number two.
      * `audit()` reading only the FIRST path — every refusal in every other
        workflow silently disappears. That is the gate going quiet.
      * A WIDER gate-job set in ONE half than the other. This is the
        fail-open on gate SCOPE: widen it inside `refusable_entries()` and an
        exemption can be written for a construct `audit()` never refuses;
        widen it inside `audit()` and a refusal fires that no lift can name,
        because the line it prints reads stale the moment it is added.

    THREE files are the minimum that distinguishes "every path" from "the
    first path", and each contributes a DIFFERENT one of the three rules so a
    rule-specific regression cannot hide behind the other two. The non-gate
    `scratch` job is what pins the scope itself: an equality assertion alone
    would survive a mutant that widened BOTH halves identically.

    Nothing here touches the tracked allowlist. The shipped
    `[workflow_integrity]` table is empty, so `audit()` refuses all three
    fixtures with the real file in place.
    """

    FILES = {"alpha.yml": ALPHA, "beta.yml": BETA, "gamma.yml": GAMMA}
    EXPECTED = frozenset(
        {
            "alpha.yml::security::Scan::shell",
            "beta.yml::chart::continue-on-error",
            "gamma.yml::application::Build::env::TRIVY_VERSION",
        }
    )
    #: Same construct as alpha's, in a job no branch-protection rule reads.
    NON_GATE = "gamma.yml::scratch::Unwatched::shell"

    def setUp(self) -> None:
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        for name, text in self.FILES.items():
            (Path(scratch.name) / name).write_text(text, encoding="utf-8")
        original = WI.WORKFLOW_DIR
        self.addCleanup(setattr, WI, "WORKFLOW_DIR", original)
        WI.WORKFLOW_DIR = Path(scratch.name)

    def test_the_refusable_set_covers_every_file_not_just_the_first(self) -> None:
        self.assertEqual(WI.refusable_entries(), self.EXPECTED)

    def test_the_audit_covers_every_file_not_just_the_first(self) -> None:
        findings = WI.audit()
        self.assertEqual(len(findings), 3, "\n\n".join(findings))
        self.assertEqual(entries_named(findings), self.EXPECTED)

    def test_both_halves_name_exactly_the_same_entries(self) -> None:
        """The seam itself: what a lift can silence and what it may name."""
        self.assertEqual(entries_named(WI.audit()), WI.refusable_entries())

    def test_a_construct_in_a_non_gate_job_is_refusable_by_neither(self) -> None:
        """Scope, pinned in both halves at once.

        `scratch` declares the identical custom shell alpha's gate job is
        refused for. Widening the gate-job set in either half admits it, and
        the equality assertion above would not notice a widening applied to
        both.
        """
        self.assertNotIn(self.NON_GATE, WI.refusable_entries())
        self.assertNotIn(self.NON_GATE, entries_named(WI.audit()))


class AnEmptyWorkflowDirectoryIsARedGate(unittest.TestCase):
    """`_workflow_paths()`'s guard, which live data can never reach.

    The repository always has workflows, so no assertion exercised the branch
    and `if False` survived it. Both entrypoints read the directory through
    that guard, and both are fail-open without it: an `audit()` over no files
    reports no finding, and a `refusable_entries()` over no files makes every
    shipped allowlist entry read as stale.
    """

    def redirect(self, directory: Path, call):
        original = WI.WORKFLOW_DIR
        try:
            WI.WORKFLOW_DIR = directory
            return call()
        finally:
            WI.WORKFLOW_DIR = original

    def test_the_path_reader_refuses_a_directory_with_no_workflows(self) -> None:
        with tempfile.TemporaryDirectory() as scratch:
            with self.assertRaises(WI.WorkflowIntegrityError) as caught:
                self.redirect(Path(scratch), WI._workflow_paths)
        self.assertIn("no workflows found", str(caught.exception))

    def test_the_audit_refuses_rather_than_reporting_a_clean_tree(self) -> None:
        with tempfile.TemporaryDirectory() as scratch:
            with self.assertRaises(WI.WorkflowIntegrityError):
                self.redirect(Path(scratch), WI.audit)

    def test_the_refusable_set_refuses_rather_than_reporting_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as scratch:
            with self.assertRaises(WI.WorkflowIntegrityError):
                self.redirect(Path(scratch), WI.refusable_entries)

    def test_a_directory_holding_a_workflow_is_accepted(self) -> None:
        """The positive twin: the guard refuses EMPTY, not everything.

        Without this, a mutant that raised unconditionally would satisfy all
        three assertions above and take the whole gate down with it.
        """
        with tempfile.TemporaryDirectory() as scratch:
            (Path(scratch) / "synthetic.yml").write_text(BASE, encoding="utf-8")
            paths = self.redirect(Path(scratch), WI._workflow_paths)
        self.assertEqual([path.name for path in paths], ["synthetic.yml"])


class TheFailureMessageTellsAnAgentWhatToDo(unittest.TestCase):
    def test_every_message_names_the_lift_mechanism_and_the_exact_line(self) -> None:
        mutations = [
            BASE.replace(
                "  security:\n    runs-on:",
                "  security:\n    continue-on-error: true\n    runs-on:",
            ),
            BASE.replace(
                "        run: ./scripts/ci/scan.sh\n",
                "        shell: sh\n        run: ./scripts/ci/scan.sh\n",
            ),
            BASE.replace(
                "        run: ./scripts/ci/scan.sh\n",
                "        env:\n          TRIVY_VERSION: v0.1.0\n"
                "        run: ./scripts/ci/scan.sh\n",
            ),
        ]
        for index, text in enumerate(mutations):
            with self.subTest(mutation=index):
                findings = run(text)
                self.assertEqual(len(findings), 1)
                message = findings[0]
                self.assertIn("LIFT:", message)
                self.assertIn("scripts/ci/ci_gate_allowlist.toml", message)
                self.assertIn("[workflow_integrity]", message)
                self.assertIn(" = ", message, "the exact line to add must be shown")


if __name__ == "__main__":  # pragma: no cover - manual invocation
    unittest.main()
