"""Hostile suite for the narrow workflow-integrity rules.

READ THIS BEFORE ADDING A TEST HERE
===================================

This suite pins THREE named dangerous constructs and the reader that finds
them. It does NOT pin a step inventory, and one must never be added — not
here, and not in `scripts/ci/workflow_integrity.py`.

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

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import workflow_integrity as WI  # noqa: E402

GATE_JOBS = frozenset({"security", "application", "chart", "analyze"})
PINNED = frozenset({"TRIVY_VERSION", "TRIVY_SHA256", "HELM_VERSION"})


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
        paths = sorted(WI.WORKFLOW_DIR.glob("*.yml"))
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
        table, which was the defect it looks like a weakening of. That pin was
        an inventory pin on the lift mechanism: applying verbatim the line a
        refusal prints silenced the refusal and immediately failed the
        assertion, so the gate's own advertised one-line lift — text that lands
        in a public CI log — turned the build red when an agent followed it.

        The rule here is the one the sibling gate in `test_subcommand_callers.py`
        already used, and it is what keeps the table from accumulating
        exemptions: an entry that names no live construct is refused, whether
        that is because the construct was removed, because the key was
        mistyped, or because somebody reserved room for a violation nobody has
        proposed. `load_allowlist` holds the other half — an entry with no
        written reason fails closed.
        """
        failures = WI.stale_allowlist_failures(
            WI.load_allowlist(), WI.refusable_entries()
        )
        self.assertEqual(failures, [], "\n\n".join(failures))

    def test_an_entry_without_a_reason_fails_closed(self) -> None:
        original = WI.ALLOWLIST_PATH.read_text(encoding="utf-8")
        header = f"[{WI.ALLOWLIST_TABLE}]\n"
        self.assertIn(header, original, "the table this rule reads is missing")
        try:
            # Inserted directly under its OWN header, never appended to the end
            # of the file: the allowlist holds several tables, and an appended
            # key belongs to whichever table happens to be last.
            WI.ALLOWLIST_PATH.write_text(
                original.replace(
                    header,
                    header + '"synthetic.yml::security::Scan::shell" = ""\n',
                    1,
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

    def test_the_shipped_allowlist_file_is_restored_afterwards(self) -> None:
        """The helper above rewrites a TRACKED file; prove it puts it back."""
        before = WI.ALLOWLIST_PATH.read_bytes()
        self.audit_with(self.VIOLATION, f'"{self.ENTRY}" = "{self.REASON}"\n')
        self.assertEqual(WI.ALLOWLIST_PATH.read_bytes(), before)


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
