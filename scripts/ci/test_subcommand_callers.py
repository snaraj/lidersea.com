"""Every registered subcommand of `release_contract.py` must have a caller.

THE ASYMMETRY THIS CLOSES
=========================

`scripts/ci/release_contract.py` registers its subcommands with argparse and
workflows invoke them BY NAME, as opaque strings in a shell line. Nothing
connects the two sides. A subcommand can therefore be deleted while a workflow
still calls it (a runtime failure that no test sees), or survive long after its
last caller is gone (dead code that still reads live).

The second case produced a near-miss in this repository's lane. An audit called
`release-record` dead in BOTH site repositories on the strength of a grep. In
the sibling repository it was not dead: the terminal publisher step invoked it
through a LINE-WRAPPED invocation, where the subcommand name sits on a
continuation line far from `release_contract.py`, and removing it was proven to
break the publisher at runtime. In THIS repository it genuinely was dead, and
0.1.37 removes it.

Both answers were right. Neither was reliably obtainable by eye, which is
exactly why this is a machine check: the gate below searches for the BARE
TOKEN anywhere in a candidate file, so line wrapping — the thing that fooled
the grep — cannot hide a caller from it.

WHAT IT REFUSES, AND WHAT IT DOES NOT
=====================================

It refuses two named conditions:

  * ZERO callers — dead code that still presents a live interface.
  * TEST-ONLY callers — a suite exercising a command nothing invokes. That is
    a genuine smell: the tests keep passing, the coverage looks real, and the
    command is unreachable in production.

It deliberately does NOT assert that the caller set is exactly some recorded
list, and no such inventory may be added here. Which workflow calls which
subcommand is ordinary active development; pinning it would break on every
legitimate move and teach agents to re-record the pin instead of thinking.
The rule is about REACHABILITY, which is a real property, not about the
current call graph, which is not.

A DOC-ONLY CALLER IS A REAL CALLER
==================================

`settings-receipt` is invoked from `docs/release-governance.md` — the GET-only
preflight the repository owner runs by hand before a release. It has no
workflow caller and it is not dead. The gate therefore reports the TIER of
every caller (workflow / script / doc / test) rather than collapsing them, so a
reviewer can tell an operator escape hatch from an orphan.

THE LIFT MECHANISM
==================

One line in `scripts/ci/ci_gate_allowlist.toml` under `[subcommand_callers]`,
with a written reason. The failure message prints the exact line to add.

That the line WORKS is itself pinned, by `test_the_one_line_lift_actually_lifts`
and `test_the_allowlist_is_never_counted_as_a_caller`. The allowlist is excluded
from the caller search set (see `SELF_NAMING`) because an exemption names the
subcommand it exempts: counted as a caller, the added line would hand its own
subcommand a script-tier caller, the stale-entry rule would demand the line be
deleted, and deleting it would trip the zero-caller rule again. A one-line lift
that fails whether or not you apply it is not a lift mechanism, so the round
trip is a test rather than an assumption.
"""

from __future__ import annotations

import argparse
import importlib.util
import re
import sys
import tomllib
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
MODULE_PATH = REPO_ROOT / "scripts" / "ci" / "release_contract.py"
ALLOWLIST_PATH = REPO_ROOT / "scripts" / "ci" / "ci_gate_allowlist.toml"
ALLOWLIST_TABLE = "subcommand_callers"

#: Files that NECESSARILY contain subcommand names and therefore can never be
#: evidence that something CALLS one. Both exclusions are load-bearing:
#:
#:   * `release_contract.py` registers every name it defines, so counting it
#:     would make the whole gate vacuous.
#:   * `ci_gate_allowlist.toml` is the LIFT MECHANISM, and an exemption names
#:     the subcommand it exempts. Counting it as a caller deadlocks the lift:
#:     adding the one line the failure message prints gives the dead subcommand
#:     a script-tier "caller" (the entry itself), which immediately trips the
#:     stale-entry rule and demands the line be deleted — and deleting it trips
#:     the zero-caller rule again. A one-line lift that fails whether or not
#:     you apply it is not a lift mechanism. Its prose masks too: a comment
#:     naming a subcommand kept `settings-receipt` alive here even with its
#:     real doc caller removed.
SELF_NAMING = frozenset({MODULE_PATH, ALLOWLIST_PATH})

#: Tiers a caller can live in, in reporting order.
TIERS = ("workflow", "script", "doc", "test")

#: Tier sets whose presence alone fails the gate.
FAILING_TIER_SETS = (frozenset(), frozenset({"test"}))


def registered_subcommands() -> tuple[str, ...]:
    """Read the names from the PARSER, never from a hand-maintained list.

    A hand-maintained list is the same asymmetry one level up: it would drift
    from the parser exactly as the workflows drift from it today.
    """
    spec = importlib.util.spec_from_file_location("_release_contract", MODULE_PATH)
    if spec is None or spec.loader is None:  # pragma: no cover - import plumbing
        raise AssertionError(f"cannot load {MODULE_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    parser = module._parser()
    actions = [
        action
        for action in parser._actions
        if isinstance(action, argparse._SubParsersAction)
    ]
    if len(actions) != 1:
        raise AssertionError(
            f"expected exactly one subparser group, found {len(actions)}; "
            "the introspection above no longer describes the parser"
        )
    return tuple(sorted(actions[0].choices))


def search_set() -> dict[Path, str]:
    """Files that can plausibly INVOKE the CLI, mapped to their tier.

    The scope is deliberate, and each exclusion was measured rather than
    assumed:

      * `.github/workflows/*.yml` — workflow.
      * `scripts/**` — script, or test when the file is a `test_*.py` suite.
      * `docs/**/*.md` — doc. These are the operator runbooks, the only
        Markdown a human copies a command out of.

    Everything else is excluded because a bare-token search there reports
    PROSE as a caller, and a false caller MASKS the deadness this gate exists
    to find. Measured at 0.1.37: `transition` matches `transition:` in
    `frontend/src/styles.css`, and `publisher` matches dozens of narrative
    sentences in `README.md` and `CHANGELOG.md`. Root Markdown — `README.md`,
    `CHANGELOG.md`, `AGENTS.md` — is prose ABOUT the system, not an invocation
    site, so it is out of scope by the same measurement.

    The two files in `SELF_NAMING` are excluded for the reason written out
    there: each necessarily contains the names, so neither can witness a call.
    """
    files: dict[Path, str] = {}
    for path in sorted((REPO_ROOT / ".github" / "workflows").glob("*.yml")):
        files[path] = "workflow"
    for path in sorted((REPO_ROOT / "scripts").rglob("*")):
        if not path.is_file() or path in SELF_NAMING:
            continue
        is_test = path.name.startswith("test_") and path.suffix == ".py"
        files[path] = "test" if is_test else "script"
    for path in sorted((REPO_ROOT / "docs").rglob("*.md")):
        files[path] = "doc"
    return files


def callers_by_tier(names: tuple[str, ...]) -> dict[str, dict[str, list[str]]]:
    """Map every subcommand to {tier: [relative paths]}.

    The token is matched BARE — bounded by characters that cannot appear in a
    subcommand name — anywhere in the file. It is deliberately not anchored to
    `release_contract.py` on the same line, because the near-miss this gate
    exists to prevent was precisely a caller whose subcommand name sat on a
    different line from the script it invoked.
    """
    contents = {
        path: (tier, path.read_text(encoding="utf-8", errors="replace"))
        for path, tier in search_set().items()
    }
    found: dict[str, dict[str, list[str]]] = {name: {} for name in names}
    for name in names:
        pattern = re.compile(
            r"(?<![A-Za-z0-9_.-])" + re.escape(name) + r"(?![A-Za-z0-9_.-])"
        )
        for path, (tier, text) in contents.items():
            if pattern.search(text):
                relative = str(path.relative_to(REPO_ROOT))
                found[name].setdefault(tier, []).append(relative)
    return found


def load_allowlist() -> dict[str, str]:
    if not ALLOWLIST_PATH.exists():
        raise AssertionError(f"missing allowlist file {ALLOWLIST_PATH}")
    data = tomllib.loads(ALLOWLIST_PATH.read_text(encoding="utf-8"))
    table = data.get(ALLOWLIST_TABLE, {})
    if not isinstance(table, dict):
        raise AssertionError(f"[{ALLOWLIST_TABLE}] in {ALLOWLIST_PATH} must be a table")
    return dict(table)


def _lift(name: str, reason: str) -> str:
    relative = ALLOWLIST_PATH.relative_to(REPO_ROOT)
    return (
        f"\n  LIFT: this rule is liftable in one line. Add to the "
        f"[{ALLOWLIST_TABLE}] table of\n        {relative}:\n\n"
        f'          "{name}" = "{reason}"\n\n'
        "        Widening an allowlist with a written reason is a one-line PR and a\n"
        "        normal part of active development, not a security event.\n"
        "  OR:   delete the subcommand, if it is genuinely dead — but prove the\n"
        "        deadness first; a line-wrapped invocation is invisible to a grep."
    )


def _report(found: dict[str, dict[str, list[str]]]) -> str:
    lines = ["", "  caller tiers for every registered subcommand:"]
    for name in sorted(found):
        tiers = found[name]
        summary = ", ".join(
            f"{tier}:{len(tiers[tier])}" for tier in TIERS if tier in tiers
        )
        lines.append(f"    {name:26s} {summary or '(no callers)'}")
    return "\n".join(lines)


def dead_subcommand_failures(
    names: tuple[str, ...],
    found: dict[str, dict[str, list[str]]],
    allowlist: dict[str, str],
) -> list[str]:
    """The zero-caller / test-only rule, as a pure function.

    It is a function rather than a test body so hostile fixtures can drive it.
    Every assertion below observes the LIVE repository, where — by design — no
    subcommand is dead; a rule exercised only against a green repository is
    satisfied just as well by a rule that refuses nothing, so the classifier
    needs inputs the repository does not supply.
    """
    failures: list[str] = []
    for name in names:
        tiers = frozenset(found[name])
        if tiers not in FAILING_TIER_SETS:
            continue
        if name in allowlist:
            continue
        if not tiers:
            reason = "why this command is registered with no caller"
            detail = (
                f"subcommand '{name}' has ZERO callers.\n"
                "  It is registered by the parser and invoked by nothing: "
                "dead code presenting a live interface."
            )
        else:
            where = ", ".join(sorted(found[name]["test"]))
            reason = "why a command only tests invoke should stay registered"
            detail = (
                f"subcommand '{name}' has TEST-ONLY callers ({where}).\n"
                "  The suite exercises a command nothing in a workflow, "
                "script, or doc invokes,\n  so the coverage is real and the "
                "command is still unreachable in production."
            )
        failures.append(detail + _lift(name, reason))
    return failures


def stale_allowlist_failures(
    names: tuple[str, ...],
    found: dict[str, dict[str, list[str]]],
    allowlist: dict[str, str],
) -> list[str]:
    """The blank-reason / unregistered / no-longer-needed rule, as a function.

    Same argument as above: the shipped allowlist is EMPTY, so every branch
    here is unreachable from live data alone.
    """
    relative = ALLOWLIST_PATH.relative_to(REPO_ROOT)
    failures: list[str] = []
    for name, reason in allowlist.items():
        if not isinstance(reason, str) or not reason.strip():
            failures.append(
                f"allowlist entry '{name}' has no written reason. An entry "
                "without a reason is not a decision, it is a hole."
            )
            continue
        if name not in names:
            failures.append(
                f"allowlist entry '{name}' is not a registered subcommand.\n"
                f"  Delete the line from the [{ALLOWLIST_TABLE}] table of "
                f"{relative}."
            )
            continue
        if frozenset(found[name]) not in FAILING_TIER_SETS:
            tiers = ", ".join(sorted(found[name]))
            failures.append(
                f"allowlist entry '{name}' is stale: it now has callers "
                f"({tiers}), so it passes on its own.\n"
                f"  Delete the line from the [{ALLOWLIST_TABLE}] table of "
                f"{relative}."
            )
    return failures


class EverySubcommandHasACaller(unittest.TestCase):
    def setUp(self) -> None:
        self.names = registered_subcommands()
        self.found = callers_by_tier(self.names)
        self.allowlist = load_allowlist()

    def test_the_parser_registers_subcommands_at_all(self) -> None:
        """A parser that registers nothing would pass every rule vacuously."""
        self.assertGreater(len(self.names), 1, "no subcommands were introspected")

    def test_the_search_set_is_not_empty(self) -> None:
        """A search set of zero files would report every subcommand dead."""
        files = search_set()
        self.assertTrue(files, "the search set collected no files")
        for tier in ("workflow", "script", "doc", "test"):
            self.assertIn(
                tier,
                set(files.values()),
                f"the search set collected no {tier} files; the globs above no "
                "longer describe this repository's layout",
            )

    def test_every_subcommand_has_a_non_test_caller(self) -> None:
        failures = dead_subcommand_failures(self.names, self.found, self.allowlist)
        if failures:
            self.fail("\n\n".join(failures) + "\n" + _report(self.found))

    def test_the_allowlist_carries_no_stale_entry(self) -> None:
        """An exemption that no longer exempts anything must be deleted.

        This is what keeps the lift mechanism cheap in BOTH directions. An
        allowlist that only ever grows stops describing reality and starts
        hiding it.
        """
        failures = stale_allowlist_failures(self.names, self.found, self.allowlist)
        if failures:
            self.fail("\n\n".join(failures))

    def test_the_module_under_audit_is_never_counted_as_a_caller(self) -> None:
        """`release_contract.py` contains every name it registers.

        Named explicitly rather than looped over `SELF_NAMING`, because a test
        that iterates the constant it pins shrinks silently when the constant
        does — it would pass for a `SELF_NAMING` that had dropped this entry.
        """
        self.assertTrue(MODULE_PATH.exists(), f"{MODULE_PATH} moved")
        self.assertNotIn(
            MODULE_PATH,
            set(search_set()),
            "counting release_contract.py would make every subcommand look "
            "called and the whole gate vacuous",
        )

    def test_the_allowlist_is_never_counted_as_a_caller(self) -> None:
        """The lift mechanism cannot be its own evidence of a caller.

        An exemption names the subcommand it exempts, so counting the allowlist
        deadlocks the lift: the added line gives the dead subcommand a
        script-tier caller, the stale rule then demands the line be deleted,
        and deleting it trips the zero-caller rule again. Its prose masks too —
        a comment naming a subcommand kept `settings-receipt` alive here with
        its real doc caller removed. Named explicitly, for the same reason as
        the test above.
        """
        self.assertTrue(ALLOWLIST_PATH.exists(), f"{ALLOWLIST_PATH} moved")
        self.assertNotIn(
            ALLOWLIST_PATH,
            set(search_set()),
            "counting ci_gate_allowlist.toml deadlocks its own one-line lift",
        )


class TheRuleRefusesWhatItClaimsTo(unittest.TestCase):
    """Hostile fixtures for the classifier itself.

    Every other assertion in this file reads the LIVE repository, where no
    subcommand is dead and the allowlist is empty — so a classifier that
    refused nothing at all would satisfy all of them. These drive the two rule
    functions with inputs the repository deliberately does not contain.
    """

    NAMES = ("orphan", "tested-only", "doc-only", "wired")
    FOUND: dict[str, dict[str, list[str]]] = {
        "orphan": {},
        "tested-only": {"test": ["scripts/ci/test_release_contract.py"]},
        "doc-only": {"doc": ["docs/release-governance.md"]},
        "wired": {"workflow": [".github/workflows/pr-gate.yml"], "test": ["t.py"]},
    }

    def failures(self, allowlist: dict[str, str] | None = None) -> list[str]:
        return dead_subcommand_failures(self.NAMES, self.FOUND, allowlist or {})

    def test_a_zero_caller_subcommand_is_refused(self) -> None:
        messages = [f for f in self.failures() if "'orphan'" in f]
        self.assertEqual(len(messages), 1, self.failures())
        self.assertIn("ZERO callers", messages[0])

    def test_a_test_only_subcommand_is_refused(self) -> None:
        messages = [f for f in self.failures() if "'tested-only'" in f]
        self.assertEqual(len(messages), 1, self.failures())
        self.assertIn("TEST-ONLY callers", messages[0])

    def test_a_doc_only_caller_is_accepted(self) -> None:
        """An operator escape hatch in a runbook is a real caller."""
        self.assertEqual([f for f in self.failures() if "'doc-only'" in f], [])

    def test_a_wired_subcommand_is_accepted(self) -> None:
        self.assertEqual([f for f in self.failures() if "'wired'" in f], [])

    def test_every_refusal_prints_the_exact_line_to_add(self) -> None:
        for message in self.failures():
            self.assertIn("LIFT:", message)
            self.assertIn("scripts/ci/ci_gate_allowlist.toml", message)
            self.assertIn(f"[{ALLOWLIST_TABLE}]", message)
            self.assertIn(" = ", message, "the exact line to add must be shown")

    def test_the_one_line_lift_actually_lifts(self) -> None:
        """The round trip the owner directive requires, both halves.

        Adding the printed line must silence the refusal AND must not be
        reported stale by the other rule. This pins the deadlock that made the
        mechanism unusable: while the allowlist counted as a caller, the entry
        gave its own subcommand a script-tier caller, so the refusal cleared
        and the stale rule immediately demanded the line be deleted again.
        """
        lift = {"orphan": "kept for a reviewed reason", "tested-only": "same"}
        self.assertEqual(self.failures(lift), [])
        self.assertEqual(stale_allowlist_failures(self.NAMES, self.FOUND, lift), [])

    def test_an_entry_scoped_to_another_subcommand_lifts_nothing(self) -> None:
        remaining = self.failures({"wired": "not the orphan"})
        self.assertEqual(len(remaining), 2, remaining)


class TheAllowlistRefusesWhatItClaimsTo(unittest.TestCase):
    """Hostile fixtures for the stale-entry rule, for the same reason."""

    NAMES = TheRuleRefusesWhatItClaimsTo.NAMES
    FOUND = TheRuleRefusesWhatItClaimsTo.FOUND

    def failures(self, allowlist: dict[str, str]) -> list[str]:
        return stale_allowlist_failures(self.NAMES, self.FOUND, allowlist)

    def test_a_blank_reason_fails_closed(self) -> None:
        messages = self.failures({"orphan": "   "})
        self.assertEqual(len(messages), 1, messages)
        self.assertIn("no written reason", messages[0])

    def test_an_unregistered_entry_is_refused(self) -> None:
        messages = self.failures({"was-deleted-in-this-pr": "stale"})
        self.assertEqual(len(messages), 1, messages)
        self.assertIn("not a registered subcommand", messages[0])

    def test_an_entry_whose_case_resolved_is_refused(self) -> None:
        messages = self.failures({"wired": "no longer needed"})
        self.assertEqual(len(messages), 1, messages)
        self.assertIn("stale", messages[0])
        self.assertIn("Delete the line", messages[0])

    def test_an_entry_still_doing_work_is_kept(self) -> None:
        self.assertEqual(self.failures({"orphan": "reviewed"}), [])


if __name__ == "__main__":  # pragma: no cover - manual invocation
    unittest.main()
