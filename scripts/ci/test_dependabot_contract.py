"""Hostile tests for the Dependabot config schema gate (issue #56).

Mirrors the loading and assertion style of test_release_contract.py: the
module under test is loaded by path (not import) so these tests exercise the
exact file CI runs, real fixtures are read from the working tree rather than
duplicated as literals, and every rejection is asserted by its EXACT
per-line message rather than a loose substring, so a message regression is
as visible as a logic regression.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import sys
import tempfile
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SPEC = importlib.util.spec_from_file_location("dependabot_contract", HERE / "dependabot_contract.py")
assert SPEC and SPEC.loader
DC = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = DC
SPEC.loader.exec_module(DC)

REAL_PATH = ROOT / ".github" / "dependabot.yml"


def real_text() -> str:
    return REAL_PATH.read_text(encoding="utf-8")


def assert_denied(case: unittest.TestCase, text: str, expected: str) -> None:
    with case.assertRaises(DC.ContractError) as denied:
        DC.check_text(text)
    case.assertEqual(str(denied.exception), expected)


class RealConfigTests(unittest.TestCase):
    """The repository's own dependabot.yml is the load-bearing positive case."""

    def test_the_repositorys_own_config_is_valid(self):
        entry_count, group_count = DC.check_text(real_text())
        self.assertEqual(entry_count, 3)
        self.assertEqual(group_count, 2)

    def test_the_repositorys_own_config_reparses_identically(self):
        # A parse is deterministic: running it twice on the same bytes must
        # not depend on any hidden state (dict ordering, module globals).
        first = DC.check_text(real_text())
        second = DC.check_text(real_text())
        self.assertEqual(first, second)


class LowLevelParserTests(unittest.TestCase):
    """The generic block reader, exercised independently of the schema."""

    def test_rejects_empty_and_whitespace_only_documents(self):
        for label, text in (
            ("empty", ""),
            ("whitespace only", "   \n\n  \n"),
        ):
            with self.subTest(label=label), self.assertRaises(DC.ContractError) as denied:
                DC.parse_yaml_subset(text)
            self.assertEqual(str(denied.exception), "line 1: file has no content")

    def test_comments_are_rejected_everywhere_not_skipped(self):
        # Adversarial finding 1 (PR #72): a prior version treated only a
        # line whose first non-space character was "#" as a comment and
        # silently skipped it, which meant every OTHER "#" -- a trailing
        # comment on real content, or a bare "- # x" null item -- was
        # folded into the scalar it followed instead of being rejected.
        # Comments are unsupported in every position now; every "#"
        # refuses the file outright, full-line or inline, quoted or not.
        cases = {
            "full line, leading": "# top rationale\nversion: 2\nupdates:\n  - package-ecosystem: npm\n    directory: /\n    schedule:\n      interval: daily\n",
            "full line, indented": "version: 2\nupdates:\n  # a note\n  - package-ecosystem: npm\n    directory: /\n    schedule:\n      interval: daily\n",
            "trailing on a mapping value": "version: 2\nupdates:\n  - package-ecosystem: npm # frontend\n    directory: /\n    schedule:\n      interval: daily\n",
            "trailing on a quoted scalar": "version: 2\nupdates:\n  - package-ecosystem: npm\n    directory: /\n    schedule:\n      interval: daily\n    groups:\n      g:\n        patterns:\n          - \"svelte\" # core\n",
            "null sequence item (dash then comment only)": "version: 2\nupdates:\n  - package-ecosystem: npm\n    directory: /\n    schedule:\n      interval: daily\n    groups:\n      g:\n        patterns:\n          - # the core package\n",
            "comment-only document": "# just a comment\n",
        }
        for label, text in cases.items():
            with self.subTest(label=label), self.assertRaises(DC.ContractError) as denied:
                DC.parse_yaml_subset(text)
            self.assertIn("'#' comments are not supported", str(denied.exception))

    def test_rejects_tabs_anywhere_in_the_document(self):
        with self.assertRaises(DC.ContractError) as denied:
            DC.parse_yaml_subset("version: 2\n\tupdates: []\n")
        self.assertEqual(str(denied.exception), "line 2: tab characters are not allowed; use spaces")

    def test_rejects_carriage_returns(self):
        with self.assertRaises(DC.ContractError) as denied:
            DC.parse_yaml_subset("version: 2\r\nupdates: []\r\n")
        self.assertEqual(
            str(denied.exception),
            "line 1: carriage returns are not allowed; use bare LF line endings",
        )

    def test_rejects_flow_style_at_top_level(self):
        with self.assertRaises(DC.ContractError) as denied:
            DC.parse_yaml_subset("version: 2\nupdates: []\n")
        self.assertEqual(
            str(denied.exception),
            "line 2: flow-style collections are not supported; use a block list or mapping",
        )

    def test_rejects_flow_style_mapping(self):
        with self.assertRaises(DC.ContractError) as denied:
            DC.parse_yaml_subset('version: 2\nupdates:\n  - groups: {a: {patterns: [x]}}\n')
        self.assertEqual(
            str(denied.exception),
            "line 3: flow-style collections are not supported; use a block list or mapping",
        )

    def test_rejects_a_continuation_key_with_no_space_before_its_value(self):
        # The FIRST key on a "- key: value" line is scanned differently
        # (compact-mapping start) from every key that follows it on its own
        # line (an ordinary mapping continuation) — exercise the latter,
        # where "directory:/" cannot be a colon-bearing plain scalar because
        # a bare mapping key is the only thing expected at that column.
        with self.assertRaises(DC.ContractError) as denied:
            DC.parse_yaml_subset(
                "version: 2\nupdates:\n  - package-ecosystem: npm\n    directory:/\n"
            )
        self.assertEqual(
            str(denied.exception),
            "line 4: expected a mapping key in the form 'key:' or 'key: value'",
        )

    def test_a_colon_with_no_space_after_a_dash_is_a_plain_scalar_not_a_key(self):
        # Real YAML never treats ":" without a following space as a mapping
        # indicator; "- package-ecosystem:npm" is therefore a one-item
        # sequence of the literal string, not a malformed key — and fails
        # later, structurally, because updates[] entries must be mappings.
        tree = DC.parse_yaml_subset("version: 2\nupdates:\n  - package-ecosystem:npm\n")
        item = tree.items["updates"].items[0]
        self.assertIsInstance(item, DC.Scalar)
        self.assertEqual(item.text, "package-ecosystem:npm")
        with self.assertRaises(DC.ContractError) as denied:
            DC.validate_dependabot(tree)
        self.assertEqual(str(denied.exception), "line 3: updates[0] must be a mapping")

    def test_rejects_an_unterminated_quoted_scalar(self):
        with self.assertRaises(DC.ContractError) as denied:
            DC.parse_yaml_subset('version: 2\nupdates:\n  - package-ecosystem: "npm\n')
        self.assertEqual(str(denied.exception), "line 3: unterminated quoted scalar")

    def test_rejects_a_bare_key_with_no_following_block(self):
        with self.assertRaises(DC.ContractError) as denied:
            DC.parse_yaml_subset("version: 2\nupdates:\n")
        self.assertEqual(str(denied.exception), "line 2: key 'updates' has no value")

    def test_rejects_duplicate_keys_in_one_mapping(self):
        with self.assertRaises(DC.ContractError) as denied:
            DC.parse_yaml_subset("version: 2\nversion: 2\nupdates:\n  - package-ecosystem: npm\n")
        self.assertEqual(str(denied.exception), "line 2: duplicate key 'version'")

    def test_rejects_orphaned_indentation_not_tied_to_a_key(self):
        with self.assertRaises(DC.ContractError) as denied:
            DC.parse_yaml_subset("version: 2\n   updates: []\n")
        self.assertEqual(str(denied.exception), "line 2: unexpected indentation")

    def test_rejects_a_document_that_does_not_start_at_column_zero(self):
        with self.assertRaises(DC.ContractError) as denied:
            DC.parse_yaml_subset("  version: 2\n")
        self.assertEqual(str(denied.exception), "line 1: the document must start at column 0")

    def test_rejects_sequence_item_spacing_that_is_not_exactly_dash_space(self):
        # A dash with no following space never dispatches as a sequence at
        # all (real YAML requires "- " or a bare "-"), so it falls through
        # to the mapping reader and fails as an invalid key instead — a
        # dash with two or more spaces DOES dispatch as a sequence and is
        # caught by the dedicated spacing check inside it. Both are
        # rejections; the exact reason differs by which reader saw it.
        with self.assertRaises(DC.ContractError) as denied:
            DC.parse_yaml_subset("version: 2\nupdates:\n  -package-ecosystem: npm\n")
        self.assertEqual(
            str(denied.exception),
            "line 3: expected a mapping key in the form 'key:' or 'key: value'",
        )
        with self.assertRaises(DC.ContractError) as denied:
            DC.parse_yaml_subset("version: 2\nupdates:\n  -  package-ecosystem: npm\n")
        self.assertEqual(
            str(denied.exception),
            "line 3: sequence item must be '- ' (dash, one space) followed by content",
        )

    def test_rejects_nested_inline_sequence_markers(self):
        with self.assertRaises(DC.ContractError) as denied:
            DC.parse_yaml_subset("version: 2\nupdates:\n  - - nested\n")
        self.assertEqual(str(denied.exception), "line 3: nested inline sequence markers are not supported")

    def test_top_level_must_be_a_mapping_not_a_sequence(self):
        with self.assertRaises(DC.ContractError) as denied:
            DC.parse_yaml_subset("- a\n- b\n")
        self.assertEqual(str(denied.exception), "line 1: the top-level document must be a mapping")

    # The following eight tests each pin one branch the PR #72 adversarial
    # review confirmed reachable-but-untested: a targeted weakening of any
    # one survived the suite that was green at review time. Each fixture
    # below reproduces the reviewer's own reachability probe; a name or
    # message change on the guard it exercises must turn the matching test
    # red, which is what makes it a guard and not decoration.

    def test_rejects_anchors_aliases_tags_and_block_scalars(self):
        for label, construct in (
            ("anchor", "&anchor"),
            ("alias", "*alias"),
            ("tag", "!tag"),
            ("literal block scalar", "|"),
            ("folded block scalar", ">"),
        ):
            text = f"version: 2\nupdates:\n  - package-ecosystem: {construct} npm\n"
            with self.subTest(label=label), self.assertRaises(DC.ContractError) as denied:
                DC.parse_yaml_subset(text)
            self.assertEqual(
                str(denied.exception),
                f"line 3: unsupported YAML construct starting with {construct[0]!r}",
            )

    def test_rejects_a_quoted_scalar_with_an_embedded_unescaped_quote(self):
        with self.assertRaises(DC.ContractError) as denied:
            DC.parse_yaml_subset('version: 2\nupdates:\n  - package-ecosystem: "a"b"\n')
        self.assertEqual(str(denied.exception), "line 3: quoted scalar contains an unescaped quote character")

    def test_rejects_an_unquoted_scalar_containing_a_quote_character(self):
        with self.assertRaises(DC.ContractError) as denied:
            DC.parse_yaml_subset('version: 2\nupdates:\n  - package-ecosystem: a"b\n')
        self.assertEqual(str(denied.exception), "line 3: unquoted scalar contains a quote character")

    def test_a_sequence_item_inside_a_mapping_block_is_rejected(self):
        # A "- " line appearing where a mapping's next key is expected,
        # at the mapping's own indent (schedule: is a mapping; a stray
        # dash item under it is neither one of its keys nor a nested
        # block of the preceding key).
        text = (
            "version: 2\nupdates:\n  - package-ecosystem: npm\n    directory: /\n"
            "    schedule:\n      interval: daily\n      - stray\n"
        )
        with self.assertRaises(DC.ContractError) as denied:
            DC.parse_yaml_subset(text)
        self.assertEqual(str(denied.exception), "line 7: expected a mapping key, found a sequence item")

    def test_a_mapping_key_inside_a_sequence_block_is_rejected(self):
        # The mirror image: a "key: value" line at a sequence's own
        # indent, where only more "- " items are expected.
        text = (
            "version: 2\nupdates:\n  - package-ecosystem: npm\n    directory: /\n"
            "    schedule:\n      interval: daily\n    groups:\n      g:\n"
            "        patterns:\n          - \"x\"\n          foo: bar\n"
        )
        with self.assertRaises(DC.ContractError) as denied:
            DC.parse_yaml_subset(text)
        self.assertEqual(str(denied.exception), "line 11: expected a sequence item, found a mapping key")

    def test_a_bare_dash_with_nothing_indented_after_it_is_rejected(self):
        text = (
            "version: 2\nupdates:\n  - package-ecosystem: npm\n    directory: /\n"
            "    schedule:\n      interval: daily\n    groups:\n      g:\n"
            "        patterns:\n          -\n"
        )
        with self.assertRaises(DC.ContractError) as denied:
            DC.parse_yaml_subset(text)
        self.assertEqual(str(denied.exception), "line 10: sequence item has no value")

    def test_orphaned_indentation_after_a_compact_mappings_last_key_is_rejected(self):
        # Over-indentation immediately after "- key: value" (the compact
        # mapping's inline first key, with no bare-key block to absorb it)
        # is denied. In the unmutated reader this specific guard, internal
        # to _parse_sequence's compact-mapping continuation, is the first
        # of three "unexpected indentation" checks to see the stray line:
        # this one, then _parse_sequence's own end-of-block guard right
        # below it, then the enclosing _parse_mapping's end-of-block guard
        # one level up -- each strictly more general than the last, since
        # a residual line over-indented for THIS check is, by construction
        # (item_indent = indent + 2), also over-indented for every guard
        # enclosing it. Disabling this guard alone, or this one together
        # with _parse_sequence's own end-of-block guard, still denies this
        # exact fixture with this exact message (verified by hand): the
        # enclosing _parse_mapping guard backstops both. That makes this
        # assertion proof of fail-closed behavior on this fixture, not
        # proof that this specific line is the one deciding it -- an
        # honest distinction from the branches above it in this file, most
        # of which (duplicate keys, sequence/mapping-shape mismatches, the
        # dash-spacing rules) have no such backstop and really do turn
        # green the moment their one guard is weakened.
        with self.assertRaises(DC.ContractError) as denied:
            DC.parse_yaml_subset("version: 2\nupdates:\n  - package-ecosystem: npm\n      stray: deep\n")
        self.assertEqual(str(denied.exception), "line 4: unexpected indentation")

    def test_orphaned_indentation_after_a_sequences_last_item_is_rejected(self):
        # Over-indentation after a sequence's own final item (not tied to
        # any specific item's compact mapping) is denied -- the
        # sequence-level sibling of
        # test_rejects_orphaned_indentation_not_tied_to_a_key, which
        # exercises the mapping-level version of this same check. Same
        # caveat as the test above: this fixture's stray line is also
        # caught by the enclosing "patterns:"-owning mapping's own
        # end-of-block guard, confirmed by disabling both simultaneously.
        # The two checks are redundant by construction, not by accident:
        # every block this reader parses is a value nested under some
        # mapping key, so a sequence's own trailing-indentation guard can
        # never be the outermost check for any real dependabot.yml shape.
        text = (
            "version: 2\nupdates:\n  - package-ecosystem: npm\n    directory: /\n"
            "    schedule:\n      interval: daily\n    groups:\n      g:\n"
            "        patterns:\n          - \"x\"\n            stray\n"
        )
        with self.assertRaises(DC.ContractError) as denied:
            DC.parse_yaml_subset(text)
        self.assertEqual(str(denied.exception), "line 11: unexpected indentation")


class RequiredHostileBatteryTests(unittest.TestCase):
    """The exact hostile cases issue #56 and the shared spec enumerate.

    Each fixture is the real dependabot.yml with one exact, targeted
    mutation, so a passing suite proves the gate catches the SAME class of
    defect this repository actually shipped once (PR #55, finding 1), not a
    synthetic stand-in for it.
    """

    def test_the_exact_pr55_finding_1_groups_stanza_is_rejected(self):
        # PR #55's adversarial review (mutant g) renamed `patterns:` to
        # `patternz:` and added `bogus-key: 12345` under the codeql-action
        # group; every existing gate passed it. That exact stanza shape:
        text = real_text().replace(
            '    groups:\n      codeql-action:\n        patterns:\n          - "github/codeql-action*"\n',
            '    groups:\n      codeql-action:\n        patternz:\n          - "github/codeql-action*"\n'
            "        bogus-key: 12345\n",
            1,
        )
        self.assertNotEqual(text, real_text())
        assert_denied(self, text, "line 12: unknown key 'bogus-key' in groups.codeql-action")
        # patternz alone (no bogus-key) independently proves patterns is
        # still required — the group's ONE real key was simply misspelled.
        patternz_only = real_text().replace(
            '        patterns:\n          - "github/codeql-action*"\n',
            '        patternz:\n          - "github/codeql-action*"\n',
            1,
        )
        assert_denied(self, patternz_only, "line 10: unknown key 'patternz' in groups.codeql-action")

    def test_version_1_is_rejected(self):
        text = real_text().replace("version: 2", "version: 1", 1)
        assert_denied(self, text, "line 1: version must be the unquoted integer 2")

    def test_missing_schedule_is_rejected(self):
        text = real_text().replace(
            "  - package-ecosystem: gomod\n    directory: /\n    schedule:\n      interval: weekly\n",
            "  - package-ecosystem: gomod\n    directory: /\n",
            1,
        )
        assert_denied(self, text, "line 12: updates[1] is missing required key 'schedule'")

    def test_unknown_ecosystem_is_rejected(self):
        text = real_text().replace("package-ecosystem: gomod", "package-ecosystem: cocoapods-bogus", 1)
        assert_denied(self, text, "line 12: unknown package-ecosystem 'cocoapods-bogus'")

    def test_unknown_key_is_rejected_at_every_level(self):
        top = "enable-beta-ecosystems: true\n" + real_text()
        assert_denied(self, top, "line 1: unknown key 'enable-beta-ecosystems' in the top-level document")

        entry = real_text().replace(
            "  - package-ecosystem: gomod\n    directory: /\n",
            "  - package-ecosystem: gomod\n    directory: /\n    foo-bar: baz\n",
            1,
        )
        assert_denied(self, entry, "line 14: unknown key 'foo-bar' in updates[1]")

        schedule = real_text().replace(
            "    schedule:\n      interval: weekly\n    open-pull-requests-limit: 5\n",
            "    schedule:\n      frequency: often\n      interval: weekly\n    open-pull-requests-limit: 5\n",
            1,
        )
        assert_denied(self, schedule, "line 6: unknown key 'frequency' in updates[0].schedule")

        group = real_text().replace(
            '        patterns:\n          - "github/codeql-action*"\n',
            '        patterns:\n          - "github/codeql-action*"\n        color: purple\n',
            1,
        )
        assert_denied(self, group, "line 12: unknown key 'color' in groups.codeql-action")

    def test_empty_updates_is_rejected(self):
        assert_denied(self, "version: 2\nupdates:\n", "line 2: key 'updates' has no value")
        assert_denied(
            self,
            "version: 2\nupdates: []\n",
            "line 2: flow-style collections are not supported; use a block list or mapping",
        )

    def test_tab_indentation_is_rejected(self):
        text = real_text().replace("    directory: /\n", "\tdirectory: /\n", 1)
        assert_denied(self, text, "line 4: tab characters are not allowed; use spaces")

    def test_flow_style_patterns_list_is_rejected(self):
        text = real_text().replace(
            '        patterns:\n          - "github/codeql-action*"\n',
            '        patterns: ["github/codeql-action*"]\n',
            1,
        )
        assert_denied(
            self,
            text,
            "line 10: flow-style collections are not supported; use a block list or mapping",
        )


class SchemaValidationTests(unittest.TestCase):
    """Every semantic branch beyond the required battery, each independently
    proven both to fire on bad input and to accept the corresponding good
    input — an assertion that never fires on any input is decorative, and
    the adversarial review protocol treats that as a finding."""

    def test_quoted_version_is_rejected(self):
        text = real_text().replace("version: 2", 'version: "2"', 1)
        assert_denied(self, text, "line 1: version must be the unquoted integer 2")

    def test_updates_entry_must_be_a_mapping(self):
        assert_denied(self, "version: 2\nupdates:\n  - justastring\n", "line 3: updates[0] must be a mapping")

    def test_directory_must_start_with_a_slash(self):
        text = real_text().replace("directory: /frontend", "directory: frontend", 1)
        assert_denied(self, text, "line 18: updates[2].directory must start with '/'")
        # Positive: root "/" (used twice in the real file) is accepted.
        self.assertEqual(DC.check_text(real_text()), (3, 2))

    def test_open_pull_requests_limit_must_be_an_unquoted_non_negative_integer(self):
        for label, mutated, expected in (
            (
                "not numeric",
                real_text().replace("open-pull-requests-limit: 5", "open-pull-requests-limit: many", 1),
                "line 7: updates[0].open-pull-requests-limit must be an unquoted non-negative integer",
            ),
            (
                "quoted",
                real_text().replace("open-pull-requests-limit: 5", 'open-pull-requests-limit: "5"', 1),
                "line 7: updates[0].open-pull-requests-limit must be an unquoted non-negative integer",
            ),
            (
                "leading zero",
                real_text().replace("open-pull-requests-limit: 5", "open-pull-requests-limit: 05", 1),
                "line 7: updates[0].open-pull-requests-limit must be an unquoted non-negative integer",
            ),
            (
                "negative",
                real_text().replace("open-pull-requests-limit: 5", "open-pull-requests-limit: -1", 1),
                "line 7: updates[0].open-pull-requests-limit must be an unquoted non-negative integer",
            ),
        ):
            with self.subTest(label=label):
                assert_denied(self, mutated, expected)

    def test_groups_value_must_be_a_mapping(self):
        text = real_text().replace(
            '    groups:\n      codeql-action:\n        patterns:\n          - "github/codeql-action*"\n',
            "    groups: yes\n",
            1,
        )
        assert_denied(self, text, "line 8: updates[0].groups must be a mapping")

    def test_group_spec_must_be_a_mapping(self):
        text = real_text().replace(
            '      codeql-action:\n        patterns:\n          - "github/codeql-action*"\n',
            "      codeql-action: yes\n",
            1,
        )
        assert_denied(self, text, "line 9: groups.codeql-action must be a mapping")

    def test_group_missing_patterns_is_rejected(self):
        text = real_text().replace(
            '      codeql-action:\n        patterns:\n          - "github/codeql-action*"\n',
            "      codeql-action:\n        dependency-type: production\n",
            1,
        )
        assert_denied(self, text, "line 10: groups.codeql-action is missing required key 'patterns'")

    def test_group_pattern_entries_must_be_non_empty(self):
        text = real_text().replace('- "github/codeql-action*"', '- ""', 1)
        assert_denied(self, text, "line 11: groups.codeql-action.patterns entries must be non-empty strings")

    def test_duplicate_group_names_are_rejected(self):
        text = real_text().replace(
            '      codeql-action:\n        patterns:\n          - "github/codeql-action*"\n',
            '      codeql-action:\n        patterns:\n          - "github/codeql-action*"\n'
            '      codeql-action:\n        patterns:\n          - "other"\n',
            1,
        )
        assert_denied(self, text, "line 12: duplicate key 'codeql-action'")

    def test_group_dependency_type_enum(self):
        good = real_text().replace(
            '        patterns:\n          - "github/codeql-action*"\n',
            '        patterns:\n          - "github/codeql-action*"\n        dependency-type: production\n',
            1,
        )
        self.assertEqual(DC.check_text(good), (3, 2))
        bad = real_text().replace(
            '        patterns:\n          - "github/codeql-action*"\n',
            '        patterns:\n          - "github/codeql-action*"\n        dependency-type: staging\n',
            1,
        )
        assert_denied(self, bad, "line 12: unknown groups.codeql-action.dependency-type 'staging'")

    def test_group_update_types_enum(self):
        good = real_text().replace(
            '        patterns:\n          - "github/codeql-action*"\n',
            '        patterns:\n          - "github/codeql-action*"\n        update-types:\n          - minor\n          - patch\n',
            1,
        )
        self.assertEqual(DC.check_text(good), (3, 2))
        bad = real_text().replace(
            '        patterns:\n          - "github/codeql-action*"\n',
            '        patterns:\n          - "github/codeql-action*"\n        update-types:\n          - epic\n',
            1,
        )
        assert_denied(self, bad, "line 13: unknown groups.codeql-action.update-types entry 'epic'")

    def test_group_applies_to_enum(self):
        good = real_text().replace(
            '        patterns:\n          - "github/codeql-action*"\n',
            '        patterns:\n          - "github/codeql-action*"\n        applies-to: security-updates\n',
            1,
        )
        self.assertEqual(DC.check_text(good), (3, 2))
        bad = real_text().replace(
            '        patterns:\n          - "github/codeql-action*"\n',
            '        patterns:\n          - "github/codeql-action*"\n        applies-to: everything\n',
            1,
        )
        assert_denied(self, bad, "line 12: unknown groups.codeql-action.applies-to 'everything'")

    def test_group_exclude_patterns_shape(self):
        good = real_text().replace(
            '        patterns:\n          - "github/codeql-action*"\n',
            '        patterns:\n          - "github/codeql-action*"\n        exclude-patterns:\n          - "github/codeql-action-cli"\n',
            1,
        )
        self.assertEqual(DC.check_text(good), (3, 2))
        bad = real_text().replace(
            '        patterns:\n          - "github/codeql-action*"\n',
            '        patterns:\n          - "github/codeql-action*"\n        exclude-patterns:\n          - ""\n',
            1,
        )
        assert_denied(self, bad, "line 13: groups.codeql-action.exclude-patterns entries must be non-empty strings")

    def test_schedule_interval_enum(self):
        text = real_text().replace("interval: weekly", "interval: fortnightly", 1)
        assert_denied(self, text, "line 6: unknown updates[0].schedule.interval 'fortnightly'")

    def test_schedule_day_time_timezone_are_accepted_when_valid(self):
        text = real_text().replace(
            "      interval: weekly\n    open-pull-requests-limit: 5\n",
            "      interval: weekly\n      day: monday\n      time: \"02:00\"\n"
            "      timezone: America/New_York\n    open-pull-requests-limit: 5\n",
            1,
        )
        self.assertEqual(DC.check_text(text), (3, 2))

    def test_schedule_day_time_timezone_are_rejected_when_malformed(self):
        for label, mutated, expected in (
            (
                "day",
                real_text().replace(
                    "      interval: weekly\n    open-pull-requests-limit: 5\n",
                    "      interval: weekly\n      day: someday\n    open-pull-requests-limit: 5\n",
                    1,
                ),
                "line 7: unknown updates[0].schedule.day 'someday'",
            ),
            (
                "time",
                real_text().replace(
                    "      interval: weekly\n    open-pull-requests-limit: 5\n",
                    '      interval: weekly\n      time: "2:00"\n    open-pull-requests-limit: 5\n',
                    1,
                ),
                "line 7: updates[0].schedule.time must be 24-hour HH:MM",
            ),
            (
                "timezone",
                real_text().replace(
                    "      interval: weekly\n    open-pull-requests-limit: 5\n",
                    '      interval: weekly\n      timezone: "not a tz!"\n    open-pull-requests-limit: 5\n',
                    1,
                ),
                "line 7: updates[0].schedule.timezone is not a recognizable identifier",
            ),
        ):
            with self.subTest(label=label):
                assert_denied(self, mutated, expected)

    def test_a_leading_comment_on_an_otherwise_valid_document_is_rejected(self):
        # Superseded by the comments-are-never-supported design (finding 1):
        # this used to be the accepted case; the whole positive claim was
        # part of what the fix reversed, so pin the reversal explicitly
        # here rather than only in LowLevelParserTests.
        text = "# groups exist to stop mutually-blocking version-locked PRs\n" + real_text()
        with self.assertRaises(DC.ContractError) as denied:
            DC.check_text(text)
        self.assertEqual(str(denied.exception), "line 1: '#' comments are not supported, full-line or inline; remove the comment")

    def test_inline_comments_are_rejected_at_every_documented_position(self):
        # Finding 1's false-reject half: before the fix, a trailing comment
        # on real content did not just get absorbed -- several shapes were
        # rejected too, but for the WRONG reason (an invented ecosystem, an
        # invented interval, a syntax error), which would have misled
        # anyone debugging why their otherwise-valid file failed. Now every
        # one fails for the SAME, correct, and only reason.
        cases = {
            "package-ecosystem": real_text().replace("package-ecosystem: npm", "package-ecosystem: npm # frontend", 1),
            "schedule.interval": real_text().replace("interval: weekly", "interval: weekly # once a week", 1),
            "version": real_text().replace("version: 2", "version: 2 # schema v2", 1),
            "open-pull-requests-limit": real_text().replace(
                "open-pull-requests-limit: 3", "open-pull-requests-limit: 3 # cap", 1
            ),
            "quoted pattern with trailing comment": real_text().replace(
                '- "svelte"\n', '- "svelte" # core\n', 1
            ),
        }
        for label, text in cases.items():
            with self.subTest(label=label), self.assertRaises(DC.ContractError) as denied:
                DC.check_text(text)
            self.assertIn("'#' comments are not supported", str(denied.exception))

    def test_as_sequence_correctly_rejects_a_scalar_where_a_list_belongs(self):
        # Finding 2's first fail-open weakening: a mutant that neuters
        # _as_sequence to return an empty Sequence instead of raising turns
        # this exact "patterns: svelte" typo -- a plausible human mistake,
        # the same malformed-groups class issue #56 exists to catch -- into
        # a group with zero patterns that silently PASSES. This test calls
        # _as_sequence only through the normal parse/validate path (never
        # the private function directly), so it is dead only if the whole
        # call chain is dead.
        text = real_text().replace(
            '        patterns:\n          - "github/codeql-action*"\n',
            "        patterns: svelte\n",
            1,
        )
        assert_denied(self, text, "line 10: groups.codeql-action.patterns must be a list")
        # updates: itself is _as_sequence's other call site; cover it too.
        assert_denied(
            self,
            "version: 2\nupdates: justastring\n",
            "line 2: updates must be a list",
        )

    def test_as_scalar_correctly_rejects_a_mapping_where_a_plain_value_belongs(self):
        text = real_text().replace(
            "directory: /frontend",
            "directory:\n      nested: 1",
            1,
        )
        assert_denied(
            self, text, "line 18: updates[2].directory must be a plain value, not a nested list or mapping"
        )

    def test_scalars_reject_forbidden_control_characters(self):
        # Finding 5: NUL, DEL, and the C1/line-separator ranges previously
        # passed straight through as literal pattern/directory text.
        for label, mutated, line_no, code_point in (
            ("NUL in a pattern", real_text().replace('"github/codeql-action*"', '"nul\x00here"', 1), 11, "0000"),
            ("DEL after directory", real_text().replace("directory: /frontend", "directory: /frontend\x7f", 1), 18, "007F"),
            ("NEL (C1) in a pattern", real_text().replace('"github/codeql-action*"', '"a\x85b"', 1), 11, "0085"),
            ("LINE SEPARATOR in a pattern", real_text().replace('"github/codeql-action*"', '"a\u2028b"', 1), 11, "2028"),
        ):
            with self.subTest(label=label), self.assertRaises(DC.ContractError) as denied:
                DC.check_text(mutated)
            self.assertEqual(
                str(denied.exception),
                f"line {line_no}: scalar contains a forbidden control character U+{code_point}",
            )


class DocumentedNarrownessTests(unittest.TestCase):
    """Finding 4: narrowing this reader deliberately accepts (fails closed,
    never a correctness hole) but that the module docstring must state
    rather than leave for the next author to discover by accident."""

    def test_group_names_are_restricted_to_the_key_charset(self):
        # Dependabot's own group names are arbitrary strings; this reader
        # reuses KEY_RE for every mapping key including group names, with
        # no quoting escape hatch.
        for label, name in (
            ("leading digit", "1action"),
            ("at-scoped", "@sveltejs"),
            ("leading underscore", "_private"),
            ("embedded space", "svelte pkgs"),
        ):
            text = real_text().replace("codeql-action:", f"{name}:", 1)
            with self.subTest(label=label), self.assertRaises(DC.ContractError) as denied:
                DC.parse_yaml_subset(text)
            self.assertIn("expected a mapping key", str(denied.exception))

    def test_a_same_indent_block_sequence_is_rejected(self):
        # Idiomatic, valid YAML ("patterns:" then "- x" at the SAME
        # column) is out of scope: this reader requires a sequence's items
        # to be indented STRICTLY deeper than the key that introduces them.
        text = (
            "version: 2\nupdates:\n  - package-ecosystem: npm\n    directory: /\n"
            "    schedule:\n      interval: daily\n    groups:\n      g:\n"
            "        patterns:\n        - \"x\"\n"
        )
        with self.assertRaises(DC.ContractError) as denied:
            DC.parse_yaml_subset(text)
        self.assertEqual(str(denied.exception), "line 9: key 'patterns' has no value")

    def test_a_byte_order_mark_is_rejected_by_name(self):
        with self.assertRaises(DC.ContractError) as denied:
            DC.parse_yaml_subset("\ufeff" + real_text())
        self.assertEqual(
            str(denied.exception),
            "line 1: a UTF-8 byte-order mark is not supported; save the file without a BOM",
        )


class CommandLineInterfaceTests(unittest.TestCase):
    """`python3 -I -B scripts/ci/dependabot_contract.py <path>`, exit 0/2."""

    @staticmethod
    def invoke(argv: list[str]) -> tuple[int, str, str]:
        with contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()) as err:
            try:
                status = DC.main(argv)
            except SystemExit as exc:
                status = exc.code
        return status, out.getvalue(), err.getvalue()

    def test_the_real_file_exits_zero_with_a_summary(self):
        status, out, err = self.invoke([str(REAL_PATH)])
        self.assertEqual(status, 0)
        self.assertEqual(err, "")
        self.assertEqual(
            out,
            f"dependabot_contract: OK - {REAL_PATH}: 3 update entries, 2 groups\n",
        )

    def test_a_missing_file_exits_two_and_denies_by_path(self):
        missing = REAL_PATH.parent / "does-not-exist.yml"
        self.assertFalse(missing.exists())
        status, out, err = self.invoke([str(missing)])
        self.assertEqual(status, 2)
        self.assertEqual(out, "")
        self.assertTrue(err.startswith(f"DENY: {missing}: "))

    def test_no_path_argument_exits_two(self):
        status, _out, _err = self.invoke([])
        self.assertEqual(status, 2)

    def test_bytes_that_are_not_valid_utf8_exit_two_and_deny_by_path(self):
        # `main()` reads with `encoding="utf-8"` and has a dedicated
        # `except UnicodeDecodeError` handler sitting right next to the
        # `except OSError` one above -- covered by
        # test_a_missing_file_exits_two_and_denies_by_path -- but nothing
        # exercised it: a mutant collapsing it to `return 0` (turning a file
        # CI cannot even decode into a silent pass) survived. 0x80 is a bare
        # UTF-8 continuation byte with no lead byte before it, invalid in
        # every position.
        with tempfile.TemporaryDirectory() as scratch:
            target = Path(scratch) / "dependabot.yml"
            target.write_bytes(b"version: 2\nupdates:\n  - package-ecosystem: \x80\n")
            status, out, err = self.invoke([str(target)])
            self.assertEqual(status, 2)
            self.assertEqual(out, "")
            self.assertTrue(err.startswith(f"DENY: {target}: "))
            self.assertIn("codec can't decode byte", err)

    def test_mutation_proof_on_a_temporary_corrupted_copy(self):
        # Copy the real file into a scratch directory, corrupt it with the
        # exact PR #55 finding-1 shape, prove the CLI denies it at the exact
        # line and exits 2, then restore the pristine bytes in the SAME
        # path and prove the CLI now exits 0 — proving the gate is neither
        # too strict on valid input nor silent on the invalid input.
        with tempfile.TemporaryDirectory() as scratch:
            target = Path(scratch) / "dependabot.yml"
            pristine = real_text()
            target.write_text(pristine, encoding="utf-8")

            status, _out, err = self.invoke([str(target)])
            self.assertEqual(status, 0)

            corrupted = pristine.replace(
                '        patterns:\n          - "github/codeql-action*"\n',
                '        patternz:\n          - "github/codeql-action*"\n        bogus-key: 12345\n',
                1,
            )
            target.write_text(corrupted, encoding="utf-8")
            status, out, err = self.invoke([str(target)])
            self.assertEqual(status, 2)
            self.assertEqual(out, "")
            self.assertEqual(
                err,
                f"DENY: {target}: line 12: unknown key 'bogus-key' in groups.codeql-action\n",
            )

            target.write_text(pristine, encoding="utf-8")
            status, out, err = self.invoke([str(target)])
            self.assertEqual(status, 0)
            self.assertEqual(err, "")
            self.assertIn("3 update entries, 2 groups", out)


if __name__ == "__main__":
    unittest.main()
