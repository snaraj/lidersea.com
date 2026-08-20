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

    def test_rejects_empty_whitespace_and_comment_only_documents(self):
        for label, text in (
            ("empty", ""),
            ("whitespace only", "   \n\n  \n"),
            ("comment only", "# just a comment\n"),
        ):
            with self.subTest(label=label), self.assertRaises(DC.ContractError) as denied:
                DC.parse_yaml_subset(text)
            self.assertEqual(str(denied.exception), "line 1: file has no content")

    def test_full_line_comments_are_skipped_but_never_required(self):
        tree = DC.parse_yaml_subset("# top rationale\nversion: 2\nupdates:\n  - package-ecosystem: npm\n    directory: /\n    schedule:\n      interval: daily\n")
        self.assertEqual(set(tree.items), {"version", "updates"})

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

    def test_leading_comment_does_not_disturb_a_valid_document(self):
        text = "# groups exist to stop mutually-blocking version-locked PRs\n" + real_text()
        self.assertEqual(DC.check_text(text), (3, 2))


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
