"""Hostile suite for the commit-identity and co-author-trailer rules.

READ THIS BEFORE ADDING A TEST HERE
===================================

This suite pins TWO named refusals and the allowlist that lifts them. It does
NOT pin a commit inventory — no assertion here says "history contains exactly
these commits" — and one must never be added. History is append-only in this
repository, so an inventory pin would break on the next merge, every merge,
forever, and the cheapest way past it would be to re-record it.

What it does pin, and why each is load-bearing:

  * the two refusals fire, driven by synthetic commits the repository does not
    contain (a range that is green today satisfies a rule that refuses nothing
    just as well as a rule that works);
  * the shipped allowlist's seeded entries are exactly the commits that really
    do violate, checked against the REAL objects in this repository, so the
    exemptions describe reality instead of being decoration;
  * the one-line lift works end to end.
"""

from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import commit_identity as CI  # noqa: E402

OWNER = CI.SANCTIONED_EMAIL
FOREIGN = "someone-else@example.invalid"
TRAILER_LINE = "Co-authored-by" + ": Someone <someone@example.invalid>"


def commit(
    sha: str = "0" * 40,
    author: str = OWNER,
    committer: str = OWNER,
    subject: str = "docs: a subject",
    body: str = "",
) -> CI.Commit:
    message = subject if not body else f"{subject}\n\n{body}"
    return CI.Commit(sha, author, committer, subject, message)


class TheRepositoryRangeIsGreen(unittest.TestCase):
    def test_this_branch_is_clean_against_its_own_base(self) -> None:
        """The commits this pull request proposes must pass on their own.

        Resolved from git rather than hard-coded: the branch point is
        whatever `main` and this head actually share, so the assertion keeps
        meaning as the branch grows.
        """
        base = CI._git("merge-base", "HEAD", "origin/main").strip()
        findings = CI.audit(base, "HEAD")
        self.assertEqual(findings, [], "\n\n".join(findings))

    def test_the_range_reader_actually_returns_commits(self) -> None:
        """An empty range would make the assertion above vacuous."""
        base = CI._git("merge-base", "HEAD", "origin/main").strip()
        shas = CI.commits_in_range(base, "HEAD")
        self.assertTrue(shas, "the range under test contains no commits")
        for sha in shas:
            self.assertRegex(sha, r"^[0-9a-f]{40}$")

    def test_reading_a_real_commit_recovers_its_fields(self) -> None:
        head = CI.read_commits(["HEAD"])[0]
        self.assertRegex(head.sha, r"^[0-9a-f]{40}$")
        self.assertEqual(head.author_email, OWNER)
        self.assertEqual(head.committer_email, OWNER)
        self.assertTrue(head.subject.strip())
        self.assertIn(head.subject, head.message)


class AForeignIdentityIsRefused(unittest.TestCase):
    def test_a_foreign_author_is_a_finding(self) -> None:
        findings = CI.check_commits([commit(author=FOREIGN)], {})
        self.assertEqual(len(findings), 1, findings)
        self.assertIn("AUTHOR email", findings[0])

    def test_a_foreign_committer_is_a_finding(self) -> None:
        findings = CI.check_commits([commit(committer=FOREIGN)], {})
        self.assertEqual(len(findings), 1, findings)
        self.assertIn("COMMITTER email", findings[0])

    def test_both_fields_are_reported_separately(self) -> None:
        findings = CI.check_commits([commit(author=FOREIGN, committer=FOREIGN)], {})
        self.assertEqual(len(findings), 1, findings)
        self.assertIn("AUTHOR email", findings[0])
        self.assertIn("COMMITTER email", findings[0])

    def test_githubs_own_merge_identity_is_not_sanctioned_either(self) -> None:
        """The web-flow identity is out of SCOPE on main, never sanctioned.

        The module skips main pushes rather than treating GitHub's committer as
        acceptable. If the rule is ever pointed at such a range it must still
        refuse, so the exemption stays a scope decision written in one place
        instead of a hole in the identity check.
        """
        findings = CI.check_commits([commit(committer="noreply@github.com")], {})
        self.assertEqual(len(findings), 1, findings)

    def test_a_near_miss_address_is_refused(self) -> None:
        """The comparison is exact — no prefix, suffix, or substring match."""
        for near in (
            "snaraj@users.noreply.github.com",
            "39077795+snaraj@users.noreply.github.com.example.invalid",
            " 39077795+snaraj@users.noreply.github.com",
            OWNER.upper(),
        ):
            with self.subTest(address=near):
                self.assertEqual(len(CI.check_commits([commit(author=near)], {})), 1)

    def test_the_sanctioned_identity_passes(self) -> None:
        self.assertEqual(CI.check_commits([commit()], {}), [])

    def test_no_message_echoes_the_offending_address(self) -> None:
        """These strings reach public CI logs (requirement 11).

        A gate that printed the address it just refused would publish it a
        second time, in a place the owner cannot redact.
        """
        findings = CI.check_commits(
            [commit(author=FOREIGN, committer=FOREIGN, body=TRAILER_LINE)], {}
        )
        self.assertEqual(len(findings), 1, findings)
        self.assertNotIn(FOREIGN, findings[0])
        self.assertNotIn("someone@example.invalid", findings[0])


class ACoAuthorTrailerIsRefused(unittest.TestCase):
    def test_a_trailer_in_the_body_is_a_finding(self) -> None:
        findings = CI.check_commits([commit(body=TRAILER_LINE)], {})
        self.assertEqual(len(findings), 1, findings)
        self.assertIn("co-author trailer", findings[0])

    def test_the_count_is_reported(self) -> None:
        findings = CI.check_commits(
            [commit(body=f"{TRAILER_LINE}\nsomething\n{TRAILER_LINE}")], {}
        )
        self.assertIn("2 co-author trailers", findings[0])

    def test_case_and_spacing_cannot_hide_it(self) -> None:
        for variant in (
            "co-authored-by: A <a@example.invalid>",
            "CO-AUTHORED-BY: A <a@example.invalid>",
            "Co-Authored-By : A <a@example.invalid>",
            "  Co-authored-by: A <a@example.invalid>",
            "\tCo-authored-by: A <a@example.invalid>",
        ):
            with self.subTest(variant=variant):
                self.assertEqual(len(CI.check_commits([commit(body=variant)], {})), 1)

    def test_prose_mentioning_the_trailer_is_not_a_finding(self) -> None:
        """The rule is about a TRAILER, not about the words appearing.

        A commit body explaining the rule — this one does — must not trip it.
        """
        body = "The contract forbids a co-authored-by: trailer, so none is used."
        self.assertEqual(CI.check_commits([commit(body=body)], {}), [])

    def test_a_clean_body_is_not_a_finding(self) -> None:
        self.assertEqual(CI.check_commits([commit(body="A normal body.\n\n- Opus5")], {}), [])


class TheSeededHistoricalEntriesDescribeReality(unittest.TestCase):
    """The allowlist's seeds are checked against the REAL commit objects.

    This is what keeps them from becoming decoration. Every seeded SHA must
    exist here and must actually violate a rule; a seed for a clean commit is
    an exemption that exempts nothing, and the suite says so.
    """

    def setUp(self) -> None:
        self.allowlist = CI.load_allowlist()

    def test_the_seed_is_not_empty(self) -> None:
        """These commits are real and permanently public; a green seed here
        would mean the rule had simply not been pointed at them."""
        self.assertTrue(
            self.allowlist,
            "the historical exceptions are unrecorded; the gate would refuse "
            "any range that reached them with no explanation",
        )

    def test_every_key_is_a_full_lowercase_sha(self) -> None:
        for sha in self.allowlist:
            with self.subTest(sha=sha):
                self.assertRegex(sha, r"^[0-9a-f]{40}$")

    def test_every_seeded_commit_exists_in_this_repository(self) -> None:
        for sha in self.allowlist:
            with self.subTest(sha=sha):
                self.assertTrue(
                    CI.commit_exists(sha),
                    f"{sha} is not a commit here; delete the line",
                )

    def test_every_seeded_commit_really_does_violate_a_rule(self) -> None:
        for sha in self.allowlist:
            with self.subTest(sha=sha):
                found = CI.violations(CI.read_commits([sha])[0])
                self.assertTrue(
                    found,
                    f"{sha} breaks no rule, so its entry exempts nothing. "
                    "Delete the line.",
                )

    def test_no_reason_repeats_an_address(self) -> None:
        """Requirement 11, enforced rather than trusted.

        The whole point of keying by SHA is that the exception is recorded
        without copying anybody's contact detail into a tracked file. A reason
        containing an address would undo that in the same file.
        """
        for sha, reason in self.allowlist.items():
            with self.subTest(sha=sha):
                self.assertNotIn("@", reason, "name the commit by SHA, not by address")

    def test_the_seeded_commits_are_refused_without_the_allowlist(self) -> None:
        """The seeds are load-bearing, not habit: remove them and it goes red."""
        commits = CI.read_commits(sorted(self.allowlist))
        self.assertEqual(len(CI.check_commits(commits, {})), len(self.allowlist))

    def test_the_seeded_commits_pass_with_the_shipped_allowlist(self) -> None:
        commits = CI.read_commits(sorted(self.allowlist))
        self.assertEqual(CI.check_commits(commits, self.allowlist), [])


class TheLiftMechanismWorks(unittest.TestCase):
    def test_every_refusal_prints_the_exact_line_to_add(self) -> None:
        for offender in (
            commit(sha="a" * 40, author=FOREIGN),
            commit(sha="b" * 40, body=TRAILER_LINE),
        ):
            with self.subTest(sha=offender.sha):
                findings = CI.check_commits([offender], {})
                self.assertEqual(len(findings), 1)
                message = findings[0]
                self.assertIn("LIFT:", message)
                self.assertIn("scripts/ci/ci_gate_allowlist.toml", message)
                self.assertIn(f"[{CI.ALLOWLIST_TABLE}]", message)
                self.assertIn(f'"{offender.sha}" = ', message)

    def test_every_refusal_says_to_fix_an_unpushed_commit_instead(self) -> None:
        """Lifting is the last resort here, not the first.

        For the other gates in this directory an allowlist entry is an ordinary
        outcome. For this one, a commit that has not been pushed can simply be
        made again correctly, and an address that reaches published history
        cannot be withdrawn — so the message says so.
        """
        message = CI.check_commits([commit(author=FOREIGN)], {})[0]
        self.assertIn("FIX IT INSTEAD", message)

    def test_the_one_line_lift_actually_lifts(self) -> None:
        offender = commit(sha="c" * 40, author=FOREIGN, body=TRAILER_LINE)
        self.assertEqual(len(CI.check_commits([offender], {})), 1)
        self.assertEqual(CI.check_commits([offender], {offender.sha: "reviewed"}), [])

    def test_an_entry_for_another_commit_lifts_nothing(self) -> None:
        offender = commit(sha="d" * 40, author=FOREIGN)
        self.assertEqual(len(CI.check_commits([offender], {"e" * 40: "other"})), 1)

    def test_an_entry_without_a_reason_fails_closed(self) -> None:
        original = CI.ALLOWLIST_PATH.read_text(encoding="utf-8")
        header = f"[{CI.ALLOWLIST_TABLE}]\n"
        self.assertIn(header, original, "the table this rule reads is missing")
        try:
            # Inserted under its OWN header rather than appended: the allowlist
            # holds several tables and an appended key joins whichever is last.
            CI.ALLOWLIST_PATH.write_text(
                original.replace(header, header + f'"{"f" * 40}" = ""\n', 1),
                encoding="utf-8",
            )
            with self.assertRaises(CI.CommitIdentityError) as caught:
                CI.load_allowlist()
            self.assertIn("no written reason", str(caught.exception))
        finally:
            CI.ALLOWLIST_PATH.write_text(original, encoding="utf-8")


class TheReaderRefusesWhatItCannotRead(unittest.TestCase):
    def test_an_unknown_revision_is_refused_not_ignored(self) -> None:
        with self.assertRaises(CI.CommitIdentityError):
            CI.commits_in_range("HEAD", "no-such-revision-here")

    def test_a_message_containing_the_field_separator_is_still_read(self) -> None:
        """Real bodies hold arbitrary text; the separators must be exotic."""
        head = CI.read_commits(["HEAD"])[0]
        self.assertNotIn(CI._FIELD, head.subject)
        self.assertNotIn(CI._RECORD, head.subject)

    def test_reading_no_commits_returns_nothing_rather_than_failing(self) -> None:
        self.assertEqual(CI.read_commits([]), ())

    def test_a_record_with_a_stray_separator_is_refused_not_truncated(self) -> None:
        r"""A message holding a literal `\x1f` must not silently lose its tail.

        `read_commits` asks git for FIVE `\x1f`-separated fields. A commit
        message that itself contains that byte produces SIX, and the field
        guard is what stops the reader building a `Commit` from the first five:
        the message would stop at the stray byte, and a `Co-authored-by:`
        trailer written AFTER it would be dropped entirely — a fail-open on the
        one rule this module exists to enforce, reachable by a hostile or
        merely unlucky commit message. The two assertions before the guard is
        exercised are what make this a real vector rather than an arbitrary
        input: the truncated message the unguarded reader would have built
        breaks no rule, while the full message carries a trailer.

        `_git` is replaced with a plain function rather than a mock framework
        (testing doctrine: stdlib-only, hand-written fakes).
        """
        subject = "feat: something"
        message = f"{subject}\n\nbody text{CI._FIELD}\n{TRAILER_LINE}\n"
        truncated = message.split(CI._FIELD)[0]
        self.assertEqual(
            CI.violations(CI.Commit("a" * 40, OWNER, OWNER, subject, truncated)),
            [],
            "the truncated message must look clean, or the guard proves nothing",
        )
        self.assertTrue(
            CI.violations(CI.Commit("a" * 40, OWNER, OWNER, subject, message)),
            "the full message must really carry the trailer the guard preserves",
        )

        record = CI._FIELD.join(("a" * 40, OWNER, OWNER, subject, message)) + CI._RECORD
        original = CI._git
        try:
            CI._git = lambda *args: record
            with self.assertRaises(CI.CommitIdentityError) as caught:
                CI.read_commits(["a" * 40])
        finally:
            CI._git = original
        self.assertIn("6 fields", str(caught.exception))

    def test_a_short_record_set_is_refused_rather_than_silently_truncated(self) -> None:
        """Ask for two commits and get one back, and the reader must object.

        `git log --no-walk=unsorted` collapses a repeated revision, which is
        the readily available input that drives this guard — without it the
        guard would be decorative. Silently returning fewer commits than were
        asked for would mean a commit in the range went unchecked, which is
        the one failure mode this module must never have.
        """
        with self.assertRaises(CI.CommitIdentityError) as caught:
            CI.read_commits(["HEAD", "HEAD"])
        self.assertIn("read", str(caught.exception))

    def test_commit_exists_answers_no_for_an_absent_commit(self) -> None:
        """A probe that always says yes would let a stale seed live forever."""
        self.assertTrue(CI.commit_exists("HEAD"))
        self.assertFalse(CI.commit_exists("0" * 40))


class TheCommandLineReportsBothOutcomes(unittest.TestCase):
    def test_a_clean_range_exits_zero(self) -> None:
        base = CI._git("merge-base", "HEAD", "origin/main").strip()
        self.assertEqual(CI.main(["--base", base, "--head", "HEAD"]), 0)

    def test_an_unreadable_range_exits_one(self) -> None:
        self.assertEqual(
            CI.main(["--base", "HEAD", "--head", "no-such-revision-here"]), 1
        )

    def test_a_range_holding_a_refused_commit_exits_one(self) -> None:
        """The positive control for the exit code, on real history.

        Every other CLI assertion runs a GREEN range, which a `main` that
        always returned 0 would satisfy. The offender is DERIVED rather than
        hard-coded — the newest commit on `main` that breaks a rule and is not
        allowlisted — so this stays true as history grows and never becomes a
        pinned SHA somebody has to re-record.

        That such commits exist in abundance is the whole reason this gate is
        scoped to the pull-request range: `main`'s squash commits carry
        GitHub's own web-flow committer, so a history-wide run would refuse
        them by the dozen and hold main CI red forever.
        """
        allowlist = CI.load_allowlist()
        shas = CI._git("rev-list", "--max-count=200", "origin/main").split()
        offender = next(
            (
                c.sha
                for c in CI.read_commits(shas)
                if c.sha not in allowlist and CI.violations(c)
            ),
            None,
        )
        self.assertIsNotNone(
            offender,
            "no unallowlisted violating commit was found in the newest 200 on "
            "main, so this control proves nothing; replace it rather than "
            "deleting it",
        )
        self.assertEqual(CI.main(["--base", f"{offender}^", "--head", offender]), 1)

    def test_the_workflow_step_invokes_this_module(self) -> None:
        """The gate must be WIRED, not merely present.

        A checker no workflow runs is the same dead surface the caller gate
        next door exists to refuse.
        """
        gate = (REPO_ROOT := CI.REPO_ROOT) / ".github" / "workflows" / "pr-gate.yml"
        text = gate.read_text(encoding="utf-8")
        self.assertIn("scripts/ci/commit_identity.py", text)
        self.assertIn("test_commit_identity.py", text)
        self.assertTrue(re.search(r"--base\s", text))


if __name__ == "__main__":  # pragma: no cover - manual invocation
    unittest.main()
