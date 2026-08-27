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
import tomllib
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import commit_identity as CI  # noqa: E402

OWNER = CI.SANCTIONED_EMAIL
FOREIGN = "someone-else@example.invalid"
TRAILER_LINE = "Co-authored-by" + ": Someone <someone@example.invalid>"

#: The tracked allowlist exactly as it sits on disk at import time, captured
#: before any test can run. One test below rewrites that REAL file and restores
#: it in `finally`; a restore that silently stopped working would corrupt it —
#: deleting the five recorded historical exceptions — while this suite stayed
#: green, because a test reading its own "before" reads it AFTER an earlier
#: test has already done the damage, and the damage is a fixed point under a
#: second application. `tearDown` compares against these bytes instead.
ALLOWLIST_BASELINE = CI.ALLOWLIST_PATH.read_bytes()


def commit(
    sha: str = "0" * 40,
    author: str = OWNER,
    committer: str = OWNER,
    subject: str = "docs: a subject",
    body: str = "",
) -> CI.Commit:
    message = subject if not body else f"{subject}\n\n{body}"
    return CI.Commit(sha, author, committer, subject, message)


def entry_under_own_header(document: str, table: str, line: str) -> str:
    """Insert `line` directly beneath `table`'s OWN header.

    Never appended to the end of the document. This allowlist holds several
    tables, and a key appended to the end joins whichever table happens to be
    LAST — which today is this gate's own `[commit_identity]`. That is exactly
    why the mistake is invisible from this file, and why the pin that guards
    this helper drives it against a document whose target table is NOT last.
    """
    header = f"[{table}]\n"
    if header not in document:
        raise AssertionError(f"the table {table!r} is missing from the document")
    return document.replace(header, header + line, 1)


def _parents(revision: str) -> tuple[str, ...]:
    """The parent SHAs of `revision`, in order, straight from git."""
    return tuple(CI._git("rev-list", "--parents", "-n", "1", revision).split()[1:])


def proposed_head(revision: str = "HEAD") -> str:
    """The commit this checkout PROPOSES, which is not always `HEAD`.

    Under a `pull_request` event `actions/checkout` checks out
    `refs/pull/N/merge` — GitHub's synthetic merge of the branch into its base.
    `HEAD` is therefore that merge commit: its committer is GitHub's own
    web-flow identity, and its SECOND parent is the commit the pull request
    actually proposes. A suite that audited `HEAD` there would be auditing
    GitHub's construct rather than the agent's work, and this gate refuses that
    identity — correctly — so the assertions below went red in CI while passing
    on every developer machine, where `HEAD` really is the branch tip. The
    workflow's own gate step never had the defect: it passes the exact base and
    head SHAs from the event payload and resolves no symbolic name at all.

    Resolution is STRUCTURAL, not environmental. Two parents means a merge and
    the second parent is the side being offered, on GitHub and on a laptop
    alike; no `GITHUB_*` variable is read, so one code path runs in both places
    and there is no branch that only ever executes in CI. Exactly two parents,
    never "two or more": GitHub's merge ref always has two, so a three-parent
    HEAD is not one, has no single proposed side, and resolves to `HEAD` so the
    gate judges it on its own identity rather than silently auditing one
    arbitrary branch of three.

    Two alternatives were considered and rejected:

      * Teaching `violations()` to ADMIT a two-parent commit carrying GitHub's
        committer. That punches a hole in the one rule this module exists to
        enforce — any commit with that identity would pass — and
        `test_githubs_own_merge_identity_is_not_sanctioned_either` states the
        opposite as a deliberate decision. The web-flow identity is out of
        SCOPE here; it is never sanctioned.
      * Allowlisting the merge commit by SHA. GitHub rebuilds that ref on every
        push, so the entry would be stale before the next commit landed.

    Tests elsewhere in this suite still name `HEAD` literally, deliberately:
    an unreadable-range error path, git's collapsing of a repeated revision,
    and an existence probe all hold for ANY revision and gain nothing from
    resolution. Only an assertion that reads a commit's identity or defines
    the audited range needs this helper.
    """
    parents = _parents(revision)
    return parents[1] if len(parents) == 2 else revision


class TheProposedHeadIsResolvedStructurally(unittest.TestCase):
    """The helper that keeps this suite pointed at the right commit in CI.

    The repository can only ever be in ONE of the shapes below, so each is
    driven through a hand-written `_git` (testing doctrine: stdlib only,
    hand-written fakes, no mock framework). The last test covers what those
    fakes structurally cannot: that the real git invocation is the right one.
    """

    HEAD_SHA = "a" * 40
    BASE_SHA = "b" * 40
    PROPOSED = "c" * 40
    THIRD = "d" * 40

    def resolve(self, rev_list_line: str) -> str:
        original = CI._git
        try:
            CI._git = lambda *args: rev_list_line
            return proposed_head()
        finally:
            CI._git = original

    def test_a_two_parent_head_resolves_to_the_side_being_proposed(self) -> None:
        """CI's shape: `refs/pull/N/merge`, base first, proposed second."""
        self.assertEqual(
            self.resolve(f"{self.HEAD_SHA} {self.BASE_SHA} {self.PROPOSED}\n"),
            self.PROPOSED,
        )

    def test_a_plain_checkout_resolves_to_the_revision_itself(self) -> None:
        """Every developer machine, and every push to `main`."""
        self.assertEqual(self.resolve(f"{self.HEAD_SHA} {self.BASE_SHA}\n"), "HEAD")

    def test_a_root_commit_resolves_to_itself(self) -> None:
        """A parentless HEAD must not index off the end of the parent list."""
        self.assertEqual(self.resolve(f"{self.HEAD_SHA}\n"), "HEAD")

    def test_an_octopus_merge_is_not_treated_as_a_pull_request_merge(self) -> None:
        """Fail closed: GitHub's merge ref has EXACTLY two parents.

        A three-parent HEAD has no single proposed side. Resolving to `HEAD`
        leaves the gate judging that commit on its own identity, which is the
        conservative answer; picking one branch of three would audit an
        arbitrary subset and call it the proposal.
        """
        self.assertEqual(
            self.resolve(
                f"{self.HEAD_SHA} {self.BASE_SHA} {self.PROPOSED} {self.THIRD}\n"
            ),
            "HEAD",
        )

    def test_the_parent_reader_agrees_with_git_on_this_checkout(self) -> None:
        """The fakes above cannot see a WRONG `rev-list` invocation.

        They feed `_parents` a line this suite wrote itself, so a mutation of
        the git arguments would survive all four. This runs the real command
        against the real checkout and compares it against the parent list git
        reports through an entirely different formatter.
        """
        expected = tuple(CI._git("log", "-1", "--format=%P", "HEAD").split())
        self.assertEqual(_parents("HEAD"), expected)


class TheRepositoryRangeIsGreen(unittest.TestCase):
    def test_this_branch_is_clean_against_its_own_base(self) -> None:
        """The commits this pull request proposes must pass on their own.

        Resolved from git rather than hard-coded: the branch point is
        whatever `main` and this head actually share, so the assertion keeps
        meaning as the branch grows. Both ends go through `proposed_head`,
        because under a `pull_request` event `HEAD` is GitHub's synthetic merge
        commit rather than this branch's tip — see that helper for why.
        """
        head = proposed_head()
        base = CI._git("merge-base", head, "origin/main").strip()
        findings = CI.audit(base, head)
        self.assertEqual(findings, [], "\n\n".join(findings))

    def test_the_range_reader_actually_returns_commits(self) -> None:
        """An empty range would make the assertion above vacuous."""
        head = proposed_head()
        base = CI._git("merge-base", head, "origin/main").strip()
        shas = CI.commits_in_range(base, head)
        self.assertTrue(shas, "the range under test contains no commits")
        for sha in shas:
            self.assertRegex(sha, r"^[0-9a-f]{40}$")

    def test_reading_a_real_commit_recovers_its_fields(self) -> None:
        head = CI.read_commits([proposed_head()])[0]
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
    def tearDown(self) -> None:
        """The tracked allowlist must survive every test in this class.

        One test below rewrites the REAL file and puts it back in `finally`.
        Comparing against `ALLOWLIST_BASELINE` — captured at import, before any
        test ran — rather than against a "before" read inside the test is what
        makes this catch a broken restore: a per-test snapshot is taken after
        any earlier damage has already landed, and rewriting an
        already-damaged file reproduces it exactly, so the check passes on a
        corrupted tree.
        """
        self.assertEqual(
            CI.ALLOWLIST_PATH.read_bytes(),
            ALLOWLIST_BASELINE,
            "a test in this class left the tracked allowlist modified on disk",
        )

    def test_the_blank_reason_fixture_lands_under_its_own_header(self) -> None:
        """`entry_under_own_header` must not degrade into an append.

        The fixture below inserts a blank-reason key to prove `load_allowlist`
        fails closed. Appending it to the end of the file instead would put it
        in whichever table is LAST — which in the shipped allowlist is this
        gate's own `[commit_identity]`, so an append passes that test for
        entirely the wrong reason and the two spellings are indistinguishable
        from inside this file. This drives the helper against a document where
        the target table is NOT last, which is the only arrangement that tells
        them apart.
        """
        document = '[first]\n"aaa" = "x"\n\n[second]\n"bbb" = "y"\n'
        parsed = tomllib.loads(entry_under_own_header(document, "first", '"ccc" = ""\n'))
        self.assertIn("ccc", parsed["first"], "the entry missed its own table")
        self.assertNotIn("ccc", parsed["second"], "an appended entry joins the LAST table")

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
        try:
            # Inserted under its OWN header rather than appended: the allowlist
            # holds several tables and an appended key joins whichever is last.
            # The helper is pinned by the placement test above; the restore is
            # pinned by this class's `tearDown`.
            CI.ALLOWLIST_PATH.write_text(
                entry_under_own_header(
                    original, CI.ALLOWLIST_TABLE, f'"{"f" * 40}" = ""\n'
                ),
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
        head = CI.read_commits([proposed_head()])[0]
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
        head = proposed_head()
        base = CI._git("merge-base", head, "origin/main").strip()
        self.assertEqual(CI.main(["--base", base, "--head", head]), 0)

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
