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
  * the one-line lift works end to end;
  * the gate step is WIRED and is guarded to `pull_request` events — a
    behavioural pin, not a step inventory, because that guard is what keeps
    main CI green and nothing else pinned it (see `GUARD_RATIONALE`).
"""

from __future__ import annotations

import json
import os
import re
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import commit_identity as CI  # noqa: E402

OWNER = CI.SANCTIONED_EMAIL
FOREIGN = "someone-else@example.invalid"
TRAILER_LINE = "Co-authored-by" + ": Someone <someone@example.invalid>"
HEAD_PLACEHOLDER = "c" * 40

#: The tracked allowlist exactly as it sits on disk at import time, captured
#: before any test can run. One test below rewrites that REAL file and restores
#: it in `finally`; a restore that silently stopped working would corrupt it —
#: deleting the five recorded historical exceptions — while this suite stayed
#: green, because a test reading its own "before" reads it AFTER an earlier
#: test has already done the damage, and the damage is a fixed point under a
#: second application. `tearDown` compares against these bytes instead.
ALLOWLIST_BASELINE = CI.ALLOWLIST_PATH.read_bytes()

#: The string that identifies the ONE `pr-gate.yml` step this module is the
#: gate for. The workflow pin below selects that step by what it RUNS, never by
#: its name or its position, so steps may be added, renamed or reordered.
GATE_INVOCATION = "scripts/ci/commit_identity.py"

#: A workflow step begins at a `- name:` list item, at whatever indentation the
#: file happens to use. Matching the ITEM rather than a fixed column keeps the
#: reader working across a legitimate reformat.
STEP_START = re.compile(r"(?m)^[ \t]*-[ \t]+name:")

#: The guard, matched as BEHAVIOUR rather than as literal text: the bare and
#: the `${{ … }}` spellings both pass, quoting and internal whitespace are
#: free, and the condition may carry further terms. `pull_request_target` does
#: NOT pass — the closing quote is part of the pattern.
PULL_REQUEST_GUARD = re.compile(r"""github\.event_name\s*==\s*['"]pull_request['"]""")

#: Printed by every failure of the pin below. A pin whose message only says
#: "this changed" teaches an agent to re-record it; this one says what breaks.
GUARD_RATIONALE = """WHY THIS GUARD EXISTS, AND WHY IT IS PINNED

The `pr-gate.yml` step that runs scripts/ci/commit_identity.py must be guarded
`if: github.event_name == 'pull_request'`. That guard is not a scope
preference. It is what keeps MAIN CI GREEN, because pr-gate.yml runs on pushes
to `main` as well as on pull requests, and the gate has no safe reading there:

  * with the guard removed, a main push supplies no `github.event.pull_request`
    payload, so PR_BASE_SHA and PR_HEAD_SHA expand EMPTY and the module exits 1
    on a range it cannot read;
  * hand it a real push range instead and it still exits 1, because the owner's
    merge commit is stamped with GitHub's own web-flow committer, which is
    deliberately NOT a sanctioned identity — see
    `test_githubs_own_merge_identity_is_not_sanctioned_either`, which is
    correct and must not be relaxed to make a push pass.

Both directions were measured at 0.1.37. Either way main CI goes red over a
commit no pull request can repair, and the release chain behind it stalls. The
failure would appear on the merge, not on the pull request that caused it.

This pins BEHAVIOUR, not inventory. It selects the step by the module it
invokes, so steps may be added, renamed, reordered or removed freely, and both
condition spellings pass. There is deliberately NO allowlist line for it: the
lift mechanism exists so a gate can stop refusing a construct that turned out
to be safe, and an entry that switches this guard off is not that — it is the
hole this test refuses. The real lift is to make the gate SAFE on the other
event first (give the range a push-shaped source, and decide what the merge
identity means there), then widen this pattern in the same pull request."""


def pr_gate_steps() -> list[str]:
    """`pr-gate.yml` split into step blocks, one per `- name:` item.

    Deliberately not a step inventory — the caller picks the single block that
    invokes the module under test and ignores every other one.
    """
    text = (CI.REPO_ROOT / ".github" / "workflows" / "pr-gate.yml").read_text(
        encoding="utf-8"
    )
    starts = [match.start() for match in STEP_START.finditer(text)]
    return [text[a:b] for a, b in zip(starts, starts[1:] + [len(text)])]


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


def proposed_range() -> tuple[str, str] | None:
    """The exact `(base, head)` this run is asked to judge, or `None`.

    TAKEN FROM THE EVENT PAYLOAD, NEVER DERIVED FROM `HEAD`
    ======================================================

    Under a `pull_request` event `actions/checkout` checks out
    `refs/pull/N/merge` — GitHub's synthetic merge of the branch into its base,
    whose committer is GitHub's own web-flow identity. Assertions here used to
    resolve `HEAD`, so in CI they read that merge commit rather than the branch
    tip and this gate refused it, correctly, while every local run stayed green
    because locally `HEAD` really IS the tip.

    The fix is not to teach the suite how to walk back from a merge ref. It is
    to stop asking `HEAD` at all. `pull_request.base.sha` and
    `pull_request.head.sha` are the SAME two values the workflow's gate step
    passes to `commit_identity.py`, read from the same payload, so the suite and
    the gate judge one identical range and neither depends on what the checkout
    happens to have put at `HEAD`. Nothing here regresses if the checkout's
    depth or ref changes later.

    FAIL CLOSED, WITH NO FALL-BACK TO `HEAD`
    ========================================

    Under a pull request the payload is the only honest source, so an
    unreadable or incomplete one RAISES. A fall-back to `HEAD` is precisely the
    defect this function exists to remove: it would restore the silent, green,
    wrong behaviour on the one event where `HEAD` is not the branch tip. The
    module's own CLI takes the same position — `--base` and `--head` are
    `required=True` with no default, so the range can never be reached by
    omission.

    WHY A PUSH TO `main` RETURNS `None` RATHER THAN A RANGE
    ======================================================

    On a push to `main` the range is the owner's merge, and its committer is
    GitHub's web-flow identity. `commit_identity.py` documents that as OUT OF
    SCOPE, and the workflow's gate step is guarded
    `if: github.event_name == 'pull_request'` for exactly that reason — every
    commit was already judged at the pull-request head, where an agent could
    still fix it.

    The suite's step carries NO such guard, so it does run on main pushes, and
    that is a real defect this returns `None` to close: an assertion reading
    `HEAD` there would read the owner's squash merge, refuse it, and hold main
    CI permanently red — blocking the release chain over a commit no pull
    request can repair. A stated skip honours the same boundary the gate step
    draws instead of auditing a range the gate itself declines to audit.

    With no `GITHUB_EVENT_NAME` at all this is a developer checkout, where
    `HEAD` genuinely is the branch tip and the branch point against
    `origin/main` is the useful pre-push range.
    """
    event_name = os.environ.get("GITHUB_EVENT_NAME", "")
    if not event_name:
        head = CI._git("rev-parse", "HEAD").strip()
        return CI._git("merge-base", head, "origin/main").strip(), head
    if event_name != "pull_request":
        return None
    event_path = os.environ.get("GITHUB_EVENT_PATH", "")
    if not event_path or not Path(event_path).is_file():
        raise CI.CommitIdentityError(
            "GITHUB_EVENT_NAME is 'pull_request' but the event payload is "
            f"unreadable ({event_path!r}); refusing to fall back to HEAD, "
            "which under this event is GitHub's synthetic merge commit"
        )
    payload = json.loads(Path(event_path).read_text(encoding="utf-8"))
    pull = payload.get("pull_request") or {}
    base = (pull.get("base") or {}).get("sha")
    head = (pull.get("head") or {}).get("sha")
    if not base or not head:
        raise CI.CommitIdentityError(
            "the pull_request payload carries no base.sha/head.sha pair; "
            "refusing to guess the range this pull request proposes"
        )
    return base, head


def require_range(case: unittest.TestCase) -> tuple[str, str]:
    """The pull-request range, or skip the calling test with a stated reason."""
    found = proposed_range()
    if found is None:
        case.skipTest(
            "this event proposes no pull-request range (see proposed_range): "
            "the owner's merge is out of scope for the identity rule, and "
            "refusing it here would hold main CI red"
        )
    return found


class TheAuditedRangeComesFromTheEventPayload(unittest.TestCase):
    """The resolver, driven through every shape the environment can take.

    The environment is saved and restored by hand rather than through a mock
    framework (testing doctrine: stdlib only, hand-written fakes).
    """

    BASE = "b" * 40
    HEAD = "c" * 40

    def resolve(self, environment: dict[str, str], git=None):
        saved = {
            key: os.environ.get(key)
            for key in ("GITHUB_EVENT_NAME", "GITHUB_EVENT_PATH")
        }
        original_git = CI._git
        try:
            for key, value in saved.items():
                os.environ.pop(key, None)
            os.environ.update(environment)
            if git is not None:
                CI._git = git
            return proposed_range()
        finally:
            CI._git = original_git
            for key, value in saved.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value

    def payload_file(self, payload: str) -> str:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / "event.json"
        path.write_text(payload, encoding="utf-8")
        return str(path)

    def test_a_pull_request_run_takes_both_shas_from_the_payload(self) -> None:
        """And touches git for the range not at all.

        The `git` fake raises, so any surviving `HEAD` resolution on this path
        is an error rather than a passing test — which is the whole point:
        under this event `HEAD` is GitHub's synthetic merge commit.
        """

        def refuse(*args):
            raise AssertionError(f"the payload path must not consult git: {args}")

        path = self.payload_file(
            '{"pull_request": {"base": {"sha": "%s"}, "head": {"sha": "%s"}}}'
            % (self.BASE, self.HEAD)
        )
        found = self.resolve(
            {"GITHUB_EVENT_NAME": "pull_request", "GITHUB_EVENT_PATH": path},
            git=refuse,
        )
        self.assertEqual(found, (self.BASE, self.HEAD))

    def test_an_unreadable_payload_fails_closed_rather_than_using_head(self) -> None:
        """The exact regression this function exists to prevent."""
        for path in ("", "/nonexistent/event.json"):
            with self.subTest(path=path):
                with self.assertRaises(CI.CommitIdentityError) as caught:
                    self.resolve(
                        {"GITHUB_EVENT_NAME": "pull_request", "GITHUB_EVENT_PATH": path}
                    )
                self.assertIn("refusing to fall back to HEAD", str(caught.exception))

    def test_a_payload_missing_either_sha_fails_closed(self) -> None:
        for payload in (
            '{"pull_request": {"head": {"sha": "%s"}}}' % HEAD_PLACEHOLDER,
            '{"pull_request": {"base": {"sha": "%s"}}}' % HEAD_PLACEHOLDER,
            '{"pull_request": {}}',
            "{}",
        ):
            with self.subTest(payload=payload):
                path = self.payload_file(payload)
                with self.assertRaises(CI.CommitIdentityError) as caught:
                    self.resolve(
                        {"GITHUB_EVENT_NAME": "pull_request", "GITHUB_EVENT_PATH": path}
                    )
                self.assertIn("refusing to guess", str(caught.exception))

    def test_a_push_to_main_proposes_no_range(self) -> None:
        """The owner's merge is out of scope, and refusing it would hold main red."""
        path = self.payload_file('{"before": "%s", "after": "%s"}' % (self.BASE, self.HEAD))
        self.assertIsNone(
            self.resolve({"GITHUB_EVENT_NAME": "push", "GITHUB_EVENT_PATH": path})
        )

    def test_a_developer_checkout_uses_the_local_branch_point(self) -> None:
        """No event at all: `HEAD` really is the tip, and the range is useful."""
        found = self.resolve({})
        self.assertIsNotNone(found)
        base, head = found
        self.assertEqual(head, CI._git("rev-parse", "HEAD").strip())
        self.assertEqual(base, CI._git("merge-base", head, "origin/main").strip())


class TheRepositoryRangeIsGreen(unittest.TestCase):
    def test_this_branch_is_clean_against_its_own_base(self) -> None:
        """The commits this pull request proposes must pass on their own.

        The range comes from `proposed_range` — the event payload in CI, the
        local branch point on a developer machine — never from `HEAD`, which
        under a `pull_request` event is GitHub's synthetic merge commit.
        """
        base, head = require_range(self)
        _, findings = CI.audit(base, head)
        self.assertEqual(findings, [], "\n\n".join(findings))

    def test_the_range_reader_actually_returns_commits(self) -> None:
        """An empty range would make the assertion above vacuous."""
        base, head = require_range(self)
        shas = CI.commits_in_range(base, head)
        self.assertTrue(shas, "the range under test contains no commits")
        for sha in shas:
            self.assertRegex(sha, r"^[0-9a-f]{40}$")

    def test_reading_a_real_commit_recovers_its_fields(self) -> None:
        head = CI.read_commits([require_range(self)[1]])[0]
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
        head = CI.read_commits([require_range(self)[1]])[0]
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
        base, head = require_range(self)
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


class TheGateStepRunsOnPullRequestEventsOnly(unittest.TestCase):
    """The `if:` that keeps main CI green, which nothing pinned until 0.1.37.

    `pr-gate.yml` runs on pushes to `main` as well as on pull requests, and
    the step that invokes `scripts/ci/commit_identity.py` carries
    `if: github.event_name == 'pull_request'`. That guard is not a preference
    about scope; it is load-bearing for main CI, and a future edit could delete
    it and only discover the consequence when the owner's next merge turns main
    red. `test_a_push_to_main_proposes_no_range` pins the SUITE half of the
    same boundary. This pins the WORKFLOW half.

    The rationale is in `GUARD_RATIONALE` below, which is also the failure
    message, so an agent that trips this is told why the guard exists rather
    than being invited to re-record a pin.
    """

    def gate_step(self) -> str:
        steps = [s for s in pr_gate_steps() if GATE_INVOCATION in s]
        self.assertEqual(
            len(steps),
            1,
            f"expected exactly one pr-gate step to invoke {GATE_INVOCATION}, "
            f"found {len(steps)}. This pin selects the step BY THE MODULE IT "
            f"RUNS rather than by position or name; if the invocation legitimately "
            f"moved or was duplicated, update the selection here in the same pull "
            f"request.\n\n{GUARD_RATIONALE}",
        )
        return steps[0]

    def test_the_gate_step_carries_the_pull_request_guard(self) -> None:
        condition = re.search(r"(?m)^[ \t]*if:[ \t]*(?P<cond>.+?)[ \t]*$", self.gate_step())
        self.assertIsNotNone(
            condition, f"that step declares no `if:` at all.\n\n{GUARD_RATIONALE}"
        )
        self.assertRegex(
            condition.group("cond"),
            PULL_REQUEST_GUARD,
            f"that step's condition is {condition.group('cond')!r}.\n\n"
            f"{GUARD_RATIONALE}",
        )

    def test_the_guard_pattern_refuses_every_other_condition(self) -> None:
        """A pattern that matched any `if:` would pin nothing at all.

        The positive spellings are both real: a bare expression and the
        `${{ … }}` form are equivalent in an `if:`, so pinning one literal
        spelling would break on a legitimate reformat.
        """
        for accepted in (
            "github.event_name == 'pull_request'",
            "${{ github.event_name == 'pull_request' }}",
            'github.event_name  ==  "pull_request"',
            "github.event_name == 'pull_request' && github.actor != 'nobody'",
        ):
            with self.subTest(accepted=accepted):
                self.assertRegex(accepted, PULL_REQUEST_GUARD)
        for refused in (
            "github.event_name != 'workflow_dispatch'",
            "github.event_name == 'push'",
            "${{ github.event_name == 'push' }}",
            "github.event_name == 'pull_request_target'",
            "always()",
            "",
        ):
            with self.subTest(refused=refused):
                self.assertNotRegex(refused, PULL_REQUEST_GUARD)

    def test_the_step_reader_really_splits_steps(self) -> None:
        """A reader returning the whole file as one blob makes the pin vacuous.

        It would find the invocation in the "blob" and then find the guard
        somewhere else entirely — another step's `if:`, or a comment — so the
        assertion above would pass with the guard deleted. A lower bound rather
        than a count: steps are added freely, and no inventory is pinned here.
        """
        steps = pr_gate_steps()
        self.assertGreater(len(steps), 1)
        self.assertTrue(all(STEP_START.match(step) for step in steps))
        self.assertEqual(
            sum(GATE_INVOCATION in step for step in steps),
            1,
            "the invocation must land in exactly one block, or the selection "
            "above is reading more than the step it means to read",
        )


if __name__ == "__main__":  # pragma: no cover - manual invocation
    unittest.main()
