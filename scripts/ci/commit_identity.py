"""Refuse a foreign commit identity or a co-author trailer in a commit range.

THE GAP THIS CLOSES
===================

This repository's enforced secret scan runs `gitleaks git` over full history
and `gitleaks dir` over the working tree. Both read BLOB CONTENT. Commit
METADATA — the author and committer identities — and commit MESSAGE BODIES are
not blobs, so neither scan has ever had one byte of coverage over them.

Two contract rules live exactly on that uncovered surface:

  * commits are authored AND committed as the owner's GitHub noreply identity,
    both fields (requirement 3);
  * no co-author trailer, ever (requirement 3, "Commit identity mechanics").

Until now both were prose. An agent that forgot to pin `GIT_AUTHOR_EMAIL`
would push a commit carrying whatever identity its environment supplied, every
gate would stay green, and the address would become permanently public the
moment the owner merged. This module makes both rules mechanical for the
commits a pull request actually proposes.

SCOPE: THE RANGE THE PULL REQUEST PROPOSES, NOT ALL HISTORY
===========================================================

The check walks `base..head` and nothing else. That is a deliberate scope, and
the two boundaries are worth stating plainly.

It is not a history audit. History is append-only here (requirement 2), so a
gate that re-examined every commit on every run could only ever refuse the
past — which no PR can fix — and would need a permanent, ever-growing
exemption list to stay green. That is the closed-inventory shape the gate
design doctrine rejects. The allowlist below therefore records the KNOWN
historical exceptions and nothing more; it does not grow with the repository.

It also does not run on pushes to `main`, and that is not an oversight. When
the owner merges, GitHub itself re-stamps the resulting commit's committer as
its own web-flow identity — the merge is GitHub's action, not an agent's, and
every commit in the range was already checked at the pull-request head where an
agent could still fix it. A gate that refused GitHub's own merge identity would
make main CI permanently red and block the release chain, so the honest
statement is: this rule binds what an agent PROPOSES. What the owner's merge
re-stamps afterwards is outside it.

THE LIFT MECHANISM
==================

One line in `scripts/ci/ci_gate_allowlist.toml` under `[commit_identity]`,
keyed by the commit SHA and carrying a written reason. Every failure message
prints the exact line.

Keying by SHA rather than by address is required, not stylistic. Requirement 11
keeps personal data out of this repository, and an allowlist keyed by address
would copy a third party's contact detail into a tracked file — publishing it a
second time, in the working tree, where it was not before. The SHA names the
same exception and carries none of it. For the same reason no message below
ever echoes the offending address: these messages land in public CI logs.

WHERE THAT LINE IS DRAWN, AND WHY THE SUBJECT IS ON THE OTHER SIDE
==================================================================

`check_commits` echoes the commit SUBJECT verbatim while echoing neither
address. That asymmetry is a decision, not an oversight, and the two fields
differ on both halves of the reason:

  * An ADDRESS is the thing this gate exists to keep unpublished, it can be a
    THIRD PARTY's — arriving from an unpinned environment or an imported
    commit, belonging to somebody who never chose to appear here — and it is
    the one field a reader does not need, because the message says how to
    inspect it locally.
  * A SUBJECT is the acting agent's OWN text, in a commit the agent has just
    pushed to this repository, so it is already published on the pull request
    the gate is running for; repeating it in the log of that same run
    discloses nothing new. It is also what makes a refusal actionable at a
    glance when a range holds several commits.

If a subject ever needs to carry an address, that is a commit-message problem
to fix before pushing, exactly as the LIFT text below already says.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
ALLOWLIST_PATH = REPO_ROOT / "scripts" / "ci" / "ci_gate_allowlist.toml"
ALLOWLIST_TABLE = "commit_identity"

#: The one sanctioned identity, for BOTH author and committer. Requirement 11
#: names the owner's already-public noreply commit identity as a narrow
#: canonical attribution exception, which is why this literal may live here.
SANCTIONED_EMAIL = "39077795+snaraj@users.noreply.github.com"

#: A trailer line, recognised the way Git recognises one: at the start of a
#: line, case-insensitively, with optional space before the colon. Prose that
#: merely MENTIONS the trailer mid-sentence is not matched. Being a little
#: broader than Git's own parser is the fail-closed direction — a false
#: refusal costs one allowlist line, a missed trailer costs a public address.
_TRAILER = re.compile(r"^[ \t]*co-authored-by[ \t]*:", re.IGNORECASE | re.MULTILINE)

_FULL_SHA = re.compile(r"^[0-9a-f]{40}$")

_FIELD = "\x1f"
_RECORD = "\x1e"


class CommitIdentityError(ValueError):
    """A range this module cannot read, or an allowlist it cannot trust."""


@dataclass(frozen=True)
class Commit:
    sha: str
    author_email: str
    committer_email: str
    subject: str
    message: str


def _git(*args: str) -> str:
    proc = subprocess.run(
        ("git", "-C", str(REPO_ROOT), *args),
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise CommitIdentityError(
            f"git {' '.join(args)} failed: {proc.stderr.strip() or proc.returncode}"
        )
    return proc.stdout


def commits_in_range(base: str, head: str, first_parent: bool = False) -> tuple[str, ...]:
    """Every commit reachable from `head` and not from `base`."""
    args = ["rev-list"]
    if first_parent:
        args.append("--first-parent")
    args.append(f"{base}..{head}")
    return tuple(_git(*args).split())


def commit_exists(sha: str) -> bool:
    proc = subprocess.run(
        ("git", "-C", str(REPO_ROOT), "cat-file", "-e", f"{sha}^{{commit}}"),
        capture_output=True,
    )
    return proc.returncode == 0


def read_commits(shas: tuple[str, ...] | list[str]) -> tuple[Commit, ...]:
    """Read identity and full message for each SHA, in the order given."""
    if not shas:
        return ()
    raw = _git(
        "log",
        "--no-walk=unsorted",
        f"--format=%H{_FIELD}%ae{_FIELD}%ce{_FIELD}%s{_FIELD}%B{_RECORD}",
        *shas,
    )
    commits: list[Commit] = []
    for record in raw.split(_RECORD):
        if not record.strip():
            continue
        parts = record.lstrip("\n").split(_FIELD)
        if len(parts) != 5:
            raise CommitIdentityError(
                f"unreadable commit record with {len(parts)} fields; refusing to guess"
            )
        commits.append(Commit(parts[0], parts[1], parts[2], parts[3], parts[4]))
    if len(commits) != len(shas):
        raise CommitIdentityError(
            f"asked for {len(shas)} commits and read {len(commits)}"
        )
    return tuple(commits)


def load_allowlist() -> dict[str, str]:
    """Read the shared lift mechanism. A malformed entry is a red gate."""
    if not ALLOWLIST_PATH.exists():
        raise CommitIdentityError(f"missing allowlist file {ALLOWLIST_PATH}")
    data = tomllib.loads(ALLOWLIST_PATH.read_text(encoding="utf-8"))
    table = data.get(ALLOWLIST_TABLE, {})
    if not isinstance(table, dict):
        raise CommitIdentityError(
            f"[{ALLOWLIST_TABLE}] in {ALLOWLIST_PATH} must be a table"
        )
    for entry, reason in table.items():
        if not isinstance(reason, str) or not reason.strip():
            raise CommitIdentityError(
                f"allowlist entry {entry!r} has no written reason; "
                "an entry without a reason is not a decision, it is a hole"
            )
    return dict(table)


def violations(commit: Commit) -> list[str]:
    """Every rule this commit breaks. Empty list means the commit is clean.

    No message here echoes the offending address: these strings reach public
    CI logs, and repeating a third party's contact detail there would publish
    it again. The SHA plus the named field is enough to inspect locally.
    """
    found: list[str] = []
    if commit.author_email != SANCTIONED_EMAIL:
        found.append(
            "its AUTHOR email is not the sanctioned owner noreply identity "
            f"(inspect locally: git log -1 --format=%ae {commit.sha})"
        )
    if commit.committer_email != SANCTIONED_EMAIL:
        found.append(
            "its COMMITTER email is not the sanctioned owner noreply identity "
            f"(inspect locally: git log -1 --format=%ce {commit.sha})"
        )
    trailers = len(_TRAILER.findall(commit.message))
    if trailers:
        found.append(
            f"its message carries {trailers} co-author trailer"
            f"{'s' if trailers > 1 else ''}, which this repository forbids "
            "outright (requirement 3)"
        )
    return found


def _lift(sha: str) -> str:
    relative = ALLOWLIST_PATH.relative_to(REPO_ROOT)
    return (
        f"\n  LIFT: this rule is liftable in one line. Add to the "
        f"[{ALLOWLIST_TABLE}] table of\n        {relative}:\n\n"
        f'          "{sha}" = "why this commit\'s identity or trailer is accepted"\n\n'
        "        Widening an allowlist with a written reason is a one-line PR and a\n"
        "        normal part of active development, not a security event.\n"
        "  BUT:  on a commit you have not pushed yet, FIX IT INSTEAD. Pin the\n"
        "        identity per 'Commit identity mechanics' and commit again; an\n"
        "        address that reaches published history cannot be unpublished.\n"
        "  NOTE: name the commit by SHA only. Never paste the address into the\n"
        "        reason — requirement 11 keeps personal data out of this repository."
    )


def check_commits(commits: tuple[Commit, ...] | list[Commit], allowlist: dict[str, str]) -> list[str]:
    """Return one finding per refused commit. Empty list means green."""
    findings: list[str] = []
    for commit in commits:
        if commit.sha in allowlist:
            continue
        broken = violations(commit)
        if not broken:
            continue
        detail = "\n".join(f"  - {reason}" for reason in broken)
        findings.append(
            f"{commit.sha} ({commit.subject}) is refused:\n{detail}" + _lift(commit.sha)
        )
    return findings


def audit(base: str, head: str, first_parent: bool = False) -> list[str]:
    """Run every rule over `base..head`. Returns the complete finding list."""
    shas = commits_in_range(base, head, first_parent)
    return check_commits(read_commits(shas), load_allowlist())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="commit_identity.py",
        description=(
            "Refuse a foreign author/committer identity or a co-author trailer "
            "in the commits of one range."
        ),
    )
    parser.add_argument("--base", required=True, help="exclusive range start")
    parser.add_argument("--head", required=True, help="inclusive range end")
    parser.add_argument(
        "--first-parent",
        action="store_true",
        help="follow only first parents, as the release gate does on main",
    )
    args = parser.parse_args(argv)
    try:
        shas = commits_in_range(args.base, args.head, args.first_parent)
        findings = check_commits(read_commits(shas), load_allowlist())
    except CommitIdentityError as error:
        print(f"DENY: {error}", file=sys.stderr)
        return 1
    if findings:
        print("\n\n".join(findings), file=sys.stderr)
        return 1
    print(
        f"commit-identity: {len(shas)} commit(s) in range; every author and "
        "committer is the sanctioned noreply identity and no message carries "
        "a co-author trailer"
    )
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entrypoint
    raise SystemExit(main())
