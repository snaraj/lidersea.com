#!/usr/bin/env python3
"""Whole-render NetworkPolicy census for the Helm chart.

WHY THIS EXISTS. A raw-line pin over one `--show-only` extract cannot make
the claim this gate needs to make. Such a pin recognises a YAML document by a
line whose prefix is exactly `kind` and the spec by a line exactly equal to
`spec:`. YAML permits whitespace before a mapping key's colon, permits the
key to be quoted, and permits escapes inside a double-quoted key, so a SECOND
`NetworkPolicy` in the very same rendered file can spell itself `kind :` /
`spec :` and be invisible to that census and to every one of its
self-mutations -- while parsing, under a real YAML implementation, as an
empty-selector `policyTypes: [Egress]` policy with one empty egress rule.
Kubernetes NetworkPolicy allowances are ADDITIVE, so that second document
hands every Pod unrestricted outbound access while the first one still reads
"default deny". That is not a hypothetical: an independent security review of
the sibling repository reproduced exactly that shape against a text pin at a
merged head, and this repository's chart has the identical exposure. The
text pin in `chart-egress-pin.sh` and this whole-render census therefore land
together here, because the text pin alone would be a claim this repository
could not support.

WHAT THIS MODULE DOES. It reads the COMPLETE installable Helm render -- every
template file, CRDs included, not one `--show-only` extract -- through a real
document reader that resolves keys to their canonical spelling before any
matching happens, flattens list wrappers so nothing can hide inside one, and
then requires the whole render to contain EXACTLY ONE NetworkPolicy whose
object equals an expectation this gate states itself. Nothing about the
expectation is read back out of the template under test: an expectation
derived from the thing it checks passes for anything that thing renders.

AND THEN IT BINDS THAT POLICY TO THE WORKLOAD. Everything above proves what
the policy SAYS. `bind_policy_to_workload` proves what it POINTS AT, and the
two are independent claims: a NetworkPolicy has a `podSelector` naming which
Pods it governs and rules saying what those Pods may do, and NOTHING in the
rules half can notice the selector drifting off the workload. Retarget only
the Deployment's Pod-template labels -- leaving the policy byte-identical --
and the policy matches ZERO Pods. A NetworkPolicy that selects no Pod governs
nothing, so those Pods run with FULL outbound access, while `helm lint`, the
ingress pin, the text pin in `chart-egress-pin.sh` and every assertion above
this paragraph stay green, because the policy's own text is untouched and
perfect. It simply applies to nothing. The binding assertion is the answer:
the render's ONE Deployment must sit in the policy's namespace, its Pod
template must carry labels the policy's selector actually matches under
Kubernetes' own `matchLabels` semantics, and the selector must name this
release rather than merely something.

WHERE THE EXPECTED FACTS COME FROM.

- The deny itself (`policyTypes` including `Egress`, `egress: []`) and the
  document inventory are CONSTANTS in this file. "No outbound connection,
  ever" is not configuration.
- The workload selector's two facts are the chart name (`chart/Chart.yaml`
  metadata) and the release name/namespace this gate renders with (passed in
  on the command line).
- The ingress peer identity and service port come from `chart/values.yaml`,
  the deployment-provider binding point AGENTS.md designates -- the same
  source `chart-ingress-pin.sh` uses, and the reason no provider name
  appears anywhere in this file.

WHY THE READER IS WRITTEN HERE. Requirement 1 and requirement 9 keep this
repository free of third-party runtime and toolchain dependencies; CI runs
no unpinned interpreter package, so PyYAML and yq are both unavailable. This
module therefore implements the reader, in the same spirit as
`scripts/ci/dependabot_contract.py`, but over the wider YAML subset a Helm
render actually uses: comments, flow collections, quoted keys and scalars,
and block scalars.

FAIL-CLOSED IS THE STRUCTURAL DESIGN GOAL. This reader does not implement all
of YAML, and it does not try to: the goal every rule below serves is that it
REFUSE rather than misread. Every construct it does not fully understand is
refused with the offending line named, never guessed at, so an unreadable
render is a red gate rather than a quiet pass. That is the design goal, not a
proof -- what is PROVEN here is the narrower, re-runnable claim stated under
PROVENANCE below, and the oracle-agreement evidence named there is inherited
from the ported reader rather than re-measured. Refused outright:

- tabs, carriage returns, other C0 control characters, DEL, the C1 control
  characters U+0080-U+009F (a real YAML reader rejects the whole stream for
  one; the range STOPS at U+009F, so `©`, `é`, CJK and emoji all read
  normally), every YAML-reader-forbidden code point U+D800-U+DFFF and
  U+FFFE-U+FFFF (all 2,050 of them, including malformed UTF-8 preserved by
  Python's stdin `surrogateescape`), byte-order marks (U+FEFF, anywhere in
  the stream -- invisible, and readers disagree about whether a leading one
  belongs to the next token), and `%` directives;
- the Unicode line breaks NEL (U+0085), LINE SEPARATOR (U+2028) and
  PARAGRAPH SEPARATOR (U+2029), anywhere in the stream: a real YAML reader
  BREAKS THE LINE at each of them, so a stream carrying one has a different
  number of lines there than here. `\\N`, `\\L` and `\\P` inside a
  double-quoted scalar still PRODUCE those characters, exactly as PyYAML
  does -- the refusal is about what the render's own bytes contain;
- anchors (`&`), aliases (`*`), tags (`!`), explicit keys (`?`), and merge
  keys (`<<`) -- each of which lets one document's meaning be assembled
  somewhere else in the stream;
- every other indicator a plain scalar may not open with, in KEY and VALUE
  position alike and from one shared constant (`_INDICATOR_START`), because
  a set kept in two places drifted apart once already;
- duplicate mapping keys, in block and flow style alike, since a later
  duplicate silently replaces the pinned earlier one;
- non-string mapping keys, plain keys carrying a comment (`k #: v` is the
  plain scalar "k" to a real reader, not a mapping entry), and plain keys
  inside a flow mapping whose colon is glued to what follows (`{a:1}` is the
  single scalar `a:1` there, with no value at all);
- flow collections or quoted scalars that do not open and close on one line,
  and multi-line plain scalars -- a value continuing onto the next line, at
  ANY indentation, including the top level where the continuation used to be
  read as a second document instead (see the document-boundary bullet below);
- plain scalars whose meaning differs between YAML 1.1 and 1.2 (`yes`, `no`,
  `on`, `off`, `y`, `n`), sexagesimals (`1:30`, and `1_:0` -- the digit
  groups take underscores too), hex/octal/binary integers, exponent forms
  (`1e3`, `1.0e3`), digit-group underscores (`1_000`), timestamps
  (`2026-08-20`, `2026-08-20T10:30:00Z`), `.inf`/`.nan`, and integers with a
  leading zero;
- the plain scalars `=` and `<<`, YAML 1.1's value key and merge key:
  PyYAML's SAFE loader has no constructor for either tag and REFUSES a
  document that carries one as a VALUE, while reading the same bytes as an
  ordinary string in key position. Refused in BOTH positions here, so this
  reader is never the more permissive of the two;
- plain scalars opening with a block sequence indicator (`- `), which real
  YAML refuses too -- this reader must never be MORE permissive than the
  tools that install the render;
- a document-end marker (`...`) with no document to end, and any content
  after one that is not preceded by a `---` document-start line: `...` ENDS
  a document rather than separating two, and a real YAML reader accepts only
  a directive, a `---`, another `...` or end-of-stream after it;
- a SECOND document that the stream never spelled. A document boundary is
  `---`, `...` or end-of-stream and nothing else, so a top-level node that
  simply stops -- a plain scalar with another line under it, a block sequence
  followed by a mapping key -- is refused rather than closed and reopened. A
  real YAML reader either FOLDS the next line into that node or refuses the
  stream; it never invents a boundary, and neither does this one.

BLOCK SCALARS ARE TRANSCRIBED, NOT PARAPHRASED. `|` and `>` bodies are the
one multi-line construct this reader RESOLVES, because their line semantics
are fully specified and PyYAML 6.0.3 implements them in one readable function
-- so exact agreement is provable and refusal would be over-reach on a
construct every Helm render is entitled to use. `_block_scalar_body` and its
two helpers follow `Scanner.scan_block_scalar`, `scan_block_scalar_breaks`
and `scan_block_scalar_indentation` step for step: the block's indentation is
the WIDEST run of leading whitespace crossed on the way to the first content
line (so a whitespace-only line wider than the body puts the body outside the
block, where the oracle raises and this reader refuses), a line of spaces is
blank only while it fits inside that indentation and is CONTENT past it, and
the folding and chomping tails are the oracle's own. A stream that does not
end in a newline has no final break to chomp, which is why the reader records
whether the trailing newline was there before splitting it away.

WHERE PYTHON'S STRING SEMANTICS ARE NOT YAML'S. YAML whitespace is exactly
SPACE and TAB, and tabs are refused above -- but Python's `str.strip()`,
`.lstrip()`, `.rstrip()` and `.split(None)` are UNICODE-aware and also eat
U+00A0, U+1680, U+2000-U+200A, U+202F, U+205F, U+3000 and the C0 separators,
while `str.splitlines()` additionally breaks lines at \\v, \\f, \\x1c-\\x1e and
U+0085/U+2028/U+2029. Every strip in this module therefore goes through the
ASCII-explicit `_ascii_strip`/`_ascii_rstrip` helpers, every split names its
separator, `str.splitlines()` is never used at all, and every regex spells
its character classes as literal ASCII ranges (`[0-9]`, `[a-fA-F]`) rather
than `\\d`/`\\w`/`\\s` -- which is also PyYAML 6.0.3's own choice, so the
transcribed patterns stay both string-equal AND behaviour-equal to the
oracle's without an `re.ASCII` flag the oracle does not carry. `int()` and
`float()` accept Unicode decimal digits and Unicode whitespace (`int('\\u0665')`
is 5), so every call site is gated behind one of those ASCII-only patterns
first and a fullwidth or Arabic-Indic digit is a plain STRING to both readers.

Floats are the one number form this reader RESOLVES rather than refuses, so
`_FLOAT_RE` is PyYAML's own float-resolver decimal branches transcribed
character for character; `.5` is 0.5 to both readers and `-.5` is the string
"-.5" to both, because the oracle's leading-dot branch carries no sign.

PROVENANCE OF THE READER, AND WHAT THIS REPOSITORY HAS AND HAS NOT PROVEN.
This reader is a port. Its code is the sibling repository's reader, whose
agreement with PyYAML 6.0.3 -- the oracle, never a dependency; nothing in
this repository imports it -- was measured THERE, over a corpus of
Helm-render and hostile shapes extended by several rounds of independent
review and a post-merge audit, with every measured divergence closed in the
code carried across. That corpus and those measurements are that
repository's evidence and are NOT re-run here; requirement 5 makes this
repository independent of it, so the honest statement of what lidersea.com
holds is narrower and is stated exactly:

- the unit suite in `scripts/ci/test_chart_render_census.py` runs here, in
  the `security` job, on every pull request, and it pins the reader's
  refusals and its exact readings one input at a time against hand-written
  expectations -- never against PyYAML, which CI does not install;
- the 53-mutation census battery in `chart-egress-pin.sh` assertion (d) runs
  here, in the `chart` job, against THIS repository's own real Helm render,
  and every mutant must be refused;
- assertion (g) pins that battery at its floor, so it cannot be quietly
  shrunk, and the unit suite pins the floor against the battery's real size,
  so the floor cannot drift away from what actually runs.

ONE READING CONVENTION FOLLOWS FROM THAT, and it applies to every comment
below: a note reading "measured on Kubernetes v1.36.3" records a live API
server probe run during the ported reader's work, NOT one this repository
ran. Those are properties of the Kubernetes API server rather than of
either chart, which is why they port; they are named as inherited anyway,
because a gate that overstates its own evidence is the thing this file
exists to prevent.

What is therefore claimed here is a bounded, re-runnable property of this
repository's own render and this reader's own tests. The oracle-agreement
claim is inherited, is named as inherited, and a future round of differential
work against PyYAML would be new evidence to record in this file rather than
a claim already in hand. Every divergence the ported work did record runs in
the safe direction -- this reader refusing something PyYAML resolves
(`2026_08`, `=` in key position, `--- x`, a `%YAML` directive reopening a
stream after `...`, and a plain scalar folded across a line break) -- which
is the direction that cannot hide a document.

CLI (stdin is the render for `census` and `mutate`):

    python3 -I -B scripts/ci/chart_render_census.py census \\
        --chart chart --release NAME --namespace NAMESPACE
    python3 -I -B scripts/ci/chart_render_census.py mutations
    python3 -I -B scripts/ci/chart_render_census.py mutate \\
        --chart chart --release NAME --namespace NAMESPACE --name MUTATION

Exit 0 on success. Exit 1, with a `chart-render-census:` line on stderr
naming the offending line or the failed assertion, on any refusal. Exit 2 is
argparse's own usage-error status for a malformed invocation.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

# --- The pinned expectation -------------------------------------------------
#
# Constants, deliberately: the deny is not configuration, and an expectation
# read out of the template under test would pass for any template.

POLICY_KIND = "NetworkPolicy"
POLICY_API_VERSION = "networking.k8s.io/v1"
POLICY_NAME_PREFIX = "ingress-to-"
POLICY_TYPES = ["Ingress", "Egress"]
POLICY_SPEC_KEYS = ("podSelector", "policyTypes", "ingress", "egress")
POLICY_METADATA_KEYS = ("name", "namespace", "labels")

# The one Pod-producing object in this render, and therefore the one workload
# the policy has to govern. `EXPECTED_INVENTORY` below already pins the render
# to exactly one of these, so a SECOND Deployment carrying the same labels --
# recorded as a P1 against an earlier attempt at this gate -- is refused by the
# inventory before the binding assertion is ever reached; the binding assertion
# re-states the count anyway so it is correct when called on its own.
WORKLOAD_KIND = "Deployment"

# The two labels that together name exactly ONE release of exactly ONE chart,
# and the reason both are required rather than either. `app.kubernetes.io/name`
# alone is carried by every release of this chart in the namespace, so a
# selector holding only it still MATCHES this workload -- a subset test passes
# -- while also governing Pods nobody reviewed. That is the over-selection half
# of the same defect as a selector that matches nothing, and a binding proof
# that only checked "does it match?" would wave it through.
WORKLOAD_IDENTITY_KEYS = ("app.kubernetes.io/instance", "app.kubernetes.io/name")

# The complete installable render, as (apiVersion, kind) pairs. A census that
# only counted NetworkPolicies would still miss a second policy written under
# a CNI's own CRD kind (CiliumNetworkPolicy, crd.projectcalico.org
# NetworkPolicy, ...), so the inventory is pinned whole. Growing the chart by
# one document is therefore a deliberate edit HERE, with a reviewer reading
# what the new document is -- which is the point.
EXPECTED_INVENTORY = (
    ("apps/v1", "Deployment"),
    ("networking.k8s.io/v1", "NetworkPolicy"),
    ("v1", "Service"),
    ("v1", "ServiceAccount"),
)

# A list wrapper may nest, but not indefinitely; a render that needs more
# than this is a render nobody is reading by hand.
MAX_WRAPPER_DEPTH = 4


class CensusError(ValueError):
    """The render could not be read, or it fails the census."""


# --- Reader -----------------------------------------------------------------

_AMBIGUOUS_PLAIN = frozenset(
    {"y", "Y", "yes", "Yes", "YES", "n", "N", "no", "No", "NO", "on", "On", "ON", "off", "Off", "OFF"}
)
_NULL_PLAIN = frozenset({"~", "null", "Null", "NULL"})
_TRUE_PLAIN = frozenset({"true", "True", "TRUE"})
_FALSE_PLAIN = frozenset({"false", "False", "FALSE"})
_INT_RE = re.compile(r"[-+]?[0-9]+")
# A float is the one number form this reader RESOLVES rather than refuses, so
# its pattern is PyYAML's own float resolver's two decimal branches,
# transcribed character for character:
#
#     [-+]?(?:[0-9][0-9_]*)\.[0-9_]*(?:[eE][-+][0-9]+)?
#     \.[0-9][0-9_]*(?:[eE][-+][0-9]+)?
#
# The leading-dot branch carries NO sign there -- only the branch with a digit
# BEFORE the dot does -- so `-.5` and `+.5` match neither, and PyYAML 6.0.3
# reads them as the STRINGS "-.5"/"+.5". A pattern that allowed a sign in front
# of a leading-dot mantissa made them the floats -0.5/0.5 here: the same shape
# as `1_000` and the timestamps, and the ported reader's differential review measured it.
# Unsigned `.5` stays a float on both sides. The resolver's other three
# branches -- sexagesimal floats, `.inf`, `.nan` -- and the exponent suffix are
# all refused further up, so only plain decimals ever reach this pattern and
# `float()` never sees an underscore or an exponent.
_FLOAT_RE = re.compile(
    r"[-+]?(?:[0-9][0-9_]*)\.[0-9_]*(?:[eE][-+][0-9]+)?"
    r"|\.[0-9][0-9_]*(?:[eE][-+][0-9]+)?"
)
# Exponent forms are refused outright: YAML 1.2 reads `1e3` and `1.0e3` as
# floats, while YAML 1.1 -- which is what sigs.k8s.io/yaml and PyYAML 6.0.3
# implement -- reads both as plain strings and wants `1.0e+3`. Three spellings,
# two answers, no way to be sure which one a cluster will see.
_EXPONENT_RE = re.compile(r"[-+]?(?:[0-9]+\.?[0-9]*|\.[0-9]+)[eE][-+]?[0-9]+")
# Sexagesimals carry digit-group underscores too, and the two YAML 1.1
# resolvers that VALUE them -- the int branch `[-+]?[1-9][0-9_]*(?::[0-5]?[0-9])+`
# and the float branch `[-+]?[0-9][0-9_]*(?::[0-5]?[0-9])+\.[0-9_]*` -- both
# allow `_` inside every digit group. A pattern that allowed digits only left
# `1_:0` a string here and the integer 60 there, which the ported reader's round-three
# exhaustive fuzz of the number alphabet found; `_` is in every class below so
# this pattern is a strict SUPERSET of both oracle branches, which is the
# direction that can only ever over-refuse.
_SEXAGESIMAL_RE = re.compile(r"[-+]?[0-9][0-9_]*(?::[0-9_]+)+(?:\.[0-9_]*)?")
# Timestamps are refused for the same reason, one step further along: YAML 1.1
# resolves a timestamp-shaped plain scalar to a date/datetime OBJECT -- PyYAML
# 6.0.3 reads `2026-08-20` as `datetime.date(2026, 8, 20)` and
# `2026-08-20 10:30:00` as a `datetime` -- while YAML 1.2's core schema has no
# timestamp type at all and reads the same bytes as a string. The pattern below
# is PyYAML's own resolver pattern, transcribed, so this reader refuses exactly
# the forms that reader VALUES and no more: the bare date form wants a two-digit
# month and day, which is why `2026-8-20` on its own stays the string both
# readers already agree it is, and `2026-08-20t10:30:00z` (lowercase zone) does
# too. Tabs never survive `_check_bytes`; `\t` is kept in the pattern only so it
# stays the oracle's, character for character.
_TIMESTAMP_RE = re.compile(
    r"(?:[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]"
    r"|[0-9][0-9][0-9][0-9]-[0-9][0-9]?-[0-9][0-9]?"
    r"(?:[Tt]|[ \t]+)[0-9][0-9]?:[0-9][0-9]:[0-9][0-9](?:\.[0-9]*)?"
    r"(?:[ \t]*(?:Z|[-+][0-9][0-9]?(?::[0-9][0-9])?))?)"
)
# `=` is YAML 1.1's "value key". PyYAML resolves a plain `=` to
# `tag:yaml.org,2002:value`, and its SAFE loader has no constructor for that
# tag, so `a: =` raises a ConstructorError instead of parsing; in KEY position
# the same bytes survive as the string "=", because `flatten_mapping` retags
# them first. One spelling, two answers, and one of those answers is a hard
# refusal in the ORACLE -- the one direction a reader must never be looser in.
# What the INSTALLER does with it is a separate, measured fact and is not the
# same refusal: on Kubernetes v1.36.3, `kubectl apply` on a shadow policy
# carrying `shadow-marker: =` reads `=` as the ordinary string "=", creates the
# four objects it could, and then rejects the shadow for its LABEL VALUE
# ("a valid label must be an empty string or ..."), exiting 1 -- a partial
# apply, not a whole-stream refusal. Refused here in both positions.
_VALUE_KEY_PLAIN = "="
# `<<` is YAML 1.1's merge key, and it is the exact same shape as `=` one tag
# along: PyYAML resolves a plain `<<` to `tag:yaml.org,2002:merge`, its SAFE
# loader has no constructor for that tag, and `a: <<` therefore raises a
# ConstructorError instead of parsing -- while `_scan_key` already refused it
# in key position. the ported reader's differential hunt measured it in value position,
# where this reader handed back the string "<<" and read on. Refused in both,
# for the same reason: a gate that reads a document the installer will not read
# is a gate reporting on something else.
_MERGE_KEY_PLAIN = "<<"
# Digit-group underscores are refused for the same reason as the exponent
# forms: YAML 1.1 -- what PyYAML 6.0.3 and sigs.k8s.io/yaml implement -- lets
# `_` separate digit groups, so `1_000` is the integer 1000 there, while
# YAML 1.2 has no such form and reads the same bytes as the string "1_000".
# One spelling, two answers. The pattern requires a leading digit (after an
# optional sign) exactly as YAML 1.1 does, so `_1` stays the string both
# readers already agree it is; the caller checks for an underscore first, so
# ordinary numbers never reach it.
_UNDERSCORE_NUMBER_RE = re.compile(
    r"[-+]?(?:[0-9][0-9_]*(?:\.[0-9_]*)?|\.[0-9][0-9_]*)(?:[eE][-+]?[0-9_]+)?"
)
_RADIX_RE = re.compile(r"[-+]?0[xXoObB][0-9a-fA-F_]+")
_SPECIAL_FLOAT_RE = re.compile(r"[-+]?\.(?:inf|Inf|INF|nan|NaN|NAN)")
# The characters a plain scalar may not OPEN with. PyYAML's `check_plain`
# forbids `-?:,[]{}#&*!|>'"%@` plus a backtick, letting through only `-` when
# the next character is not a space, and `?`/`:` when the next character is not
# a space AND the scalar is not inside a flow collection. This reader refuses
# the same set from ONE constant used in
# all three plain-scalar entry points -- block value, block key, flow key --
# because a set that lived in two places drifted apart once already: `_scan_key`
# refused only `& * ! ?` while `_scan_value` refused the wider set, so `@foo:`,
# `` `foo: ``, `|foo:`, `>foo:` and `,foo:` were keys here and hard scanner
# errors in the tool that installs the render. Quotes, `[`, `{` and `#` never
# reach the check in value position -- they are dispatched to the quoted, flow
# and comment paths first -- and the two deliberate, measured asymmetries are
# `-` (refused only as the block sequence indicator `- `, since `-5` is a plain
# scalar both readers agree on) and `:` (a legal plain-scalar opener in BLOCK
# context, refused only inside a flow collection, exactly as PyYAML does).
_INDICATOR_START = "&*!?|>%@`,[]{}#"

# NEL, LINE SEPARATOR and PARAGRAPH SEPARATOR are LINE BREAKS to a YAML 1.1
# reader and ordinary characters to anything that only splits on `\n`. PyYAML
# 6.0.3 breaks the line at each of them, so `kind: Network<NEL>Policy` is two
# lines and a scanner error there while it was one line and the scalar
# "Network\x85Policy" here -- and a leading or trailing one silently vanished
# from a key or value here that PyYAML never saw at all. Refused everywhere in
# the stream, never translated: a reader that disagrees with the installer
# about how many LINES a document has is not reading the same document.
_UNICODE_LINE_BREAKS = {
    "\x85": "NEL (U+0085)",
    "\u2028": "LINE SEPARATOR (U+2028)",
    "\u2029": "PARAGRAPH SEPARATOR (U+2029)",
}

_SIMPLE_ESCAPES = {
    "0": "\0",
    "a": "\a",
    "b": "\b",
    "t": "\t",
    "n": "\n",
    "v": "\v",
    "f": "\f",
    "r": "\r",
    "e": "\x1b",
    " ": " ",
    '"': '"',
    "/": "/",
    "\\": "\\",
    "N": "\x85",
    "_": "\xa0",
    "L": "\u2028",
    "P": "\u2029",
}


# YAML's whitespace is exactly SPACE and TAB, and tabs are refused outright by
# `_check_bytes`, so the only whitespace this reader may ever strip is the
# ASCII space. Python's `str.strip()`/`.lstrip()`/`.rstrip()`/`.split(None)`
# are UNICODE-aware and eat far more than that -- U+00A0, U+1680,
# U+2000-U+200A, U+202F, U+205F, U+3000, plus the C0 separators. Leaning on
# them made `a: \xa0` the value None here where PyYAML 6.0.3 reads the string
# "\xa0", made a whole-document `\xa0` vanish into ZERO documents, and let
# `a: |\xa0` parse as a block scalar where PyYAML raises: accept-and-misread
# and accept-where-the-oracle-refuses, in this reader's own taxonomy. the ported reader's
# differential review measured all three. Every strip below is therefore
# ASCII-explicit through these helpers, and `str.splitlines()` is never used
# anywhere in this module -- it breaks lines at \v, \f, \x1c-\x1e and
# U+0085/U+2028/U+2029 as well as \n, which is the same bug one step earlier.
_YAML_SPACE = " "


def _ascii_strip(raw: str) -> str:
    return raw.strip(_YAML_SPACE)


def _ascii_rstrip(raw: str) -> str:
    return raw.rstrip(_YAML_SPACE)


def _indent_of(raw: str) -> int:
    return len(raw) - len(raw.lstrip(_YAML_SPACE))


def _ignorable(raw: str) -> bool:
    stripped = _ascii_strip(raw)
    return stripped == "" or stripped.startswith("#")


def _document_marker(raw: str) -> str | None:
    """`"---"`, `"..."` or None: which document marker this LINE is.

    ONE predicate, in ONE place. `documents()` and the four block readers each
    used to decide this for themselves, and two of those spellings could
    disagree about a line like `---\xa0`: Python's `str.strip()` eats the
    U+00A0 and calls it a marker where an ASCII strip does not. A stream
    carrying one then made `documents()` hand the line to `_document_body`,
    which returned None without consuming it, and the outer loop spun forever
    -- a HANG rather than a red gate, which is worse than either answer.
    Sharing the predicate makes that desynchronisation unrepresentable, for
    exactly the reason `_INDICATOR_START` is one constant.

    A marker is only a marker at column zero and only when the three
    characters are followed by nothing or by a space, which is PyYAML's own
    rule -- `...x` and `  ...` are ordinary plain scalars to both readers.
    """
    if _indent_of(raw) != 0:
        return None
    stripped = _ascii_strip(raw)
    for marker in ("---", "..."):
        if stripped == marker or stripped.startswith(marker + " "):
            return marker
    return None


class Reader:
    """A fail-closed reader for the YAML subset a Helm render actually uses."""

    def __init__(self, text: str, origin: str) -> None:
        self.origin = origin
        self.lines = text.split("\n")
        # A trailing newline terminates the last line; it does not add an
        # empty one. Keeping the split artefact would give a `|+` block
        # scalar one newline more than it really has.
        #
        # WHETHER the stream ended with that newline is itself a fact the
        # block-scalar reader needs, and popping the artefact destroys it:
        # `a: |` / `  x` WITH a final newline is "x\n" to PyYAML 6.0.3 and
        # WITHOUT one is "x", because clip chomping appends the last line's
        # break and an unterminated last line has none. Recording it here
        # keeps the two streams distinguishable after the split.
        self.ends_with_newline = bool(self.lines) and self.lines[-1] == ""
        if self.ends_with_newline:
            self.lines.pop()
        self.i = 0
        self._check_bytes()

    def _line_break_after(self, index: int) -> bool:
        """Does line `index` end with a line break, or with end-of-stream?"""
        if index >= len(self.lines):
            return False
        if index < len(self.lines) - 1:
            return True
        return self.ends_with_newline

    # -- diagnostics --------------------------------------------------------

    def fail(self, message: str, lineno: int | None = None) -> None:
        if lineno is None:
            lineno = min(self.i + 1, len(self.lines))
        raise CensusError("%s line %d: %s" % (self.origin, lineno, message))

    def _check_bytes(self) -> None:
        for lineno, raw in enumerate(self.lines, start=1):
            if "\t" in raw:
                self.fail("tab characters are refused; YAML forbids them as indentation and "
                          "they make every column ambiguous", lineno)
            if "\r" in raw:
                self.fail("carriage returns are refused; a line that ends differently than it "
                          "looks is a line this gate will not guess at", lineno)
            if "\ufeff" in raw:
                # A byte-order mark is invisible and readers disagree about it:
                # PyYAML and the YAML spec strip one at stream start, so `kind`
                # behind a BOM is the key `kind` there, while a reader that does
                # not strip it sees a DIFFERENT key and stops recognising the
                # document. Anywhere else in the stream it is not even a
                # separator. Refused everywhere rather than stripped, so no
                # rendered byte is ever silently discarded.
                self.fail("a byte-order mark (U+FEFF) is refused; it is invisible and readers "
                          "disagree about whether it is part of the next token", lineno)
            for ch in raw:
                code = ord(ch)
                if code < 0x20 or code == 0x7F:
                    self.fail("control character %r is refused" % ch, lineno)
                if 0xD800 <= code <= 0xDFFF or 0xFFFE <= code <= 0xFFFF:
                    # YAML 1.2.2's `c-printable` excludes the entire surrogate
                    # block and the two BMP noncharacters. PyYAML 6.0.3 uses
                    # that exact printable set and rejects the stream before
                    # scanning. The surrogate block also catches malformed
                    # UTF-8 that Python preserves through stdin's
                    # `surrogateescape` (for example byte 80 -> U+DC80).
                    # Supplementary noncharacters such as U+1FFFE/U+1FFFF are
                    # deliberately NOT included: the spec and oracle permit
                    # every code point from U+10000 through U+10FFFF.
                    self.fail("the YAML-forbidden code point U+%04X is refused; YAML 1.2.2 "
                              "and PyYAML 6.0.3 exclude it from printable streams" % code,
                              lineno)
                if ch in _UNICODE_LINE_BREAKS:
                    self.fail("%s is refused; a real YAML reader treats it as a LINE BREAK, so "
                              "the bytes after it start a new line there while they continue "
                              "this one here -- one stream, two different documents"
                              % _UNICODE_LINE_BREAKS[ch], lineno)
                if 0x80 <= code <= 0x9F:
                    # PyYAML's reader rejects the whole stream for any of these
                    # (its printable set skips U+0080-U+009F). Measured against
                    # Kubernetes v1.36.3, the installer does not reject the
                    # whole stream: `kubectl apply` on a render carrying one
                    # CREATES the four objects it could read and then exits 1
                    # ("yaml: control characters are not allowed"), so a render
                    # this gate read happily would be a render that installs
                    # PART of itself. The
                    # range STOPS at U+009F: `©`, `é`, CJK and emoji all read
                    # normally, and so does U+00A0 -- but U+00A0 reads normally
                    # only because the strip helpers above are ASCII-explicit.
                    # A sole or edge U+00A0 would otherwise read as the value
                    # None here against PyYAML's "\xa0", because Python's own
                    # `str.strip()` eats it. So the promise is exactly this
                    # range, and no more.
                    self.fail("the C1 control character U+%04X is refused; a real YAML reader "
                              "rejects the entire stream for it, so a render this gate could "
                              "read would be a render nothing can install" % code, lineno)
            if raw[:1] == "%":
                self.fail("YAML directives are refused; they can change how the rest of the "
                          "stream is interpreted", lineno)

    # -- documents ----------------------------------------------------------

    def documents(self) -> list[object]:
        docs: list[object] = []
        # `...` ENDS a document; it does not separate two. PyYAML accepts only
        # a directive, a `---`, another `...` or end-of-stream after one, and
        # raises a ParserError on anything else -- while this reader used to
        # treat `...` as a benign boundary and read straight on. `...\n` alone
        # was ZERO documents here and a ParserError there; `x: 1\n...\nfoo: v`
        # was TWO documents here and a ParserError there. the ported reader's round-four
        # review measured both. Refused, in the oracle's own shape: a bare
        # `...` before any document, or content after one with no intervening
        # `---`, stops the gate with the offending line named.
        after_document_end = False
        while True:
            self._skip_ignorable()
            if self.i >= len(self.lines):
                return docs
            raw = self.lines[self.i]
            stripped = _ascii_strip(raw)
            marker = _document_marker(raw)
            if marker == "---":
                if stripped != "---":
                    self.fail("content on a document-start line is refused; write the document "
                              "on the following lines")
                self.i += 1
                # EQUIVALENT MUTANT (proven by the ported reader's measurement):
                # dropping this reset changes nothing -- 0 diffs over 182,170
                # corpus inputs and 29 probes -- but only BECAUSE of the
                # document-boundary rewrite. Since `_read_document` returns only at a spelled marker
                # or end-of-stream, the loop can never come back round to the
                # `if after_document_end` test with ordinary content in hand,
                # so a stale flag is unobservable. Before that rewrite it was
                # load-bearing, and it stays as the statement of intent.
                after_document_end = False
                docs.append(self._read_document())
                continue
            if marker == "...":
                if stripped != "...":
                    self.fail("content on a document-end line is refused")
                if not docs:
                    self.fail("a document-end marker (`...`) before any document is refused; a "
                              "real YAML reader has no document to end here and raises instead "
                              "of reading on")
                self.i += 1
                after_document_end = True
                continue
            if after_document_end:
                self.fail("content after a document-end marker (`...`) is refused; a real YAML "
                          "reader requires a `---` document-start line first and raises "
                          "otherwise. Measured against Kubernetes v1.36.3, a render whose last "
                          "document is separated by `...` instead of `---` is WORSE than a "
                          "refused one: `kubectl apply` exits 0 and installs three of the four "
                          "objects, silently discarding everything after the marker. A stream "
                          "this gate read two documents out of is a stream that installs a "
                          "DIFFERENT set of objects than the one it was counted from")
            docs.append(self._read_document())

    def _read_document(self) -> object:
        """One document, and then the boundary that closes it.

        A DOCUMENT BOUNDARY IS SPELLED, NEVER INFERRED. `documents()` used to
        loop straight back and start a second document wherever a top-level
        node happened to end -- and a top-level node ends whenever the next
        line is not more indented, which is to say almost anywhere. PyYAML
        6.0.3 does something else entirely in every one of those shapes: it
        FOLDS the next line into the node above (`a` / `b` is the one scalar
        "a b" there and was TWO documents ['a', 'b'] here), or it refuses the
        stream outright (`-` / `a` and `x` / `kind: v` are both ScannerErrors
        there and were two documents here). Accept-and-misread and
        accept-where-the-oracle-refuses, in this reader's own taxonomy; the
        ported reader's differential review measured all three, and they were
        structurally unreachable to its earlier rounds because every corpus
        alphabet those rounds swept was newline-free.
        Refused here, with the offending line named, which also makes the
        module's standing claim that "multi-line plain scalars are refused"
        TRUE: the reader was not refusing them, it was silently splitting the
        stream into documents that DO NOT INSTALL AS COUNTED. Measured against
        Kubernetes v1.36.3 rather than reasoned about: `kubectl apply` on such
        a render is a PARTIAL APPLY -- it creates the four objects it could
        read and THEN exits 1 on the unreadable tail, so the cluster is left
        half-changed and the census's count described a file nothing applied
        whole.
        """
        node = self._document_body()
        self._skip_ignorable()
        if self.i >= len(self.lines):
            return node
        if _document_marker(self.lines[self.i]) is not None:
            return node
        self.fail("a second document may begin only after a `---` document-start line; this "
                  "line ends or continues the document above instead, and a real YAML reader "
                  "either FOLDS it into that node or refuses the stream outright -- it never "
                  "starts a new document here, so neither will this gate")

    def _document_body(self) -> object:
        self._skip_ignorable()
        if self.i >= len(self.lines):
            return None
        raw = self.lines[self.i]
        if _document_marker(raw) is not None:
            return None
        start = self.i
        node = self._node(_indent_of(raw))
        # EQUIVALENT MUTANT (proven by the ported reader's measurement): no input
        # reaches this guard -- 0 diffs over 182,170 corpus inputs and 29
        # probes with it removed. It exists because the differential review measured a real
        # HANG here: `documents()` and `_document_body` decided independently
        # what a `---`/`...` marker was, and a line like `---\xa0` could be a
        # marker to one and content to the other, so the outer loop spun
        # forever. Sharing `_document_marker` made the desynchronisation
        # unrepresentable and left this guard as the belt behind that brace.
        # A hang is worse than either answer, so the belt stays.
        if self.i == start:
            self.fail("this document consumed no input; refusing rather than looping")
        return node

    def _skip_ignorable(self) -> None:
        while self.i < len(self.lines) and _ignorable(self.lines[self.i]):
            self.i += 1

    # -- nodes --------------------------------------------------------------

    def _node(self, indent: int) -> object:
        raw = self.lines[self.i]
        body = raw[indent:]
        if _ascii_rstrip(body) == "-" or body.startswith("- "):
            return self._sequence(indent)
        if body[:1] in ("[", "{"):
            return self._scalar_line(indent)
        if self._scan_key(body, self.i + 1) is not None:
            return self._mapping(indent)
        return self._scalar_line(indent)

    def _scalar_line(self, indent: int) -> object:
        raw = self.lines[self.i]
        lineno = self.i + 1
        value, end = self._scan_value(raw, indent, lineno, flow=False)
        self._require_trailing_blank(raw, end, lineno)
        self.i += 1
        if self.i < len(self.lines):
            nxt = self.lines[self.i]
            if not _ignorable(nxt) and _indent_of(nxt) > indent:
                self.fail("multi-line plain scalars are refused; a value that continues onto "
                          "the next line is a value this gate will not guess at", self.i + 1)
        return value

    def _mapping(self, indent: int) -> dict:
        out: dict = {}
        while self.i < len(self.lines):
            raw = self.lines[self.i]
            if _ignorable(raw):
                self.i += 1
                continue
            here = _indent_of(raw)
            if _document_marker(raw) is not None:
                break
            if here < indent:
                break
            if here > indent:
                self.fail("unexpected indentation inside a block mapping")
            body = raw[indent:]
            if _ascii_rstrip(body) == "-" or body.startswith("- "):
                self.fail("a block sequence entry appears where a mapping key was expected")
            lineno = self.i + 1
            scanned = self._scan_key(body, lineno)
            if scanned is None:
                self.fail("this line is neither a mapping key nor anything else this reader "
                          "can parse")
            key, rest = scanned
            if key in out:
                self.fail("duplicate mapping key %r; a later duplicate silently replaces the "
                          "earlier one, so the pinned value could be overwritten unseen" % key,
                          lineno)
            self.i += 1
            out[key] = self._value_after_key(body[rest:], indent, lineno)
        return out

    def _sequence(self, indent: int) -> list:
        items: list = []
        while self.i < len(self.lines):
            raw = self.lines[self.i]
            if _ignorable(raw):
                self.i += 1
                continue
            here = _indent_of(raw)
            if _document_marker(raw) is not None:
                break
            if here < indent:
                break
            if here > indent:
                self.fail("unexpected indentation inside a block sequence")
            body = raw[indent:]
            if _ascii_rstrip(body) == "-":
                self.i += 1
                items.append(self._child(indent, allow_sibling_sequence=False))
                continue
            if not body.startswith("- "):
                break
            offset = 2
            while indent + offset < len(raw) and raw[indent + offset] == " ":
                offset += 1
            # Rewriting the dash to spaces preserves every column, so the item
            # is parsed as an ordinary node at its own indentation.
            self.lines[self.i] = " " * (indent + offset) + raw[indent + offset:]
            items.append(self._node(indent + offset))
        return items

    def _value_after_key(self, text: str, parent_indent: int, lineno: int) -> object:
        stripped = _ascii_strip(text)
        if stripped == "" or stripped.startswith("#"):
            return self._child(parent_indent, allow_sibling_sequence=True)
        if stripped[0] in ("|", ">"):
            return self._block_scalar(stripped, parent_indent, lineno)
        value, end = self._scan_value(text, 0, lineno, flow=False)
        self._require_trailing_blank(text, end, lineno)
        return value

    def _child(self, parent_indent: int, allow_sibling_sequence: bool) -> object:
        self._skip_ignorable()
        if self.i >= len(self.lines):
            return None
        raw = self.lines[self.i]
        here = _indent_of(raw)
        if _document_marker(raw) is not None:
            return None
        if here > parent_indent:
            return self._node(here)
        if allow_sibling_sequence and here == parent_indent:
            body = raw[here:]
            # EQUIVALENT MUTANT (proven by the ported reader's measurement): spelling
            # this `body.rstrip()` instead is indistinguishable -- 0 diffs in
            # values and refusal messages over 182,170 corpus inputs and 29
            # targeted probes. `-\xa0` would enter `_sequence` here, but
            # `_sequence`'s own test is ASCII-explicit, so it consumes nothing,
            # returns [], and the caller re-reads the same line and fails with
            # the identical message. The clause is redundant with that one, not
            # unreachable, and `_sequence`'s copy IS killed by the suite.
            if _ascii_rstrip(body) == "-" or body.startswith("- "):
                return self._sequence(here)
        return None

    def _block_scalar(self, header_text: str, parent_indent: int, lineno: int) -> str:
        # `str.split(None, 1)` splits on Python's whitespace, not YAML's: it
        # cut `|\xa0` into the header `|` and no trailing text at all, so
        # `a: |\xa0` parsed as an ordinary literal block scalar here while
        # PyYAML 6.0.3 raises a ScannerError on the U+00A0 after the
        # indicator. Splitting on the ASCII space alone keeps the header
        # exactly the bytes YAML says it is, so an unsupported one is refused
        # by the loop below instead of silently accepted.
        parts = header_text.split(_YAML_SPACE, 1)
        header = parts[0]
        trailing = _ascii_strip(parts[1]) if len(parts) > 1 else ""
        if trailing and not trailing.startswith("#"):
            self.fail("unexpected text after a block scalar header", lineno)
        style = header[0]
        chomp = ""
        explicit = None
        for ch in header[1:]:
            if ch in "+-":
                if chomp:
                    self.fail("a block scalar header carries two chomping indicators", lineno)
                chomp = ch
            elif ch in "123456789":
                if explicit is not None:
                    self.fail("a block scalar header carries two indentation indicators", lineno)
                explicit = int(ch)
            else:
                self.fail("unsupported block scalar header %r" % header, lineno)
        return self._block_scalar_body(style, chomp, explicit, parent_indent)

    # -- block scalar bodies, transcribed from the oracle --------------------
    #
    # WHY THIS IS A TRANSCRIPTION AND NOT A PARAPHRASE. Block-scalar line
    # semantics are fully specified and the oracle implements them in one
    # readable function (`Scanner.scan_block_scalar` and its three helpers in
    # PyYAML 6.0.3), so exact agreement is PROVABLE here and refusal would be
    # over-reach: a Helm render is entitled to a `|` block. The paraphrase
    # that stood here before called every all-space line "blank" whatever its
    # width, detected the block's indentation from the first non-blank line
    # instead of from the widest leading whitespace run, and threw leading
    # blank lines away — three separate divergences the ported reader's differential review
    # measured:
    #
    #   `a: >` / `` / `  x`     -> "x\n"  here, "\nx\n" there (leading break lost)
    #   `a: |` / `  x` / `   `  -> "x\n"  here, "x\n \n" there (a whitespace-only
    #                              line WIDER than the block indent is CONTENT,
    #                              not a blank line)
    #   `a: >` / `   ` / `  x`  -> accepted here, ParserError there (the widest
    #                              leading run SETS the indent, so the following
    #                              line is not in the block at all)
    #
    # The functions below follow the oracle's own control flow step for step
    # — its indentation scan, its break scan, its main loop, its folding rule
    # and its chomping tail — over this reader's line list instead of a
    # character stream. Column arithmetic replaces `self.column`, and
    # `_line_break_after` replaces `peek() != '\0'` at a line end, because a
    # stream whose last line carries no newline has no final break to chomp.
    # Tabs, carriage returns and the Unicode line breaks never reach here:
    # `_check_bytes` refuses the whole stream for any of them, so every break
    # in this reader is exactly "\n".

    def _bs_skip_indent(self, k: int, col: int, indent: int) -> int:
        """The oracle's `while self.column < indent and self.peek() == ' '`."""
        if k >= len(self.lines):
            return col
        line = self.lines[k]
        while col < indent and col < len(line) and line[col] == " ":
            col += 1
        return col

    def _bs_breaks(self, k: int, col: int, indent: int) -> tuple[int, int, int]:
        """`scan_block_scalar_breaks`: the blank lines at or under `indent`.

        A line is blank only once at most `indent` of its leading spaces have
        been skipped and NOTHING is left before its break. A whitespace-only
        line carrying MORE spaces than that is a content line whose text is
        the surplus spaces — the exact rule `a: |` / `  x` / `   ` turns on.
        """
        breaks = 0
        col = self._bs_skip_indent(k, col, indent)
        while k < len(self.lines) and col >= len(self.lines[k]) and self._line_break_after(k):
            breaks += 1
            k += 1
            col = self._bs_skip_indent(k, 0, indent)
        return breaks, k, col

    def _bs_indentation(self, k: int) -> tuple[int, int, int, int]:
        """`scan_block_scalar_indentation`: leading breaks and the widest run.

        The oracle walks spaces and line breaks together, so the widest run of
        leading spaces it crosses — on a whitespace-only line just as much as
        on the first content line — is what `max()` compares against the
        parent indentation. A whitespace-only line wider than the first
        content line therefore pushes the block's indent PAST that content,
        which is why the oracle then reads an empty scalar and the parser
        raises on the orphaned line.
        """
        breaks = 0
        max_indent = 0
        col = 0
        while k < len(self.lines):
            line = self.lines[k]
            while col < len(line) and line[col] == " ":
                col += 1
                if col > max_indent:
                    max_indent = col
            if col < len(line) or not self._line_break_after(k):
                break
            breaks += 1
            k += 1
            col = 0
        return breaks, max_indent, k, col

    def _block_scalar_body(self, style: str, chomp: str, explicit: int | None,
                           parent_indent: int) -> str:
        folded = style == ">"
        # EQUIVALENT MUTANT (proven by the ported reader's measurement, twice over): the
        # `max(..., 1)` here and the `- 1` below are the oracle's own spelling
        # and are ARITHMETICALLY redundant in this reader, because
        # `parent_indent` is a block mapping's indentation and is never
        # negative. `parent_indent + 1` and `parent_indent + explicit` are the
        # same two numbers -- 0 diffs over 182,170 corpus inputs and 29 probes,
        # as they must be. Kept as the oracle writes them, so the
        # transcription stays line-for-line checkable against
        # `Scanner.scan_block_scalar`.
        min_indent = max(parent_indent + 1, 1)
        k = self.i
        if explicit is not None:
            indent = min_indent + explicit - 1
            breaks, k, col = self._bs_breaks(k, 0, indent)
        else:
            breaks, max_indent, k, col = self._bs_indentation(k)
            indent = max(min_indent, max_indent)
        chunks: list[str] = []
        line_break = ""
        while col == indent and self._bs_has_more(k, col):
            chunks.append("\n" * breaks)
            line = self.lines[k]
            leading_non_space = line[col:col + 1] != " "
            chunks.append(line[col:])
            if self._line_break_after(k):
                line_break = "\n"
                k += 1
                col = 0
            else:
                line_break = ""
                k = len(self.lines)
                col = 0
            breaks, k, col = self._bs_breaks(k, col, indent)
            if col == indent and self._bs_has_more(k, col):
                # The oracle's own folding rule, comment and all: a single
                # break between two lines that both start with content folds
                # to one space, and anything else keeps its break.
                #
                # EQUIVALENT MUTANT (proven by the ported reader's measurement): the
                # `line_break == "\n"` conjunct is unreachable-false here.
                # `line_break` is "" only in the branch above that also sets
                # `k = len(self.lines)`, after which `_bs_breaks` cannot move
                # the column off 0 and `indent` is at least 1, so the test
                # guarding this block is already False and the loop has broken.
                # Dropping it changes nothing over 182,170 corpus inputs and 29
                # probes. Kept because it is the oracle's own condition, and a
                # transcription that quietly simplifies is a transcription
                # nobody can check.
                if (folded and line_break == "\n" and leading_non_space
                        and self.lines[k][col:col + 1] != " "):
                    if not breaks:
                        chunks.append(" ")
                else:
                    chunks.append(line_break)
            else:
                break
        self.i = k
        # Chomp the tail, exactly as the oracle does: clip and keep both put
        # the final break back, and only keep also puts the trailing blank
        # lines back.
        if chomp != "-":
            chunks.append(line_break)
        if chomp == "+":
            chunks.append("\n" * breaks)
        return "".join(chunks)

    def _bs_has_more(self, k: int, col: int) -> bool:
        """The oracle's `self.peek() != '\\0'` at (line, column)."""
        if k >= len(self.lines):
            return False
        if col < len(self.lines[k]):
            return True
        return self._line_break_after(k)

    # -- scalars ------------------------------------------------------------

    def _require_trailing_blank(self, text: str, end: int, lineno: int) -> None:
        rest = _ascii_strip(text[end:])
        if rest and not rest.startswith("#"):
            self.fail("unexpected trailing content %r after a value" % rest, lineno)

    def _scan_key(self, body: str, lineno: int) -> tuple[str, int] | None:
        if body[:1] in ('"', "'"):
            text, end = self._scan_quoted(body, 0, lineno)
            j = end
            while j < len(body) and body[j] == " ":
                j += 1
            if j < len(body) and body[j] == ":" and (j + 1 == len(body) or body[j + 1] == " "):
                return text, j + 1
            return None
        j = 0
        while True:
            k = body.find(":", j)
            if k < 0:
                return None
            if k + 1 == len(body) or body[k + 1] == " ":
                key = body[:k].rstrip(" ")
                if key == "":
                    self.fail("a mapping key is empty", lineno)
                if key[0] in _INDICATOR_START or key.startswith("<<"):
                    self.fail("anchors, aliases, tags, explicit keys, and merge keys are "
                              "refused, and so is every other indicator a plain scalar may "
                              "not open with (%r); a key whose meaning is assembled elsewhere "
                              "in the stream, or that real YAML will not read as a key at "
                              "all, is a key this gate will not follow" % key[0], lineno)
                if '"' in key or "'" in key:
                    self.fail("unexpected quote character inside a plain mapping key", lineno)
                if " #" in key:
                    # ` #` opens a comment, so real YAML ends the scalar there
                    # and this line stops being a mapping entry at all: `k #: v`
                    # is the plain scalar "k" to PyYAML, and a mapping key "k #"
                    # here. Refused rather than re-implemented -- a rendered key
                    # carrying a comment is not a shape any chart needs.
                    self.fail("a plain mapping key may not carry a comment (%r); real YAML ends "
                              "the scalar at the ` #`, so this line is not the mapping entry it "
                              "looks like" % key, lineno)
                resolved = self._resolve_plain(key, lineno)
                if not isinstance(resolved, str):
                    self.fail("non-string mapping key %r is refused" % key, lineno)
                return resolved, k + 1
            j = k + 1

    def _scan_quoted(self, s: str, i: int, lineno: int) -> tuple[str, int]:
        quote = s[i]
        j = i + 1
        buf: list[str] = []
        if quote == "'":
            while j < len(s):
                if s[j] == "'":
                    if j + 1 < len(s) and s[j + 1] == "'":
                        buf.append("'")
                        j += 2
                        continue
                    return "".join(buf), j + 1
                buf.append(s[j])
                j += 1
            self.fail("unterminated single-quoted scalar; a quoted scalar must open and close "
                      "on one line here", lineno)
        while j < len(s):
            ch = s[j]
            if ch == '"':
                return "".join(buf), j + 1
            if ch == "\\":
                j += 1
                if j >= len(s):
                    self.fail("a double-quoted scalar ends with a dangling escape", lineno)
                esc = s[j]
                if esc in _SIMPLE_ESCAPES:
                    buf.append(_SIMPLE_ESCAPES[esc])
                    j += 1
                    continue
                if esc in ("x", "u", "U"):
                    width = {"x": 2, "u": 4, "U": 8}[esc]
                    digits = s[j + 1:j + 1 + width]
                    if len(digits) != width or any(c not in "0123456789abcdefABCDEF" for c in digits):
                        self.fail("malformed \\%s escape in a double-quoted scalar" % esc, lineno)
                    buf.append(chr(int(digits, 16)))
                    j += 1 + width
                    continue
                self.fail("unsupported escape sequence \\%s" % esc, lineno)
            buf.append(ch)
            j += 1
        self.fail("unterminated double-quoted scalar; a quoted scalar must open and close on "
                  "one line here", lineno)
        raise AssertionError("unreachable")  # pragma: no cover

    def _scan_value(self, s: str, i: int, lineno: int, flow: bool) -> tuple[object, int]:
        while i < len(s) and s[i] == " ":
            i += 1
        if i >= len(s) or s[i] == "#":
            return None, len(s)
        ch = s[i]
        if ch == "[":
            return self._flow_sequence(s, i, lineno)
        if ch == "{":
            return self._flow_mapping(s, i, lineno)
        if ch in ('"', "'"):
            return self._scan_quoted(s, i, lineno)
        if ch in _INDICATOR_START or (flow and ch == ":"):
            # `:` opens a legal plain scalar in BLOCK context (`a: :b` is the
            # string ":b" to PyYAML too) and an illegal one inside a flow
            # collection, which is why it is the one position-dependent member.
            self.fail("anchors, aliases, tags, explicit keys, block scalars in this position, "
                      "and every other indicator a plain scalar may not open with are "
                      "refused (%r)" % ch, lineno)
        if flow:
            j = i
            while j < len(s):
                cur = s[j]
                # PyYAML's `scan_plain` ends a plain scalar inside a flow
                # collection at any of `,?[]{}`, and at a `:` followed by a
                # space or one of `,[]{}`. Breaking on a narrower set left
                # `{b: 1 [}` the scalar "1 [" here and a parse error there.
                if cur in ",?[]{}":
                    break
                if cur == ":" and (j + 1 >= len(s) or s[j + 1] in " ,[]{}"):
                    break
                if cur == "#" and j > i and s[j - 1] == " ":
                    break
                j += 1
        else:
            j = len(s)
            k = i
            while k < len(s):
                if s[k] == "#" and (k == i or s[k - 1] == " "):
                    j = k
                    break
                k += 1
        raw = s[i:j].rstrip(" ")
        if raw == "":
            self.fail("empty scalar where a value was expected", lineno)
        if ": " in raw or raw.endswith(":"):
            self.fail("a plain scalar may not contain a mapping indicator (%r)" % raw, lineno)
        if raw == "-" or raw.startswith("- "):
            self.fail("a plain scalar may not open with a block sequence indicator (%r); "
                      "real YAML refuses this too, and refusing it keeps this reader from "
                      "being MORE permissive than the tools that install the render" % raw,
                      lineno)
        return self._resolve_plain(raw, lineno), j

    def _flow_sequence(self, s: str, i: int, lineno: int) -> tuple[list, int]:
        j = i + 1
        items: list = []
        while True:
            while j < len(s) and s[j] == " ":
                j += 1
            if j >= len(s):
                self.fail("unterminated flow sequence; a flow collection must open and close "
                          "on one line here", lineno)
            if s[j] == "]":
                return items, j + 1
            value, j = self._scan_value(s, j, lineno, flow=True)
            items.append(value)
            while j < len(s) and s[j] == " ":
                j += 1
            if j >= len(s):
                self.fail("unterminated flow sequence", lineno)
            if s[j] == ",":
                j += 1
                continue
            if s[j] == "]":
                return items, j + 1
            self.fail("unexpected character %r inside a flow sequence" % s[j], lineno)

    def _flow_mapping(self, s: str, i: int, lineno: int) -> tuple[dict, int]:
        j = i + 1
        out: dict = {}
        while True:
            while j < len(s) and s[j] == " ":
                j += 1
            if j >= len(s):
                self.fail("unterminated flow mapping; a flow collection must open and close "
                          "on one line here", lineno)
            if s[j] == "}":
                return out, j + 1
            if s[j] in ('"', "'"):
                key, j = self._scan_quoted(s, j, lineno)
            else:
                k = j
                while k < len(s) and s[k] not in ":,}]":
                    k += 1
                if k >= len(s) or s[k] != ":":
                    self.fail("flow mapping entry without a value", lineno)
                if k + 1 < len(s) and s[k + 1] not in " ,}]":
                    # Inside a flow collection a colon only ENDS a key when a
                    # space or a flow indicator follows it. PyYAML reads
                    # `{a:1}` as the single plain scalar `a:1` with no value,
                    # and `{a :1}` as `a :1`; this reader used to split both at
                    # the colon and hand back `{a: 1}` -- a mapping the tool
                    # that installs the render never sees. Refused rather than
                    # re-implemented: an empty flow value is not a shape any
                    # Helm render needs.
                    self.fail("a flow mapping key whose colon is glued to the next character "
                              "is refused; real YAML reads %r as one plain scalar with no "
                              "value, not as a key and a value" % s[j:], lineno)
                raw = s[j:k].rstrip(" ")
                if raw == "":
                    self.fail("a mapping key is empty", lineno)
                if raw == "-" or raw.startswith("- ") or any(c in raw for c in "?[{#"):
                    # The same `scan_plain` rule, on the key side: inside a flow
                    # collection a plain scalar ENDS at `?`, `[`, `{` and at a
                    # `#` that opens a comment, and may not open with `- `. A
                    # key scanned straight through them was a key real YAML
                    # never reads (`{1 [: v}`, `{- k: v}`).
                    self.fail("a plain key inside a flow mapping that carries a nested "
                              "collection, an explicit-key indicator, a comment, or a block "
                              "sequence indicator is refused (%r); real YAML ends the key "
                              "there" % raw, lineno)
                if raw[0] in _INDICATOR_START or raw.startswith("<<"):
                    self.fail("anchors, aliases, tags, explicit keys, and merge keys are "
                              "refused, and so is every other indicator a plain scalar may "
                              "not open with (%r)" % raw[0], lineno)
                resolved = self._resolve_plain(raw, lineno)
                if not isinstance(resolved, str):
                    self.fail("non-string mapping key %r is refused" % raw, lineno)
                key = resolved
                j = k
            while j < len(s) and s[j] == " ":
                j += 1
            if j >= len(s) or s[j] != ":":
                self.fail("flow mapping entry without a value", lineno)
            j += 1
            value, j = self._scan_value(s, j, lineno, flow=True)
            if key in out:
                self.fail("duplicate mapping key %r in a flow mapping" % key, lineno)
            out[key] = value
            while j < len(s) and s[j] == " ":
                j += 1
            if j >= len(s):
                self.fail("unterminated flow mapping", lineno)
            if s[j] == ",":
                j += 1
                continue
            if s[j] == "}":
                return out, j + 1
            self.fail("unexpected character %r inside a flow mapping" % s[j], lineno)

    def _resolve_plain(self, raw: str, lineno: int) -> object:
        if raw in _NULL_PLAIN:
            return None
        if raw in _TRUE_PLAIN:
            return True
        if raw in _FALSE_PLAIN:
            return False
        if raw in _AMBIGUOUS_PLAIN:
            self.fail("plain scalar %r resolves to a boolean under YAML 1.1 and to a string "
                      "under YAML 1.2; quote it or write true/false" % raw, lineno)
        if raw == _VALUE_KEY_PLAIN:
            self.fail("the plain scalar %r is refused; it is YAML 1.1's value key, which a "
                      "safe YAML loader REFUSES outright in value position and reads as an "
                      "ordinary string in key position -- quote it to mean the string" % raw,
                      lineno)
        if raw == _MERGE_KEY_PLAIN:
            self.fail("the plain scalar %r is refused; it is YAML 1.1's merge key, which a "
                      "safe YAML loader REFUSES outright in value position -- quote it to "
                      "mean the string" % raw, lineno)
        if _RADIX_RE.fullmatch(raw):
            self.fail("hexadecimal, octal, and binary integer forms are refused; "
                      "implementations disagree about them (%r)" % raw, lineno)
        if _SEXAGESIMAL_RE.fullmatch(raw):
            self.fail("sexagesimal number forms are refused; %r means 60-base arithmetic "
                      "under YAML 1.1 and a string under YAML 1.2" % raw, lineno)
        if _TIMESTAMP_RE.fullmatch(raw):
            self.fail("timestamp scalars are refused; %r is a date/datetime OBJECT under "
                      "YAML 1.1 and a plain string under YAML 1.2 -- quote it to mean the "
                      "string" % raw, lineno)
        if _SPECIAL_FLOAT_RE.fullmatch(raw):
            self.fail("infinity and not-a-number scalars are refused (%r)" % raw, lineno)
        if _EXPONENT_RE.fullmatch(raw):
            self.fail("exponent number forms are refused; %r reads as a float under YAML 1.2 "
                      "and as a string under YAML 1.1" % raw, lineno)
        if "_" in raw and _UNDERSCORE_NUMBER_RE.fullmatch(raw):
            self.fail("digit-group underscores are refused; %r reads as a number under "
                      "YAML 1.1 and as a string under YAML 1.2" % raw, lineno)
        if _INT_RE.fullmatch(raw):
            digits = raw.lstrip("+-")
            if len(digits) > 1 and digits[0] == "0":
                self.fail("an integer with a leading zero is refused; it is octal under "
                          "YAML 1.1 and decimal under YAML 1.2 (%r)" % raw, lineno)
            return int(raw)
        if _FLOAT_RE.fullmatch(raw):
            return float(raw)
        return raw


def parse_documents(text: str, origin: str) -> list[object]:
    """Parse a YAML stream into a list of documents, failing closed."""
    return Reader(text, origin).documents()


# --- Chart facts ------------------------------------------------------------


def _read_mapping(path: Path) -> dict:
    docs = parse_documents(path.read_text(encoding="utf-8"), str(path))
    real = [d for d in docs if d is not None]
    if len(real) != 1 or not isinstance(real[0], dict):
        raise CensusError("%s: expected exactly one mapping document" % path)
    return real[0]


def _require_str(mapping: dict, path: tuple[str, ...], origin: str) -> str:
    value = mapping
    for key in path:
        if not isinstance(value, dict) or key not in value:
            raise CensusError("%s declares no %s" % (origin, ".".join(path)))
        value = value[key]
    if not isinstance(value, str) or value == "":
        raise CensusError("%s.%s is not a non-empty string" % (origin, ".".join(path)))
    return value


class ChartFacts:
    """Every variable fact the expectation needs, and where each comes from."""

    def __init__(self, chart_dir: Path, release: str, namespace: str,
                 peer_instance: str | None = None) -> None:
        chart_yaml = _read_mapping(chart_dir / "Chart.yaml")
        values_yaml = _read_mapping(chart_dir / "values.yaml")
        self.chart_name = _require_str(chart_yaml, ("name",), "chart metadata")
        self.release = release
        self.namespace = namespace
        self.peer_namespace = _require_str(values_yaml, ("ingress", "peerNamespace"), "chart values")
        self.peer_app_name = _require_str(values_yaml, ("ingress", "peerAppName"), "chart values")
        # The peer instance is the ONE fact a caller may state instead of
        # reading it from values: the gate renders once with the instance
        # deliberately overridden, and the census must follow that override
        # exactly rather than be skipped for it.
        self.peer_instance = peer_instance or _require_str(
            values_yaml, ("ingress", "peerInstance"), "chart values")
        port = values_yaml.get("service", {})
        port = port.get("port") if isinstance(port, dict) else None
        if not isinstance(port, int) or isinstance(port, bool):
            raise CensusError("chart values declare no integer service.port")
        self.service_port = port

    def expected_policy(self) -> dict:
        return {
            "apiVersion": POLICY_API_VERSION,
            "kind": POLICY_KIND,
            "spec": {
                "podSelector": {
                    "matchLabels": {
                        "app.kubernetes.io/name": self.chart_name,
                        "app.kubernetes.io/instance": self.release,
                    }
                },
                "policyTypes": list(POLICY_TYPES),
                "ingress": [
                    {
                        "from": [
                            {
                                "namespaceSelector": {
                                    "matchLabels": {
                                        "kubernetes.io/metadata.name": self.peer_namespace,
                                    }
                                },
                                "podSelector": {
                                    "matchLabels": {
                                        "app.kubernetes.io/name": self.peer_app_name,
                                        "app.kubernetes.io/instance": self.peer_instance,
                                    }
                                },
                            }
                        ],
                        "ports": [{"port": self.service_port, "protocol": "TCP"}],
                    }
                ],
                "egress": [],
            },
        }


def _describe(value: object) -> str:
    return repr(value)


# --- What "installable" has to mean -----------------------------------------
#
# THE CLAIM THIS GATE PRINTS IS "N INSTALLABLE OBJECTS". If it counts an
# object Kubernetes will not install, that claim is false in the fatal
# direction. The measured instance the ported reader's differential review
# found: a render carrying a multi-line value in a LABEL censused GREEN --
# four objects, exactly one NetworkPolicy, equal to the pinned expectation --
# while a real API server REFUSES the NetworkPolicy for it and applies the
# ServiceAccount, Service and Deployment anyway, because a partial apply
# reports each object's fate separately. THE WORKLOAD INSTALLS WITHOUT ITS
# DENY while this gate reports everything fine. The reason that shape can ride
# at all is that `metadata.labels` is the one part of the pinned policy whose
# CONTENT the census deliberately does not fix -- which is exactly why the
# block-scalar shadow mutation is written there too.
#
# WHERE THESE RULES COME FROM, AND WHAT THIS REPOSITORY MEASURED. The
# boundaries below were probed from both sides against a live Kubernetes
# v1.36.3 API server (`kubectl apply --dry-run=server`, and `kubectl create
# --dry-run=server` where `apply`'s own last-applied-configuration annotation
# would have confounded a size limit) as part of the ported reader's work in
# the sibling repository. THIS REPOSITORY HAS NOT RE-MEASURED THEM AGAINST A
# CLUSTER and does not claim to have: they are carried here as upstream
# Kubernetes ObjectMeta validation -- the label key/value grammar, the RFC 1123
# subdomain and label name rules, and the annotation size cap -- which are
# properties of the API server, not of either repository's chart. Every rule is
# pinned one input at a time by `test_chart_render_census.py`, so what runs in
# CI here is the rule as written, and a future live re-measurement would be new
# evidence to record here rather than a claim already in hand.
#
#   label VALUE   `` accepted, `a` accepted, `MyValue` accepted, `12345`
#                 accepted, `a_b.c-d` accepted, 63 bytes accepted, 64 bytes
#                 refused, and `-abc`, `abc-`, `.abc`, `-`, `a b`, `a/b`,
#                 `a\nb`, `é` all refused.
#   label KEY     `a` accepted, 63-byte name accepted, 64 refused,
#                 `A_b.c-d` accepted, `example.com/a` accepted, a 253-byte
#                 prefix accepted, 254 refused, and ``, `/a`, `example.com/`,
#                 `a/b/c`, `-a`, `a\nb`, `Example.com/a`, `exa_mple.com/a`
#                 all refused. The prefix is a LOWERCASE DNS subdomain; the
#                 name part is not (uppercase and `_` are legal there).
#   annotations   keys follow the label-key rule exactly (`a/b/c` and a
#                 64-byte name are both refused); values are arbitrary strings
#                 -- `x\ny\n` and a non-ASCII value are both accepted, where
#                 a LABEL refuses each of them, which is what makes
#                 an annotation the right home for a multi-line value -- and
#                 the SUM of every key and value is capped: 262144 bytes
#                 accepted, 262145 refused.
#   metadata.name a lowercase RFC 1123 SUBDOMAIN for NetworkPolicy,
#                 ServiceAccount and Deployment (`a-b.c` accepted, `1abc`
#                 accepted, 253 bytes accepted, 254 refused, `a_b`, `AbC` and
#                 `abc.` refused) and a lowercase RFC 1123 LABEL for Service,
#                 which additionally forbids dots and caps at 63 (`abc` and
#                 `1abc` accepted; `a.b`, `Abc`, `abc-` and 64 bytes refused).
#   selectors     `matchLabels`, a Service's `spec.selector` and a Pod's
#                 `nodeSelector` are validated by the same label key/value
#                 rules, at any depth -- `spec.podSelector.matchLabels`,
#                 `spec.selector` and `spec.template.spec.nodeSelector` each
#                 refused `a\nb` and `a/b/c` on the real server.
#   value TYPES   a label or annotation value that is a YAML number or boolean
#                 is refused by the server before validation even runs ("json:
#                 cannot unmarshal number into Go struct field
#                 ObjectMeta.metadata.labels of type string"), so it is refused
#                 here too.
#
# ONE DELIBERATE OVER-REFUSAL, stated rather than hidden: a label or
# annotation value written as the plain YAML `null` is ACCEPTED by the API
# server, which decodes it into Go's zero string and stores an EMPTY label.
# This gate refuses it. Coercing a value nobody wrote into a value the render
# does not say is exactly the guess every other rule in this file declines to
# make, and refusing is the direction that cannot hide a policy. It is the one
# place the installability check is stricter than the installer, and
# `test_a_null_label_value_is_the_one_deliberate_over_refusal` pins it as such.
#
# WHAT THIS DELIBERATELY DOES NOT DO, stated rather than left to be discovered:
# it does not validate per-kind SPEC schemas. A Deployment with no
# `spec.selector` is refused by the API server and counted installable here.
# That rule is not a small stable regex -- it is the OpenAPI schema of every
# kind, which a stdlib-only gate cannot carry (requirements 1 and 9) -- and it
# is not in the fatal direction either: a malformed Deployment leaves the deny
# installed and the workload absent, which is the safe half. The one object
# whose absence IS fatal, the NetworkPolicy, has its whole spec pinned against
# a literal expectation a few lines below, so its spec cannot be malformed
# without failing the census outright. Namespace EXISTENCE is likewise out of
# scope: it is a property of the cluster, not of the render.

LABEL_VALUE_MAX_BYTES = 63
QUALIFIED_NAME_MAX_BYTES = 63
DNS_SUBDOMAIN_MAX_BYTES = 253
DNS_LABEL_MAX_BYTES = 63
ANNOTATIONS_MAX_BYTES = 262144

# Spelled as literal ASCII ranges for the same reason every other pattern in
# this file is: `\w` and `\d` are Unicode-aware in Python and would admit a
# fullwidth digit the API server refuses.
_LABEL_VALUE_RE = re.compile(r"(?:(?:[A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9])?")
_QUALIFIED_NAME_RE = re.compile(r"(?:[A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9]")
_DNS_LABEL_RE = re.compile(r"[a-z0-9](?:[-a-z0-9]*[a-z0-9])?")
_DNS_SUBDOMAIN_RE = re.compile(r"[a-z0-9](?:[-a-z0-9]*[a-z0-9])?"
                               r"(?:\.[a-z0-9](?:[-a-z0-9]*[a-z0-9])?)*")

# Kinds whose `metadata.name` is a DNS-1123 LABEL rather than a subdomain.
# The inventory above pins the render to four kinds, so this set is complete
# for what this gate can ever see; growing the inventory is the moment to
# re-measure it.
_DNS_LABEL_NAME_KINDS = frozenset({"Service"})

# Mappings that are label maps wherever they appear, at any depth.
_LABEL_MAP_KEYS = ("matchLabels", "nodeSelector")


def _too_long(text: str, ceiling: int) -> bool:
    # Kubernetes counts BYTES, not characters, and says so in its own error
    # text ("must be no more than 63 bytes").
    return len(text.encode("utf-8")) > ceiling


def _label_value_problem(value: object) -> str | None:
    if not isinstance(value, str):
        return ("is %s, not a string; Kubernetes stores label values as strings "
                "and refuses anything else" % _describe(value))
    if _too_long(value, LABEL_VALUE_MAX_BYTES):
        return "is longer than %d bytes" % LABEL_VALUE_MAX_BYTES
    if not _LABEL_VALUE_RE.fullmatch(value):
        return ("is not a valid label value; Kubernetes wants an empty string, "
                "or alphanumerics with `-`, `_` and `.` inside, starting and "
                "ending alphanumeric")
    return None


def _label_key_problem(key: object) -> str | None:
    if not isinstance(key, str):
        return "is %s, not a string" % _describe(key)
    prefix, slash, name = key.rpartition("/")
    if slash:
        if prefix == "":
            return "has an empty prefix before its `/`"
        if "/" in prefix:
            return "carries more than one `/`"
        if _too_long(prefix, DNS_SUBDOMAIN_MAX_BYTES):
            return "has a prefix longer than %d bytes" % DNS_SUBDOMAIN_MAX_BYTES
        if not _DNS_SUBDOMAIN_RE.fullmatch(prefix):
            return ("has a prefix that is not a lowercase DNS subdomain "
                    "(uppercase and `_` are legal in the NAME part, never in "
                    "the prefix)")
    if name == "":
        return "has an empty name part"
    if _too_long(name, QUALIFIED_NAME_MAX_BYTES):
        return "has a name part longer than %d bytes" % QUALIFIED_NAME_MAX_BYTES
    if not _QUALIFIED_NAME_RE.fullmatch(name):
        return ("has a name part that is not a valid qualified name; "
                "Kubernetes wants alphanumerics with `-`, `_` and `.` inside, "
                "starting and ending alphanumeric")
    return None


def _uninstallable(where: str, detail: str) -> CensusError:
    return CensusError(
        "%s: %s. This gate's claim is that the render carries N INSTALLABLE "
        "objects, so an object a real API server refuses is not one of them -- "
        "and a render whose NetworkPolicy is refused while its workload applies "
        "installs the workload WITHOUT its deny." % (where, detail))


def _check_label_map(mapping: object, where: str, what: str) -> None:
    if not isinstance(mapping, dict):
        raise _uninstallable(where, "%s is %s, not a mapping" % (what, _describe(mapping)))
    for key, value in mapping.items():
        problem = _label_key_problem(key)
        if problem is not None:
            raise _uninstallable(where, "the %s key %s %s" % (what, _describe(key), problem))
        problem = _label_value_problem(value)
        if problem is not None:
            raise _uninstallable(
                where, "the %s value for %s %s" % (what, _describe(key), problem))


def _check_annotations(mapping: object, where: str) -> None:
    if not isinstance(mapping, dict):
        raise _uninstallable(where, "metadata.annotations is %s, not a mapping"
                             % _describe(mapping))
    total = 0
    for key, value in mapping.items():
        problem = _label_key_problem(key)
        if problem is not None:
            raise _uninstallable(
                where, "the metadata.annotations key %s %s" % (_describe(key), problem))
        if not isinstance(value, str):
            raise _uninstallable(
                where, "the metadata.annotations value for %s is %s, not a string"
                % (_describe(key), _describe(value)))
        total += len(key.encode("utf-8")) + len(value.encode("utf-8"))
    if total > ANNOTATIONS_MAX_BYTES:
        raise _uninstallable(
            where, "its annotations total %d bytes; Kubernetes caps them at %d"
            % (total, ANNOTATIONS_MAX_BYTES))


def _check_metadata_maps(metadata: dict, where: str) -> None:
    if "labels" in metadata:
        _check_label_map(metadata["labels"], where, "metadata.labels")
    if "annotations" in metadata:
        _check_annotations(metadata["annotations"], where)


def _walk_installable(node: object, where: str) -> None:
    """Every label map in the object, at any depth.

    ObjectMeta is checked and then NOT descended into: a label whose KEY
    happens to be spelled `matchLabels` is an ordinary label, not a selector,
    and descending would refuse a render Kubernetes installs happily.
    """
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "metadata" and isinstance(value, dict):
                _check_metadata_maps(value, where)
                continue
            if key in _LABEL_MAP_KEYS:
                _check_label_map(value, where, key)
                continue
            _walk_installable(value, where)
    elif isinstance(node, list):
        for item in node:
            _walk_installable(item, where)


def check_installable(objects: list[dict]) -> None:
    """Refuse any object a real Kubernetes API server would refuse."""
    for index, obj in enumerate(objects, start=1):
        kind = obj.get("kind")
        where = "object %d (%s)" % (index, kind if isinstance(kind, str) else "?")
        metadata = obj.get("metadata")
        if not isinstance(metadata, dict):
            raise _uninstallable(where, "carries no metadata mapping, so it has no name")
        name = metadata.get("name")
        if not isinstance(name, str) or name == "":
            raise _uninstallable(where, "declares no non-empty string metadata.name")
        where = "object %d (%s %s)" % (index, kind, name)
        if kind in _DNS_LABEL_NAME_KINDS:
            if _too_long(name, DNS_LABEL_MAX_BYTES) or not _DNS_LABEL_RE.fullmatch(name):
                raise _uninstallable(
                    where, "is named %s; a %s name must be a lowercase RFC 1123 LABEL "
                    "of at most %d bytes -- lowercase alphanumerics and `-`, no dots"
                    % (_describe(name), kind, DNS_LABEL_MAX_BYTES))
        elif _too_long(name, DNS_SUBDOMAIN_MAX_BYTES) or not _DNS_SUBDOMAIN_RE.fullmatch(name):
            raise _uninstallable(
                where, "is named %s; a name must be a lowercase RFC 1123 subdomain of "
                "at most %d bytes" % (_describe(name), DNS_SUBDOMAIN_MAX_BYTES))
        namespace = metadata.get("namespace")
        if namespace is not None:
            if (not isinstance(namespace, str) or namespace == ""
                    or _too_long(namespace, DNS_LABEL_MAX_BYTES)
                    or not _DNS_LABEL_RE.fullmatch(namespace)):
                raise _uninstallable(
                    where, "renders into namespace %s; a namespace name must be a "
                    "lowercase RFC 1123 label of at most %d bytes, so no such namespace "
                    "can ever exist" % (_describe(namespace), DNS_LABEL_MAX_BYTES))
        if kind == "Service":
            spec = obj.get("spec")
            if isinstance(spec, dict) and "selector" in spec:
                _check_label_map(spec["selector"], where, "spec.selector")
        _walk_installable(obj, where)


# --- Census -----------------------------------------------------------------


def flatten(documents: list[object]) -> list[dict]:
    """Return every installable object, list wrappers deliberately unwrapped."""
    out: list[dict] = []
    for index, doc in enumerate(documents, start=1):
        _flatten_one(doc, out, depth=0, where="document %d" % index)
    return out


def _flatten_one(doc: object, out: list[dict], depth: int, where: str) -> None:
    if doc is None:
        return
    if not isinstance(doc, dict):
        raise CensusError("%s is not a mapping (%s); a render this gate cannot read is a "
                          "render it refuses" % (where, _describe(doc)))
    kind = doc.get("kind")
    if not isinstance(kind, str) or kind == "":
        raise CensusError("%s declares no string `kind`; every installable object must say "
                          "what it is" % where)
    if kind == "List" or kind.endswith("List"):
        if depth >= MAX_WRAPPER_DEPTH:
            raise CensusError("%s nests list wrappers more than %d deep; refusing"
                              % (where, MAX_WRAPPER_DEPTH))
        extra = set(doc) - {"apiVersion", "kind", "items", "metadata"}
        if extra:
            raise CensusError("%s is a %s wrapper carrying unexpected keys %s; a wrapper this "
                              "gate cannot fully account for is refused"
                              % (where, kind, sorted(extra)))
        items = doc.get("items")
        if not isinstance(items, list):
            raise CensusError("%s is a %s wrapper whose `items` is %s, not a sequence; a "
                              "wrapper whose contents cannot be inspected is refused"
                              % (where, kind, _describe(items)))
        for position, item in enumerate(items, start=1):
            _flatten_one(item, out, depth + 1, "%s -> %s item %d" % (where, kind, position))
        return
    out.append(doc)


# --- Binding the policy to the workload it governs ---------------------------
#
# THE TWO HALVES OF A NETWORKPOLICY ARE INDEPENDENT, AND ONLY ONE OF THEM IS
# PINNED ABOVE. `spec.podSelector` says WHICH Pods the policy governs;
# `policyTypes` plus the rule lists say WHAT those Pods may do. Every
# assertion in `census` reads the policy alone, so every one of them is
# satisfied by a policy that governs NOTHING: retarget the Deployment's
# Pod-template labels, leave the policy byte-identical, and Kubernetes matches
# it against zero Pods. Those Pods then run with full outbound access. `helm
# lint` sees valid YAML, `chart-ingress-pin.sh` inspects `spec.ingress` by
# construction, and the text pin in `chart-egress-pin.sh` reads a policy whose
# text is exactly right. The manifest still says "default deny". It denies
# nothing.
#
# THE FOUR DIRECTIONS THIS HAS TO COVER, because a check written for only the
# one named above would be half a check:
#
#   1. the workload moves and the policy stays -- the Pod-template labels are
#      retargeted, or the whole Deployment moves to another namespace (a
#      NetworkPolicy governs Pods in its OWN namespace only, so a namespace
#      move is the same zero-Pod outcome by a different road);
#   2. the policy moves and the workload stays -- the selector is rewritten to
#      name something else. The pinned-object comparison in `census` also
#      catches this today, and deliberately so: two independent derivations of
#      the same fact is the point, not duplication. The binding assertion is
#      derived from the RENDERED WORKLOAD; the pinned object is derived from
#      CONSTANTS. Either one alone would be a single point of failure;
#   3. the selector matches the workload PLUS something unintended -- dropping
#      `app.kubernetes.io/instance` still matches these Pods and additionally
#      governs every other release of this chart in the namespace. Handled by
#      requiring both `WORKLOAD_IDENTITY_KEYS`, not by the match test, which
#      passes;
#   4. the Deployment stops matching its OWN template -- `spec.selector` and
#      `spec.template.metadata.labels` disagree. Kubernetes refuses such a
#      Deployment outright, so the render installs no Pods at all, and a
#      policy proven to bind zero Pods has proven nothing.
#
# THE EMPTY SELECTOR IS REFUSED, DELIBERATELY, and it is worth stating exactly
# why because the naive reading points the other way. In Kubernetes,
# `podSelector: {}` selects ALL Pods in the namespace, so for the EGRESS half
# it is strictly more restrictive than the pinned selector -- it denies more.
# It is refused anyway, for three reasons, in order of weight:
#
#   a. IT WOULD MAKE THIS ASSERTION VACUOUS. An empty selector matches this
#      workload for exactly the same reason it matches everything, so it
#      satisfies a binding test no matter WHAT the Deployment's labels say.
#      Accept it and the drift in direction (1) -- the whole reason this code
#      exists -- becomes undetectable again by simply emptying the selector.
#      A guard that an input can switch off is not a guard;
#   b. THE OTHER HALF OF THIS POLICY IS AN ALLOW-LIST. The same object carries
#      `policyTypes: [Ingress, Egress]` and one ingress rule admitting exactly
#      one peer. Widening the selector to the namespace applies THAT rule to
#      every co-tenant Pod as well -- a real change to workloads nobody
#      reviewed, in a namespace this chart does not own;
#   c. FAIL-CLOSED DOCTRINE (AGENTS.md requirement 4). The narrow selector is
#      the reviewed state. A widening that happens to be safe today for one of
#      the two policy types is still a change nobody reviewed, and this gate's
#      job is to make a human read it.
#
# `matchExpressions` is refused on the same principle rather than the same
# reasoning: this module does not implement set-based selector semantics, so a
# render using them is REFUSED with the reason named, never evaluated by
# guesswork. That is the rule every other refusal in this file follows.
#
# DELIBERATELY OUT OF SCOPE, so a later reader does not mistake silence for
# coverage: the Service's `spec.selector` is not checked against the workload
# here. A Service pointing at the wrong Pods is an availability defect, not an
# egress one, and this gate is the egress deny's. Adding it would be a
# separate, deliberate widening of this file's remit.


def _label_map(value: object, where: str) -> dict:
    """A mapping of string labels to string values, or a refusal."""
    if not isinstance(value, dict):
        raise CensusError("%s is %s, not a mapping of labels" % (where, _describe(value)))
    for key, entry in value.items():
        if not isinstance(key, str) or not isinstance(entry, str):
            raise CensusError("%s carries the entry %s: %s, which is not a string label; a "
                              "label this gate cannot compare is a label it refuses"
                              % (where, _describe(key), _describe(entry)))
    return value


def _mapping_at(obj: object, path: tuple[str, ...], where: str) -> dict:
    node = obj
    for key in path:
        if not isinstance(node, dict) or key not in node:
            raise CensusError("%s declares no %s" % (where, ".".join(path)))
        node = node[key]
    if not isinstance(node, dict):
        raise CensusError("%s.%s is %s, not a mapping"
                          % (where, ".".join(path), _describe(node)))
    return node


def _match_labels_of(selector: dict, where: str) -> dict:
    """The ONE selector shape this gate evaluates; everything else is refused."""
    if sorted(selector) != ["matchLabels"]:
        raise CensusError(
            "%s is %s; exactly one key -- matchLabels -- is accepted here. An EMPTY selector "
            "selects every Pod in the namespace rather than this workload: it would satisfy a "
            "binding test for the same reason it satisfies everything, which would make this "
            "assertion vacuous on exactly the drift it exists to catch, and it applies this "
            "policy's ingress allow-list to co-tenant Pods nobody reviewed. matchExpressions "
            "is set-based selection this module does not evaluate, so it is refused rather "
            "than guessed at." % (where, _describe(selector)))
    labels = _label_map(selector["matchLabels"], "%s.matchLabels" % where)
    if not labels:
        raise CensusError(
            "%s.matchLabels is empty, which selects every Pod in the namespace exactly as an "
            "empty selector does; an always-true selector is not a binding." % where)
    return labels


def _unsatisfied(selector: dict, labels: dict) -> list:
    """Kubernetes matchLabels semantics: every pair must be present and equal."""
    return sorted("%s=%s" % (key, value) for key, value in selector.items()
                  if labels.get(key) != value)


def bind_policy_to_workload(objects: list[dict], policy: dict) -> dict:
    """Prove the policy SELECTS the workload it is written to govern.

    Read the block comment above for why each refusal is where it is. Both
    inputs come from the render; nothing here is read out of the chart's own
    templates, so this assertion cannot be satisfied by a template that simply
    renders whatever it likes.
    """
    workloads = [o for o in objects if o.get("kind") == WORKLOAD_KIND]
    if len(workloads) != 1:
        raise CensusError(
            "the complete render carries %d %s objects; exactly one is required. A policy "
            "binds to A workload, and this gate has to know which one -- two workloads "
            "sharing the canonical labels is how a selector proves nothing while looking "
            "exact." % (len(workloads), WORKLOAD_KIND))
    workload = workloads[0]

    policy_namespace = _mapping_at(policy, ("metadata",), "the policy").get("namespace")
    workload_namespace = _mapping_at(workload, ("metadata",), "the workload").get("namespace")
    if workload_namespace != policy_namespace:
        raise CensusError(
            "the workload renders into namespace %s while the policy renders into %s. A "
            "NetworkPolicy governs Pods in its OWN namespace only, so a workload that moves "
            "away from its policy keeps every other gate green and loses its deny entirely."
            % (_describe(workload_namespace), _describe(policy_namespace)))

    pod_labels = _label_map(
        _mapping_at(workload, ("spec", "template", "metadata", "labels"), "the workload"),
        "the workload's Pod template labels")
    if not pod_labels:
        raise CensusError(
            "the workload's Pod template carries no labels at all, so no selector can bind "
            "its Pods and the deny has nothing to attach to.")

    workload_selector = _match_labels_of(
        _mapping_at(workload, ("spec", "selector"), "the workload"),
        "the workload's own selector")
    detached = _unsatisfied(workload_selector, pod_labels)
    if detached:
        raise CensusError(
            "the workload's own selector requires %s, which its Pod template does not carry. "
            "Kubernetes REFUSES a Deployment whose selector does not match its template, so "
            "this render creates no Pods at all -- and a deny proven over zero Pods is not a "
            "proof." % _describe(detached))

    pod_selector = _match_labels_of(
        _mapping_at(policy, ("spec", "podSelector"), "the policy"),
        "the policy's podSelector")
    unnamed = [key for key in WORKLOAD_IDENTITY_KEYS if key not in pod_selector]
    if unnamed:
        raise CensusError(
            "the policy's podSelector omits %s. Both identity labels are required: the name "
            "alone is carried by every release of this chart in the namespace, so a selector "
            "without the instance still matches THIS workload while also governing Pods "
            "nobody reviewed." % _describe(unnamed))

    unsatisfied = _unsatisfied(pod_selector, pod_labels)
    if unsatisfied:
        raise CensusError(
            "the policy's podSelector requires %s, which this render's Pod template labels "
            "%s do not satisfy, so the policy selects ZERO of this workload's Pods. A "
            "NetworkPolicy that selects no Pod governs nothing: those Pods run with FULL "
            "outbound access while the manifest still reads default deny, and every pin over "
            "the policy's own text stays green because that text is untouched."
            % (_describe(unsatisfied), _describe(dict(sorted(pod_labels.items())))))

    return {"workload": workload, "pod_labels": pod_labels, "selector": pod_selector}


def census(text: str, facts: ChartFacts, origin: str = "<render>") -> dict:
    """Assert the whole render carries exactly one, exactly pinned, policy."""
    objects = flatten(parse_documents(text, origin))

    # Before anything is COUNTED, everything counted must be installable: the
    # sentence this gate prints is "N installable objects", and the ported reader's
    # differential review measured a render where that sentence was false in the
    # fatal direction. See "What `installable` has to mean" above.
    check_installable(objects)

    policies = [o for o in objects if o.get("kind") == POLICY_KIND]
    if len(policies) != 1:
        names = [o.get("metadata", {}).get("name") if isinstance(o.get("metadata"), dict) else None
                 for o in policies]
        raise CensusError(
            "the complete render carries %d NetworkPolicy objects (%s); exactly one is "
            "required. NetworkPolicy allowances are additive, so a second policy grants what "
            "the first one denies." % (len(policies), names))
    policy = policies[0]

    inventory = sorted((str(o.get("apiVersion")), str(o.get("kind"))) for o in objects)
    if inventory != sorted(EXPECTED_INVENTORY):
        raise CensusError(
            "the complete render's object inventory is not the pinned one.\nexpected:\n%s\n\n"
            "rendered:\n%s\n\nAdding a document to this chart is a deliberate edit of "
            "EXPECTED_INVENTORY in scripts/ci/chart_render_census.py, so a reviewer reads what "
            "the new document is -- including any policy written under a CNI's own kind."
            % ("\n".join("  %s %s" % pair for pair in sorted(EXPECTED_INVENTORY)),
               "\n".join("  %s %s" % pair for pair in inventory)))

    expected = facts.expected_policy()

    if policy.get("apiVersion") != expected["apiVersion"]:
        raise CensusError("the policy declares apiVersion %s; %s is pinned"
                          % (_describe(policy.get("apiVersion")), expected["apiVersion"]))

    metadata = policy.get("metadata")
    if not isinstance(metadata, dict):
        raise CensusError("the policy carries no metadata mapping")
    if sorted(metadata) != sorted(POLICY_METADATA_KEYS):
        raise CensusError("the policy's metadata keys are %s; exactly %s are pinned"
                          % (sorted(metadata), sorted(POLICY_METADATA_KEYS)))
    expected_name = POLICY_NAME_PREFIX + facts.chart_name
    if metadata.get("name") != expected_name:
        raise CensusError("the policy is named %s; %s is pinned"
                          % (_describe(metadata.get("name")), expected_name))
    if metadata.get("namespace") != facts.namespace:
        raise CensusError("the policy renders into namespace %s; this gate rendered with %s"
                          % (_describe(metadata.get("namespace")), facts.namespace))

    if sorted(policy) != sorted(("apiVersion", "kind", "metadata", "spec")):
        raise CensusError("the policy's top-level keys are %s; exactly apiVersion, kind, "
                          "metadata, spec are pinned" % sorted(policy))

    spec = policy.get("spec")
    if not isinstance(spec, dict):
        raise CensusError("the policy carries no spec mapping")
    if sorted(spec) != sorted(POLICY_SPEC_KEYS):
        raise CensusError("the policy's spec keys are %s; exactly %s are pinned. An unpinned "
                          "spec key is a field nobody reviewed."
                          % (sorted(spec), sorted(POLICY_SPEC_KEYS)))

    # Each half stated on its own, so a failure says which promise broke.
    if spec["podSelector"] != expected["spec"]["podSelector"]:
        raise CensusError("the policy's podSelector is %s; %s is pinned. A policy binds only "
                          "the Pods it selects, so a wrong or empty selector leaves this "
                          "workload with full outbound access while the manifest still reads "
                          "default deny."
                          % (_describe(spec["podSelector"]), _describe(expected["spec"]["podSelector"])))
    if spec["policyTypes"] != expected["spec"]["policyTypes"]:
        raise CensusError("the policy's policyTypes are %s; %s are pinned"
                          % (_describe(spec["policyTypes"]), _describe(expected["spec"]["policyTypes"])))
    if "Egress" not in spec["policyTypes"]:
        raise CensusError("the policy does not declare the Egress policy type, so Kubernetes "
                          "applies no egress rule at all and an empty egress list restricts "
                          "nothing")
    if not isinstance(spec["egress"], list) or spec["egress"] != []:
        raise CensusError("the policy's egress is %s; an exactly empty list is pinned. An "
                          "empty mapping, a single empty rule, or any rule at all is an "
                          "ALLOWANCE -- the emptiest-looking rule is the widest one there is."
                          % _describe(spec["egress"]))
    if spec["ingress"] != expected["spec"]["ingress"]:
        raise CensusError("the policy's ingress is not the one rule the chart values declare."
                          "\nexpected:\n%s\n\nrendered:\n%s"
                          % (_describe(expected["spec"]["ingress"]), _describe(spec["ingress"])))

    # And the whole object at once, so nothing above can drift out of step.
    actual = {
        "apiVersion": policy["apiVersion"],
        "kind": policy["kind"],
        "spec": spec,
    }
    if actual != expected:
        raise CensusError("the policy object does not equal the pinned expectation.\n"
                          "expected:\n%s\n\nrendered:\n%s" % (_describe(expected), _describe(actual)))

    # Everything above proves what the policy SAYS, and every one of those
    # assertions is satisfied by a policy that governs nothing. This last one
    # proves what it POINTS AT.
    binding = bind_policy_to_workload(objects, policy)

    return {"objects": len(objects), "policy": policy, "workload": binding["workload"]}


# --- Hostile mutations ------------------------------------------------------
#
# Every rejection path above is proven able to fire, against the REAL render,
# before this gate is allowed to pass. A guard that cannot fail is not a
# guard. Each entry rewrites the render into something a chart could really
# emit -- or into something no reader should accept -- and the census must
# refuse it.

_ALLOW_ALL_TAIL = """\
  podSelector: {}
  policyTypes: [Egress]
  egress: [{}]
"""

_SHADOW_SPACED = """\
apiVersion : networking.k8s.io/v1
kind : NetworkPolicy
metadata :
  name : shadow-allow-all
  namespace : shadow
spec :
  podSelector : {}
  policyTypes : [Egress]
  egress : [{}]
"""

_SHADOW_DOUBLE_QUOTED = """\
"apiVersion": "networking.k8s.io/v1"
"kind": "NetworkPolicy"
"metadata":
  "name": "shadow-allow-all"
  "namespace": "shadow"
"spec":
  "podSelector": {}
  "policyTypes": ["Egress"]
  "egress": [{}]
"""

_SHADOW_SINGLE_QUOTED = """\
'apiVersion': 'networking.k8s.io/v1'
'kind': 'NetworkPolicy'
'metadata':
  'name': 'shadow-allow-all'
  'namespace': 'shadow'
'spec':
  'podSelector': {}
  'policyTypes': ['Egress']
  'egress': [{}]
"""

# `\x6b` is `k` and `\x4e` is `N`: the key and its value only become `kind`
# and `NetworkPolicy` once the escapes are resolved, which is exactly what
# "canonical key normalisation" has to mean.
_SHADOW_ESCAPED = r"""apiVersion: networking.k8s.io/v1
"\x6bind": "\x4eetworkPolicy"
metadata:
  name: shadow-allow-all
  namespace: shadow
spec:
  podSelector: {}
  policyTypes: [Egress]
  egress: [{}]
"""

_SHADOW_FLOW = ("{apiVersion: networking.k8s.io/v1, kind: NetworkPolicy, "
                "metadata: {name: shadow-allow-all, namespace: shadow}, "
                "spec: {podSelector: {}, policyTypes: [Egress], egress: [{}]}}\n")

_SHADOW_LITERAL_KIND = """\
apiVersion: networking.k8s.io/v1
kind: |-
  NetworkPolicy
metadata:
  name: shadow-allow-all
  namespace: shadow
spec:
""" + _ALLOW_ALL_TAIL

_SHADOW_FOLDED_KIND = """\
apiVersion: networking.k8s.io/v1
kind: >-
  NetworkPolicy
metadata:
  name: shadow-allow-all
  namespace: shadow
spec:
""" + _ALLOW_ALL_TAIL

_SHADOW_GENERIC_LIST = """\
apiVersion: v1
kind: List
items:
  - apiVersion: networking.k8s.io/v1
    kind: NetworkPolicy
    metadata:
      name: shadow-allow-all
      namespace: shadow
    spec:
      podSelector: {}
      policyTypes: [Egress]
      egress: [{}]
"""

_SHADOW_TYPED_LIST = """\
apiVersion: networking.k8s.io/v1
kind: NetworkPolicyList
items:
  - apiVersion: networking.k8s.io/v1
    kind: NetworkPolicy
    metadata:
      name: shadow-allow-all
      namespace: shadow
    spec:
      podSelector: {}
      policyTypes: [Egress]
      egress: [{}]
"""

_SHADOW_NESTED_LIST = """\
apiVersion: v1
kind: List
items:
  - apiVersion: v1
    kind: List
    items:
      - apiVersion: networking.k8s.io/v1
        kind: NetworkPolicy
        metadata:
          name: shadow-allow-all
          namespace: shadow
        spec:
          podSelector: {}
          policyTypes: [Egress]
          egress: [{}]
"""

_SHADOW_OPAQUE_LIST = """\
apiVersion: v1
kind: List
items: shadow-allow-all
"""

_SHADOW_FOREIGN_KIND = """\
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: shadow-allow-all
  namespace: shadow
spec:
  endpointSelector: {}
  egress:
    - toEntities:
        - all
"""

_SHADOW_CONFIGMAP = """\
apiVersion: v1
kind: ConfigMap
metadata:
  name: shadow-config
  namespace: shadow
data:
  shadow: enabled
"""

_SHADOW_ANCHORED = """\
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: shadow-allow-all
  namespace: shadow
spec: &wide
  podSelector: {}
  policyTypes: [Egress]
  egress: [{}]
"""

_SHADOW_MERGE_KEY = """\
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: shadow-allow-all
  namespace: shadow
spec:
  <<: *wide
  egress: [{}]
"""

_SHADOW_TAGGED = """\
apiVersion: networking.k8s.io/v1
kind: !!str NetworkPolicy
metadata:
  name: shadow-allow-all
  namespace: shadow
spec:
""" + _ALLOW_ALL_TAIL

_SHADOW_TAB_INDENTED = (
    "apiVersion: networking.k8s.io/v1\n"
    "kind: NetworkPolicy\n"
    "metadata:\n"
    "\tname: shadow-allow-all\n"
    "spec:\n"
    "\tpodSelector: {}\n"
    "\tpolicyTypes: [Egress]\n"
    "\tegress: [{}]\n"
)

# A BOM in front of `kind` is the whole trick: PyYAML and the spec strip a
# leading one, so THEY see the key `kind`, and a reader that keeps it sees a
# different key and stops recognising the document as a policy at all.
_SHADOW_BOM_PREFIXED = (
    "\ufeff"
    "apiVersion: networking.k8s.io/v1\n"
    "kind: NetworkPolicy\n"
    "metadata:\n"
    "  name: shadow-allow-all\n"
    "  namespace: shadow\n"
    "spec:\n"
) + _ALLOW_ALL_TAIL

# `1_000` is the integer 1000 under YAML 1.1 and the string "1_000" under
# YAML 1.2; a shadow policy that carries one is a document two readers do not
# agree about, so this reader refuses to be either of them.
_SHADOW_UNDERSCORE_NUMBER = """\
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: shadow-allow-all
  namespace: shadow
  generation: 1_000
spec:
""" + _ALLOW_ALL_TAIL

# A YAML 1.1 timestamp is a date/datetime OBJECT to the reader that installs
# the render and a plain string to a YAML 1.2 one. `creationTimestamp` is a
# field every Kubernetes object really carries, so this is the shape a shadow
# policy would wear without looking odd at all.
_SHADOW_TIMESTAMP = """\
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: shadow-allow-all
  namespace: shadow
  creationTimestamp: 2026-08-20T10:30:00Z
spec:
""" + _ALLOW_ALL_TAIL

# `=` is YAML 1.1's value key: a safe YAML loader REFUSES the document that
# carries one in value position, where this reader used to hand back the
# string "=" and read on. A gate that reads a document the installer will not
# read is a gate reporting on something else -- and "will not read" is rarely
# "installs nothing": measured on Kubernetes v1.36.3, `kubectl apply` on this
# render creates the four objects it could read and THEN exits 1 on the shadow,
# leaving the cluster half-changed.
_SHADOW_VALUE_KEY = """\
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: shadow-allow-all
  namespace: shadow
  labels:
    shadow-marker: =
spec:
""" + _ALLOW_ALL_TAIL


# The eight constructs the ported reader's differential review and the author's own hunt
# measured, each written into a shadow policy the way a chart could really emit
# it. Every one of them is a shape where this reader and the reader that
# INSTALLS the render used to disagree -- about how many lines the document
# has, about whether the stream is readable at all, or about what a scalar
# means -- and a gate that reads a different document than the installer is a
# gate reporting on something else.
_SHADOW_UNICODE_LINE_BREAK = (
    "apiVersion: networking.k8s.io/v1\n"
    "kind: NetworkPolicy\n"
    "metadata:\n"
    "  name: shadow-allow-all\n"
    "  namespace: shadow\n"
    "  labels:\n"
    "    shadow-marker: a\u2028b\n"
    "spec:\n"
) + _ALLOW_ALL_TAIL

_SHADOW_C1_CONTROL = (
    "apiVersion: networking.k8s.io/v1\n"
    "kind: NetworkPolicy\n"
    "metadata:\n"
    "  name: shadow-allow-all\n"
    "  namespace: shadow\n"
    "  labels:\n"
    "    shadow-marker: a\u009fb\n"
    "spec:\n"
) + _ALLOW_ALL_TAIL

# U+FFFE is valid UTF-8 (`EF BF BE`) but is outside YAML 1.2.2's printable
# set. Put it in a comment so this mutation proves the pre-parse stream guard
# itself, independent of policy semantics or scalar resolution.
_SHADOW_YAML_FORBIDDEN_CODE_POINT = (
    "# raw YAML-forbidden code point: \ufffe\n"
) + _SHADOW_SPACED

_SHADOW_FLOW_GLUED_COLON = """\
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: shadow-allow-all
  namespace: shadow
  labels: {shadow-marker:enabled}
spec:
""" + _ALLOW_ALL_TAIL

_SHADOW_FLOW_NESTED_INDICATOR = """\
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: shadow-allow-all
  namespace: shadow
  labels: {shadow-marker: enabled [}
spec:
""" + _ALLOW_ALL_TAIL

_SHADOW_INDICATOR_LEADING_KEY = """\
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: shadow-allow-all
  namespace: shadow
  labels:
    @shadow-marker: enabled
spec:
""" + _ALLOW_ALL_TAIL

_SHADOW_COMMENTED_KEY = """\
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: shadow-allow-all
  namespace: shadow
  labels:
    shadow-marker #hidden: enabled
spec:
""" + _ALLOW_ALL_TAIL

_SHADOW_MERGE_KEY_SCALAR = """\
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: shadow-allow-all
  namespace: shadow
  labels:
    shadow-marker: <<
spec:
""" + _ALLOW_ALL_TAIL

_SHADOW_UNDERSCORED_SEXAGESIMAL = """\
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: shadow-allow-all
  namespace: shadow
  generation: 1_:0
spec:
""" + _ALLOW_ALL_TAIL

# The two classes below are about what happens ACROSS a line break, so no
# newline-free corpus alphabet can reach either of them.
#
# A document nobody spelled. `null` is a whole, legal top-level document; the
# reader used to end it wherever the next line was not more indented, and start
# a SECOND document there -- so the wrapper below became a document of its own
# although the stream never spelled a `---` in front of it. The wrapper carries
# no items, so the census counted the same four objects and passed, while
# PyYAML 6.0.3 refuses this stream outright. What the INSTALLER does is worse
# than a refusal, and was measured on Kubernetes v1.36.3 rather than assumed:
# `kubectl apply` on this exact render CREATES all four objects and only THEN
# exits 1 ("error converting YAML to JSON: yaml: line 3: mapping values are not
# allowed in this context") -- a PARTIAL APPLY out of a file the census
# reported GREEN on, which leaves a cluster half-changed and a reviewer with no
# signal at all. Put a policy in those `items` and the same trick is how a
# second document appears where a reviewer counted one.
_SHADOW_UNSPELLED_DOCUMENT = """\
null
apiVersion: v1
kind: List
items: []
"""

# A block scalar that swallows the line after it. The block's indentation is
# set by the WIDEST run of leading whitespace the oracle crosses on its way to
# the first content line -- a whitespace-only line included -- so the seven
# spaces below push the block's indent past `shadow-marker` and PyYAML 6.0.3
# reads an EMPTY scalar and then raises on the orphaned line. This reader used
# to call every all-space line blank whatever its width, detect the indent from
# the first non-blank line, and read `shadow-marker` as block content: green
# gate, unloadable render. Written under `metadata.labels`, the one part of the
# pinned policy whose CONTENT the census does not fix, so the mutation reaches
# the reader rather than tripping a different assertion first.
_SHADOW_BLOCK_SCALAR_NOTE = [
    "    shadow-note: |",
    "       ",
    "      shadow-marker",
]

# the ported reader's differential review measured the first
# CENSUS-VS-CLUSTER gap, and it ran in the fatal direction. The four shadows below are that class, each one
# a render the PRE-REPAIR census reported GREEN on -- "4 installable objects,
# exactly one NetworkPolicy, equal to the pinned expectation" -- and a real
# v1.36.3 API server refuses an object out of. Written under `metadata`, the
# part of the render the census pins least, exactly where the block-scalar
# shadow rides.
#
# The first is the one that is FATAL rather than merely false: a multi-line
# value in a LABEL of the pinned policy. `kubectl apply` creates the
# ServiceAccount, the Service and the Deployment and rejects the NetworkPolicy
# alone, so the workload installs WITHOUT ITS DENY while the gate reports
# everything fine.
_SHADOW_UNINSTALLABLE_LABEL_VALUE = [
    "    shadow-note: |",
    "      first",
    "",
    "       indented",
    "       ",
    "      last",
]

# A label KEY carrying a second `/`. The API server refuses the object; this
# reader read the key happily, because a key is only ever matched here, never
# validated.
_SHADOW_UNINSTALLABLE_LABEL_KEY = [
    "    shadow.example/marker/extra: enabled",
]

# And the same class on an object the census counts but does not pin: a name
# no Kubernetes object may carry, and an annotation key no Kubernetes object
# may carry. Neither is fatal on its own -- a refused ServiceAccount leaves the
# deny installed -- but "N INSTALLABLE objects" is a false sentence either way,
# and a census that only checks the objects it already pins is checking the
# wrong half.
_SHADOW_UNINSTALLABLE_NAME_SUFFIX = "_shadow"

_SHADOW_UNINSTALLABLE_ANNOTATION_KEY = [
    "  annotations:",
    "    shadow.example/marker/extra: enabled",
]


def _split(text: str) -> list[str]:
    return text.split("\n")


def _find_block(lines: list[str], anchor: list[str]) -> int:
    hits = [i for i in range(len(lines) - len(anchor) + 1)
            if [_ascii_rstrip(l) for l in lines[i:i + len(anchor)]] == anchor]
    if len(hits) != 1:
        raise CensusError("mutation anchor %r matched %d places in the render; the self-test "
                          "needs exactly one" % (anchor, len(hits)))
    return hits[0]


def _replace_block(text: str, anchor: list[str], replacement: list[str]) -> str:
    lines = _split(text)
    at = _find_block(lines, anchor)
    return "\n".join(lines[:at] + replacement + lines[at + len(anchor):])


def _insert_into_policy_file(text: str, document: str) -> str:
    """Add a second document to the file the policy already renders from."""
    lines = _split(text)
    at = _find_block(lines, ["kind: NetworkPolicy"])
    end = at + 1
    while end < len(lines) and _ascii_rstrip(lines[end]) != "---":
        end += 1
    block = ["---"] + _split(document.rstrip("\n"))
    return "\n".join(lines[:end] + block + lines[end:])


def _append_new_file(text: str, document: str, source: str) -> str:
    tail = ["---", "# Source: %s" % source] + _split(document.rstrip("\n")) + [""]
    return text.rstrip("\n") + "\n" + "\n".join(tail)


def _end_a_document_with_a_marker(text: str) -> str:
    """Separate the render's LAST document with `...` instead of `---`.

    the ported reader's differential review measured `...`: a document-end marker ENDS a
    document, and PyYAML 6.0.3 accepts only a directive, a `---`, another
    `...` or end-of-stream after one -- anything else is a ParserError. This
    reader used to treat `...` as a benign boundary and read straight on, so
    the render below parsed here into the SAME four documents and the SAME
    pinned policy and this gate reported GREEN on it.

    THE INSTALLER DOES NOT REFUSE THIS STREAM, and the ported reader's differential review
    was right to insist the difference be measured rather than assumed. On
    Kubernetes v1.36.3, `kubectl apply` on this render EXITS 0 and creates
    three objects -- the NetworkPolicy, the ServiceAccount and the Service --
    silently discarding the Deployment that follows the `...`. That is the
    stronger case for the refusal, not the weaker one: a partial install with a
    success exit code is more dangerous than a rejected file, because nothing
    anywhere reports a problem. And which object goes missing is only an
    accident of template order: on the same server, a render whose
    NetworkPolicy renders LAST behind a `...` applies at rc=0 with the
    ServiceAccount, the Service and the Deployment installed and NO POLICY AT
    ALL -- the workload up, its deny silently discarded, and a green exit code.
    """
    lines = _split(text)
    at = [i for i, line in enumerate(lines) if _ascii_rstrip(line) == "---"]
    if not at:
        raise CensusError("the render carries no document-start line to rewrite; the "
                          "self-test needs one")
    lines[at[-1]] = "..."
    return "\n".join(lines)


def mutations(facts: ChartFacts) -> list[tuple[str, object]]:
    """Every hostile render this census must refuse, as (name, rewriter)."""
    name = facts.chart_name
    selector_anchor = [
        "  podSelector:",
        "    matchLabels:",
        "      app.kubernetes.io/name: " + name,
        "      app.kubernetes.io/instance: " + facts.release,
    ]
    ports_anchor = [
        "      ports:",
        "        - port: %d" % facts.service_port,
        "          protocol: TCP",
    ]
    peer_instance_anchor = ["              app.kubernetes.io/instance: " + facts.peer_instance]
    # The policy's own metadata head, which no other document in the render
    # repeats: the one anchor that lets a mutation reach INSIDE the pinned
    # policy's labels.
    policy_labels_anchor = [
        "  name: " + POLICY_NAME_PREFIX + name,
        "  namespace: " + facts.namespace,
        "  labels:",
    ]
    # The ServiceAccount's own head: an object the census COUNTS but does not
    # pin, so a mutation of its metadata reaches the installability check
    # rather than tripping the pinned-policy assertions first.
    account_anchor = ["kind: ServiceAccount", "metadata:", "  name: " + name]
    # The workload's three binding surfaces. Each anchor is unique in the
    # render by INDENTATION as much as by text: the Deployment's own selector
    # sits under `  selector:` at two spaces (the Service's selector carries no
    # matchLabels at all), and the Pod template's labels are the render's only
    # `labels:` key at six.
    workload_head_anchor = [
        "kind: " + WORKLOAD_KIND,
        "metadata:",
        "  name: " + name,
        "  namespace: " + facts.namespace,
    ]
    workload_selector_anchor = [
        "  selector:",
        "    matchLabels:",
        "      app.kubernetes.io/name: " + name,
        "      app.kubernetes.io/instance: " + facts.release,
    ]
    pod_template_labels_anchor = [
        "      labels:",
        "        app.kubernetes.io/name: " + name,
        "        app.kubernetes.io/instance: " + facts.release,
    ]

    def retarget_the_workload(text: str) -> str:
        """Move the Pod-template labels AND the Deployment's own selector.

        THE HOLE THIS GATE EXISTS FOR, as a render. The policy is untouched
        and still perfect; the Deployment stays valid, because its selector
        moves with its template; and the policy now matches zero Pods.
        """
        moved = _replace_block(
            text, pod_template_labels_anchor,
            [pod_template_labels_anchor[0],
             "        app.kubernetes.io/name: " + name + "-web",
             pod_template_labels_anchor[2]])
        return _replace_block(
            moved, workload_selector_anchor,
            workload_selector_anchor[:2]
            + ["      app.kubernetes.io/name: " + name + "-web",
               workload_selector_anchor[3]])

    def drop_the_workload_instance_label(text: str) -> str:
        """The same hole through the OTHER key, and the subtler one.

        The Pods keep the app name, so a selector checked only against the app
        name would still look bound. The policy names the instance too, which
        this render's Pods no longer carry, so the match is empty.
        """
        dropped = _replace_block(text, pod_template_labels_anchor,
                                 pod_template_labels_anchor[:2])
        return _replace_block(dropped, workload_selector_anchor,
                              workload_selector_anchor[:3])

    def detach_the_workload_selector(text: str) -> str:
        """Move only `spec.selector`, leaving the Pod template alone.

        Kubernetes refuses a Deployment whose selector does not match its own
        template, so this render creates no Pods -- and a deny proven over
        zero Pods is not a proof.
        """
        return _replace_block(
            text, workload_selector_anchor,
            workload_selector_anchor[:2]
            + ["      app.kubernetes.io/name: " + name + "-web",
               workload_selector_anchor[3]])
    shadow_source = "%s/templates/shadow-policy.yaml" % name

    def same_file(document: str):
        return lambda text: _insert_into_policy_file(text, document)

    def new_file(document: str):
        return lambda text: _append_new_file(text, document, shadow_source)

    return [
        # --- a second policy the old raw-line census could not see ---------
        ("shadow-same-file-spaced-keys", same_file(_SHADOW_SPACED)),
        ("shadow-new-file-spaced-keys", new_file(_SHADOW_SPACED)),
        ("shadow-double-quoted-keys", new_file(_SHADOW_DOUBLE_QUOTED)),
        ("shadow-single-quoted-keys", new_file(_SHADOW_SINGLE_QUOTED)),
        ("shadow-escaped-quoted-kind", new_file(_SHADOW_ESCAPED)),
        ("shadow-flow-style-document", new_file(_SHADOW_FLOW)),
        ("shadow-literal-block-scalar-kind", new_file(_SHADOW_LITERAL_KIND)),
        ("shadow-folded-block-scalar-kind", new_file(_SHADOW_FOLDED_KIND)),
        # --- a second policy hidden inside a wrapper ------------------------
        ("shadow-generic-list-wrapper", new_file(_SHADOW_GENERIC_LIST)),
        ("shadow-typed-list-wrapper", new_file(_SHADOW_TYPED_LIST)),
        ("shadow-nested-list-wrapper", new_file(_SHADOW_NESTED_LIST)),
        ("shadow-uninspectable-list-wrapper", new_file(_SHADOW_OPAQUE_LIST)),
        # --- a second policy under another kind, and any extra document -----
        ("shadow-foreign-policy-kind", new_file(_SHADOW_FOREIGN_KIND)),
        ("shadow-extra-configmap", new_file(_SHADOW_CONFIGMAP)),
        # --- constructs no reader should accept -----------------------------
        ("shadow-anchored-spec", new_file(_SHADOW_ANCHORED)),
        ("shadow-merge-key", new_file(_SHADOW_MERGE_KEY)),
        ("shadow-explicit-tag", new_file(_SHADOW_TAGGED)),
        ("shadow-tab-indented", new_file(_SHADOW_TAB_INDENTED)),
        ("shadow-bom-prefixed", new_file(_SHADOW_BOM_PREFIXED)),
        ("shadow-underscore-number", new_file(_SHADOW_UNDERSCORE_NUMBER)),
        ("shadow-timestamp-scalar", new_file(_SHADOW_TIMESTAMP)),
        ("shadow-value-key-scalar", new_file(_SHADOW_VALUE_KEY)),
        ("shadow-unicode-line-break", new_file(_SHADOW_UNICODE_LINE_BREAK)),
        ("shadow-c1-control-character", new_file(_SHADOW_C1_CONTROL)),
        ("shadow-yaml-forbidden-code-point",
         new_file(_SHADOW_YAML_FORBIDDEN_CODE_POINT)),
        ("shadow-flow-glued-colon-key", new_file(_SHADOW_FLOW_GLUED_COLON)),
        ("shadow-flow-nested-indicator", new_file(_SHADOW_FLOW_NESTED_INDICATOR)),
        ("shadow-indicator-leading-key", new_file(_SHADOW_INDICATOR_LEADING_KEY)),
        ("shadow-commented-plain-key", new_file(_SHADOW_COMMENTED_KEY)),
        ("shadow-merge-key-scalar", new_file(_SHADOW_MERGE_KEY_SCALAR)),
        ("shadow-underscored-sexagesimal", new_file(_SHADOW_UNDERSCORED_SEXAGESIMAL)),
        ("render-separated-by-a-document-end-marker",
         lambda text: _end_a_document_with_a_marker(text)),
        ("render-with-an-unspelled-document-boundary", new_file(_SHADOW_UNSPELLED_DOCUMENT)),
        ("shadow-block-scalar-swallows-the-next-line",
         lambda text: _replace_block(text, policy_labels_anchor,
                                     policy_labels_anchor + _SHADOW_BLOCK_SCALAR_NOTE)),
        # --- a render this gate counted that Kubernetes will not install -----
        ("render-with-an-uninstallable-label-value",
         lambda text: _replace_block(text, policy_labels_anchor,
                                     policy_labels_anchor + _SHADOW_UNINSTALLABLE_LABEL_VALUE)),
        ("render-with-an-uninstallable-label-key",
         lambda text: _replace_block(text, policy_labels_anchor,
                                     policy_labels_anchor + _SHADOW_UNINSTALLABLE_LABEL_KEY)),
        ("render-with-an-uninstallable-object-name",
         lambda text: _replace_block(
             text, account_anchor,
             account_anchor[:2] + [account_anchor[2] + _SHADOW_UNINSTALLABLE_NAME_SUFFIX])),
        ("render-with-an-uninstallable-annotation-key",
         lambda text: _replace_block(text, account_anchor,
                                     account_anchor + _SHADOW_UNINSTALLABLE_ANNOTATION_KEY)),
        # --- the pinned policy itself, widened ------------------------------
        ("policy-egress-allow-all",
         lambda text: _replace_block(text, ["  egress: []"], ["  egress: [{}]"])),
        ("policy-egress-respelled-and-widened",
         lambda text: _replace_block(text, ["  egress: []"], ["  egress : [{}]"])),
        ("policy-egress-empty-mapping",
         lambda text: _replace_block(text, ["  egress: []"], ["  egress: {}"])),
        ("policy-drop-egress-policy-type",
         lambda text: _replace_block(text,
                                     ["  policyTypes:", "    - Ingress", "    - Egress"],
                                     ["  policyTypes:", "    - Ingress"])),
        ("policy-empty-pod-selector",
         lambda text: _replace_block(text, selector_anchor, ["  podSelector: {}"])),
        ("policy-wrong-pod-selector-app",
         lambda text: _replace_block(text, selector_anchor,
                                     selector_anchor[:2]
                                     + ["      app.kubernetes.io/name: " + name + "-elsewhere"]
                                     + selector_anchor[3:])),
        ("policy-extra-spec-key",
         lambda text: _replace_block(text, ["  egress: []"],
                                     ["  egress: []", "  shadowKey: true"])),
        ("policy-second-ingress-rule",
         lambda text: _replace_block(text, ports_anchor, ports_anchor + ["    - {}"])),
        ("policy-drop-peer-instance",
         lambda text: _replace_block(text, peer_instance_anchor, [])),
        ("policy-duplicate-kind-key",
         lambda text: _replace_block(text, ["kind: NetworkPolicy"],
                                     ["kind: NetworkPolicy", "kind: ConfigMap"])),
        # --- the policy left perfect, pointing at nothing -------------------
        # Every one of these five leaves the NetworkPolicy document either
        # byte-identical or still self-consistent, which is precisely why they
        # belong here: they are the renders on which `helm lint`,
        # `chart-ingress-pin.sh` and the text battery in `chart-egress-pin.sh`
        # are all green, and only the binding assertion is red.
        ("workload-pod-labels-retargeted", retarget_the_workload),
        ("workload-pod-labels-drop-the-instance", drop_the_workload_instance_label),
        ("workload-selector-detached-from-its-template", detach_the_workload_selector),
        ("workload-moved-to-another-namespace",
         lambda text: _replace_block(
             text, workload_head_anchor,
             workload_head_anchor[:3] + ["  namespace: " + facts.namespace + "-elsewhere"])),
        # The over-selection direction: still a match for this workload, and
        # additionally a match for every other release of this chart.
        ("policy-selector-drops-the-instance-key",
         lambda text: _replace_block(text, selector_anchor, selector_anchor[:3])),
    ]


def mutate(text: str, facts: ChartFacts, wanted: str) -> str:
    table = dict(mutations(facts))
    if wanted not in table:
        raise CensusError("unknown mutation %s" % wanted)
    mutated = table[wanted](text)
    if mutated == text:
        raise CensusError("mutation %s changed nothing, so refusing it would prove nothing"
                          % wanted)
    return mutated


# --- CLI --------------------------------------------------------------------


def _add_facts_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--chart", required=True, help="chart directory")
    parser.add_argument("--release", required=True, help="release name the render used")
    parser.add_argument("--namespace", required=True, help="namespace the render used")
    parser.add_argument("--peer-instance", default=None,
                        help="expected ingress peer instance; defaults to the chart values")


def _read_stdin_utf8() -> str:
    """Decode the CLI byte stream deterministically without text-wrapper normalization."""
    try:
        raw = sys.stdin.buffer.read()
    except AttributeError as error:
        raise CensusError("standard input has no byte buffer; refusing an ambiguous stream") from error
    return raw.decode("utf-8", errors="surrogateescape")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="chart_render_census", description=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)
    census_parser = sub.add_parser("census", help="assert the whole render on stdin")
    _add_facts_arguments(census_parser)
    sub.add_parser("mutations", help="print every hostile mutation name")
    mutate_parser = sub.add_parser("mutate", help="rewrite the render on stdin into a hostile one")
    _add_facts_arguments(mutate_parser)
    mutate_parser.add_argument("--name", required=True, help="mutation to apply")
    args = parser.parse_args(argv)

    try:
        if args.mode == "mutations":
            names = [n for n, _ in mutations(_STATIC_FACTS)]
            sys.stdout.write("\n".join(names) + "\n")
            return 0
        facts = ChartFacts(Path(args.chart), args.release, args.namespace, args.peer_instance)
        if args.mode == "census":
            result = census(_read_stdin_utf8(), facts)
            sys.stdout.write("chart-render-census: %d installable objects, exactly one "
                             "NetworkPolicy, equal to the pinned expectation and selecting "
                             "the one %s it governs\n"
                             % (result["objects"], WORKLOAD_KIND))
            return 0
        sys.stdout.write(mutate(_read_stdin_utf8(), facts, args.name))
        return 0
    except CensusError as error:
        sys.stderr.write("chart-render-census: %s\n" % error)
        return 1
    except OSError as error:
        sys.stderr.write("chart-render-census: %s\n" % error)
        return 1


class _StaticFacts:
    """Names only. `mutations` is listed without reading the chart at all."""

    chart_name = "chart"
    release = "release"
    namespace = "namespace"
    peer_namespace = "peer-namespace"
    peer_app_name = "peer-app"
    peer_instance = "peer-instance"
    service_port = 0


_STATIC_FACTS = _StaticFacts()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
