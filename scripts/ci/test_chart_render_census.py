"""Hostile tests for the whole-render NetworkPolicy census.

The census in `scripts/ci/chart_render_census.py` replaces a raw-line
document scan that a second `NetworkPolicy` could walk straight past by
spelling its keys `kind :` and `spec :` -- valid YAML, invisible to a
prefix match, and an additive allow-all for every Pod once Kubernetes has
it. The behavioural half of the proof lives in `chart-egress-pin.sh`, whose
assertions (d) and (g) rewrite the REAL Helm render into 53 hostile ones and
require the census to refuse every single one. This suite is the other half:
it pins the reader itself, one rejection per test, without needing helm --
so it runs in the `security` job alongside the other contract suites. That
job discovers each suite by its own exact glob rather than one wildcard, so
this file is named in `.github/workflows/pr-gate.yml` by its own step and a
future layout change cannot silently stop collecting it.

It also pins the OTHER claim the census makes, which reading the policy alone
can never support: that the policy SELECTS the workload it governs.
`PolicyIsBoundToTheWorkload` below is that half -- the drift where the
Deployment's Pod-template labels move, the policy stays byte-identical, and a
perfect-looking deny governs zero Pods.

Two rules shape every test here, both taken from AGENTS.md:

- A guard that cannot fail is no guard. Each rejection test names one input
  and requires a refusal, and each acceptance test names one input the
  reader must read EXACTLY right -- a reader that refuses everything would
  be as useless as one that accepts everything.
- The expectation is never derived from the thing under test. The census
  fixtures build their render and their expectation from opposite ends: the
  chart facts come from a temporary Chart.yaml/values.yaml, the policy shape
  is the module's own pinned constants, and the hostile renders are written
  out by hand.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SPEC = importlib.util.spec_from_file_location("chart_render_census", HERE / "chart_render_census.py")
assert SPEC and SPEC.loader
CRC = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CRC
SPEC.loader.exec_module(CRC)

GATE_SCRIPT = HERE / "chart-egress-pin.sh"
REAL_CHART = ROOT / "chart"

FIXTURE_CHART_NAME = "fixture-chart"
FIXTURE_RELEASE = "fixture-release"
FIXTURE_NAMESPACE = "fixture-namespace"
FIXTURE_PEER_NAMESPACE = "peer-namespace"
FIXTURE_PEER_APP = "peer-app"
FIXTURE_PEER_INSTANCE = "peer-instance"
FIXTURE_PORT = 8080


def parse(text: str) -> list[object]:
    return CRC.parse_documents(text, "<test>")


def fixture_chart(directory: Path) -> Path:
    chart = directory / "chart"
    (chart).mkdir()
    (chart / "Chart.yaml").write_text(
        textwrap.dedent(
            """\
            apiVersion: v2
            name: %s
            version: 0.0.1
            appVersion: "0.0.1"
            """
        )
        % FIXTURE_CHART_NAME,
        encoding="utf-8",
    )
    (chart / "values.yaml").write_text(
        textwrap.dedent(
            """\
            # A comment, because a real values file has them.
            service:
              port: %d
            ingress:
              peerNamespace: %s
              peerAppName: %s
              peerInstance: %s
            """
        )
        % (FIXTURE_PORT, FIXTURE_PEER_NAMESPACE, FIXTURE_PEER_APP, FIXTURE_PEER_INSTANCE),
        encoding="utf-8",
    )
    return chart


PINNED_POLICY = """\
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: ingress-to-{chart}
  namespace: {namespace}
  labels:
    app.kubernetes.io/name: {chart}
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/name: {chart}
      app.kubernetes.io/instance: {release}
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: {peer_namespace}
          podSelector:
            matchLabels:
              app.kubernetes.io/name: {peer_app}
              app.kubernetes.io/instance: {peer_instance}
      ports:
        - port: {port}
          protocol: TCP
  # A comment inside the spec, exactly like the real template carries.
  egress: []
"""

REST_OF_RENDER = """\
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: {chart}
---
apiVersion: v1
kind: Service
metadata:
  name: {chart}
spec:
  type: ClusterIP
  selector:
    app.kubernetes.io/name: {chart}
    app.kubernetes.io/instance: {release}
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {chart}
  namespace: {namespace}
spec:
  replicas: 2
  selector:
    matchLabels:
      app.kubernetes.io/name: {chart}
      app.kubernetes.io/instance: {release}
  template:
    metadata:
      labels:
        app.kubernetes.io/name: {chart}
        app.kubernetes.io/instance: {release}
        app.kubernetes.io/managed-by: Helm
    spec:
      containers:
        - name: {chart}
"""


def render() -> str:
    """The pinned render, fully substituted. Tests rewrite the TEXT of this."""
    fields = dict(
        chart=FIXTURE_CHART_NAME,
        release=FIXTURE_RELEASE,
        namespace=FIXTURE_NAMESPACE,
        peer_namespace=FIXTURE_PEER_NAMESPACE,
        peer_app=FIXTURE_PEER_APP,
        peer_instance=FIXTURE_PEER_INSTANCE,
        port=FIXTURE_PORT,
    )
    return (PINNED_POLICY + REST_OF_RENDER).format(**fields)


SHADOW_ALLOW_ALL_SPACED = """\
---
apiVersion : networking.k8s.io/v1
kind : NetworkPolicy
metadata :
  name : shadow-allow-all
spec :
  podSelector : {}
  policyTypes : [Egress]
  egress : [{}]
"""


class ReaderReadsRealYAML(unittest.TestCase):
    """The reader must be RIGHT, not merely strict."""

    def test_a_spaced_key_is_the_same_key(self):
        self.assertEqual(parse("kind : NetworkPolicy\n"), [{"kind": "NetworkPolicy"}])

    def test_a_double_quoted_key_is_the_same_key(self):
        self.assertEqual(parse('"kind": NetworkPolicy\n'), [{"kind": "NetworkPolicy"}])

    def test_a_single_quoted_key_is_the_same_key(self):
        self.assertEqual(parse("'kind': NetworkPolicy\n"), [{"kind": "NetworkPolicy"}])

    def test_escapes_inside_a_quoted_key_resolve_before_matching(self):
        # \\x6b is `k`; \\x4e is `N`. This is the shape a raw-line census
        # cannot see at all, and the reason normalisation happens first.
        self.assertEqual(parse(r'"\x6bind": "\x4eetworkPolicy"' + "\n"),
                         [{"kind": "NetworkPolicy"}])

    def test_flow_collections_parse(self):
        self.assertEqual(parse("spec: {podSelector: {}, policyTypes: [Ingress, Egress], egress: []}\n"),
                         [{"spec": {"podSelector": {}, "policyTypes": ["Ingress", "Egress"],
                                    "egress": []}}])

    def test_a_flow_sequence_of_empty_mappings_is_one_empty_rule(self):
        self.assertEqual(parse("egress: [{}]\n"), [{"egress": [{}]}])

    def test_block_sequences_compact_and_expanded(self):
        self.assertEqual(parse("a:\n  - x: 1\n    w: 2\n  -\n    z: 3\n"),
                         [{"a": [{"x": 1, "w": 2}, {"z": 3}]}])

    def test_a_sequence_may_sit_at_its_parent_indentation(self):
        self.assertEqual(parse("policyTypes:\n- Ingress\n- Egress\n"),
                         [{"policyTypes": ["Ingress", "Egress"]}])

    def test_a_literal_block_scalar_resolves_to_its_text(self):
        self.assertEqual(parse("kind: |-\n  NetworkPolicy\n"), [{"kind": "NetworkPolicy"}])

    def test_a_folded_block_scalar_resolves_to_its_text(self):
        self.assertEqual(parse("kind: >-\n  NetworkPolicy\n"), [{"kind": "NetworkPolicy"}])

    def test_block_scalar_chomping(self):
        # Each answer checked against PyYAML 6.0.3 on the same input; a
        # trailing newline in the stream is a line terminator, not a line.
        self.assertEqual(parse("a: |\n  x\n\n"), [{"a": "x\n"}])
        self.assertEqual(parse("a: |-\n  x\n\n"), [{"a": "x"}])
        self.assertEqual(parse("a: |+\n  x\n\n"), [{"a": "x\n\n"}])

    def test_the_whole_chomping_grid(self):
        # Clip, strip and keep, literal and folded, with and without trailing
        # blank lines. Every value below is PyYAML 6.0.3's own on the same
        # input: clip keeps ONE final break, strip keeps none, keep keeps them
        # all, and a body with no content at all still keeps what `+` promises.
        self.assertEqual(parse("a: |\n  x\n"), [{"a": "x\n"}])
        self.assertEqual(parse("a: |-\n  x\n"), [{"a": "x"}])
        self.assertEqual(parse("a: |+\n  x\n"), [{"a": "x\n"}])
        self.assertEqual(parse("a: >\n  x\n"), [{"a": "x\n"}])
        self.assertEqual(parse("a: >-\n  x\n"), [{"a": "x"}])
        self.assertEqual(parse("a: >+\n  x\n"), [{"a": "x\n"}])
        self.assertEqual(parse("a: |\n  x\n\n\n"), [{"a": "x\n"}])
        self.assertEqual(parse("a: |-\n  x\n\n\n"), [{"a": "x"}])
        self.assertEqual(parse("a: |+\n  x\n\n\n"), [{"a": "x\n\n\n"}])
        self.assertEqual(parse("a: |\nb: 2\n"), [{"a": "", "b": 2}])
        self.assertEqual(parse("a: |\n\n\n"), [{"a": ""}])
        self.assertEqual(parse("a: |+\n\n\n"), [{"a": "\n\n"}])
        self.assertEqual(parse("a: |+\n\n\nb: 2\n"), [{"a": "\n\n", "b": 2}])

    def test_a_block_scalar_keeps_its_leading_blank_lines(self):
        # the ported reader's differential review measured this one: `a: >` / `` / `  x` was
        # "x\n" here and "\nx\n" to PyYAML 6.0.3, because the folder threw a
        # leading break away when nothing had been emitted yet. A leading blank
        # line is CONTENT -- and content dropped out of a scalar is content a
        # reviewer never reads. Closed by transcribing the oracle rather than
        # by refusing, so these are AGREEMENT tests.
        self.assertEqual(parse("a: >\n\n  x\n"), [{"a": "\nx\n"}])
        self.assertEqual(parse("a: |\n\n  x\n"), [{"a": "\nx\n"}])
        self.assertEqual(parse("a: |\n\n\n  x\n"), [{"a": "\n\nx\n"}])
        self.assertEqual(parse("a: >+\n\n  x\n"), [{"a": "\nx\n"}])
        self.assertEqual(parse("a: >-\n\n  x\n"), [{"a": "\nx"}])
        self.assertEqual(parse("a: |2\n\n   x\n"), [{"a": "\n x\n"}])
        self.assertEqual(parse("top:\n  a: >\n\n    x\n"), [{"top": {"a": "\nx\n"}}])

    def test_a_whitespace_only_line_is_blank_only_up_to_the_block_indent(self):
        # The second member of that class: `a: |` / `  x` / `   ` was "x\n" here
        # and "x\n \n" there. A line of spaces is a BLANK line only while it
        # fits inside the block's indentation; one space wider and the surplus
        # is scalar content. Three spaces against a two-space block is one
        # space of content, four spaces is two, and one or two spaces is a
        # blank line -- PyYAML 6.0.3's answer on each.
        self.assertEqual(parse("a: |\n  x\n \n"), [{"a": "x\n"}])
        self.assertEqual(parse("a: |\n  x\n  \n"), [{"a": "x\n"}])
        self.assertEqual(parse("a: |\n  x\n   \n"), [{"a": "x\n \n"}])
        self.assertEqual(parse("a: |\n  x\n    \n"), [{"a": "x\n  \n"}])
        self.assertEqual(parse("a: |\n  x\n   \n  y\n"), [{"a": "x\n \ny\n"}])
        self.assertEqual(parse("a: >\n  x\n   \n  y\n"), [{"a": "x\n \ny\n"}])
        self.assertEqual(parse("a: |\n  x\n \n  y\n"), [{"a": "x\n\ny\n"}])
        self.assertEqual(parse("top:\n  a: |\n    x\n     \n"), [{"top": {"a": "x\n \n"}}])

    def test_the_folding_rule_is_the_oracle_s_own(self):
        # A single break between two content lines folds to one space; a blank
        # line, or a more-indented line on either side, keeps every break.
        self.assertEqual(parse("a: >\n  x\n  y\n"), [{"a": "x y\n"}])
        self.assertEqual(parse("a: >\n  x\n\n  y\n"), [{"a": "x\ny\n"}])
        self.assertEqual(parse("a: >\n  x\n\n\n  y\n"), [{"a": "x\n\ny\n"}])
        self.assertEqual(parse("a: >\n  x\n   y\n  z\n"), [{"a": "x\n y\nz\n"}])
        self.assertEqual(parse("a: |\n  x\n  y\n"), [{"a": "x\ny\n"}])
        self.assertEqual(parse("a: |\n  x\n\n  y\n"), [{"a": "x\n\ny\n"}])

    def test_an_explicit_indentation_indicator_counts_from_the_parent(self):
        self.assertEqual(parse("a: |2\n   x\n"), [{"a": " x\n"}])
        self.assertEqual(parse("a: |2\n  x\n"), [{"a": "x\n"}])
        self.assertEqual(parse("a: |1\n x\n"), [{"a": "x\n"}])
        self.assertEqual(parse("a: |4\n    x\n"), [{"a": "x\n"}])
        self.assertEqual(parse("a: >2\n   x\n"), [{"a": " x\n"}])
        self.assertEqual(parse("top:\n  a: |2\n     x\n"), [{"top": {"a": " x\n"}}])

    def test_a_stream_that_does_not_end_in_a_newline_has_no_final_break(self):
        # Not in the ported receipt -- this reader's own newline-bearing
        # sweep found it. Clip chomping appends the LAST LINE'S break, and an
        # unterminated final line has none, so `a: |` / `  x` is "x" to PyYAML
        # 6.0.3 with no trailing newline and "x\n" with one. Splitting the
        # stream on "\n" and popping the empty tail destroyed that distinction,
        # so both spellings read "x\n" here: an accept-and-misread over 3,774
        # members of the block-scalar sweep alone.
        self.assertEqual(parse("a: |\n  x"), [{"a": "x"}])
        self.assertEqual(parse("a: |\n  x\n"), [{"a": "x\n"}])
        self.assertEqual(parse("a: |-\n  x"), [{"a": "x"}])
        self.assertEqual(parse("a: |+\n  x"), [{"a": "x"}])
        self.assertEqual(parse("a: >\n  x"), [{"a": "x"}])
        self.assertEqual(parse("a: |\n  x\n  y"), [{"a": "x\ny"}])
        self.assertEqual(parse("a: 1"), [{"a": 1}])
        # An unterminated line of pure whitespace is not a line the block ever
        # enters: end-of-stream stops the scan before the first content line,
        # so clip and strip both give the empty scalar and only `+` keeps the
        # blank line above it. Each answer is PyYAML 6.0.3's own.
        self.assertEqual(parse("a: |\n\n "), [{"a": ""}])
        self.assertEqual(parse("a: >\n\n "), [{"a": ""}])
        self.assertEqual(parse("a: |-\n\n "), [{"a": ""}])
        self.assertEqual(parse("a: |+\n\n "), [{"a": "\n"}])
        self.assertEqual(parse("a: |\n\n  "), [{"a": ""}])
        self.assertEqual(parse("a: |\n  x\n  "), [{"a": "x\n"}])
        self.assertEqual(parse("top:\n  a: |\n\n   "), [{"top": {"a": ""}}])

    def test_a_document_boundary_may_be_spelled_and_still_reads(self):
        # The acceptance companion to the refusal below: a document really
        # ended by `---`, by `...`, by end-of-stream, or by a comment or blank
        # line before end-of-stream still reads on both sides.
        self.assertEqual(parse("a\n---\nb\n"), ["a", "b"])
        self.assertEqual(parse("a\n...\n"), ["a"])
        self.assertEqual(parse("a\n"), ["a"])
        self.assertEqual(parse("a\n# c\n"), ["a"])
        self.assertEqual(parse("a\n\n"), ["a"])
        self.assertEqual(parse("a: 1\n\nb: 2\n"), [{"a": 1, "b": 2}])
        self.assertEqual(parse("- a: 1\n  b: 2\n- c: 3\n"), [[{"a": 1, "b": 2}, {"c": 3}]])
        self.assertEqual(parse("a: >\n   \nb: 2\n"), [{"a": "", "b": 2}])

    def test_a_document_marker_inside_a_block_scalar_does_not_split_the_stream(self):
        docs = parse("data: |\n  ---\n  kind: NetworkPolicy\nkind: ConfigMap\n")
        self.assertEqual(len(docs), 1)
        self.assertEqual(docs[0]["kind"], "ConfigMap")
        self.assertEqual(docs[0]["data"], "---\nkind: NetworkPolicy\n")

    def test_comments_are_ignored_wherever_they_appear(self):
        self.assertEqual(parse("# leading\nkind: NetworkPolicy  # trailing\n  # indented\n"),
                         [{"kind": "NetworkPolicy"}])

    def test_a_hash_inside_a_scalar_is_not_a_comment(self):
        self.assertEqual(parse("name: a#b\n"), [{"name": "a#b"}])

    def test_documents_split_and_empty_documents_are_none(self):
        self.assertEqual(parse("---\na: 1\n---\n---\nb: 2\n"), [{"a": 1}, None, {"b": 2}])

    def test_a_document_end_marker_closes_a_document(self):
        # The acceptance companion to the two refusals below: PyYAML 6.0.3
        # reads every one of these exactly as this reader does. `...` may end a
        # document, may repeat, may be followed by comments and blank lines,
        # and a `---` may reopen the stream after it.
        self.assertEqual(parse("a: 1\n...\n---\nb: 2\n"), [{"a": 1}, {"b": 2}])
        self.assertEqual(parse("a: 1\n...\n"), [{"a": 1}])
        self.assertEqual(parse("a: 1\n...\n...\n"), [{"a": 1}])
        self.assertEqual(parse("---\n...\n"), [None])
        self.assertEqual(parse("a: 1\n...\n\n# c\n---\nb: 2\n"), [{"a": 1}, {"b": 2}])

    def test_a_document_end_marker_is_only_one_at_column_zero(self):
        # The companion that keeps the refusal from eating ordinary text: an
        # indented `...`, a `...` inside a quoted or block scalar, and a `...`
        # in value position are all plain content to PyYAML, and to this
        # reader. Only a column-zero marker line ends a document.
        self.assertEqual(parse("  ...\n"), ["..."])
        self.assertEqual(parse("a: ...\n"), [{"a": "..."}])
        self.assertEqual(parse('a: "..."\n'), [{"a": "..."}])
        self.assertEqual(parse("a: '...'\n"), [{"a": "..."}])
        self.assertEqual(parse("a: |\n  ...\nb: 2\n"), [{"a": "...\n", "b": 2}])
        self.assertEqual(parse("...x\n"), ["...x"])

    def test_unicode_whitespace_is_scalar_CONTENT_not_whitespace(self):
        # YAML's whitespace is exactly space and tab. Python's `str.strip()`
        # also eats U+00A0, U+1680, U+2000-U+200A, U+202F, U+205F and U+3000,
        # and leaning on it made every line below a MISREAD: `a: \xa0` was the
        # value None here and the string "\xa0" to PyYAML 6.0.3, and a
        # whole-document `\xa0` was ZERO documents here and one there. Each
        # answer below is PyYAML's own on the same input.
        for ch in ("\xa0", "\u1680", "\u2000", "\u2004", "\u200a", "\u2007",
                   "\u202f", "\u205f", "\u3000"):
            self.assertEqual(parse("a: %s\n" % ch), [{"a": ch}])
            self.assertEqual(parse("%s\n" % ch), [ch])
            self.assertEqual(parse("  %s  \n" % ch), [ch])
            self.assertEqual(parse("a:\n  - %s\n" % ch), [{"a": [ch]}])
            self.assertEqual(parse("a:\n  -%s\n" % ch), [{"a": "-" + ch}])
            self.assertEqual(parse("%s: v\n" % ch), [{ch: "v"}])
            self.assertEqual(parse("a: {k: %s}\n" % ch), [{"a": {"k": ch}}])
            self.assertEqual(parse("a: [%s]\n" % ch), [{"a": [ch]}])
            self.assertEqual(parse("a: |\n  x\n  %s\n  y\n" % ch),
                             [{"a": "x\n%s\ny\n" % ch}])
            # ... and neither `---` nor `...` survives one being glued to it.
            self.assertEqual(parse("---%s\n" % ch), ["---" + ch])
            self.assertEqual(parse("...%s\n" % ch), ["..." + ch])

    def test_unicode_digits_are_strings_and_ascii_digits_still_resolve(self):
        # `int()` and `float()` accept Unicode decimal digits and Unicode
        # whitespace -- `int("\u0665")` (ARABIC-INDIC FIVE) is 5, and so is
        # `int("\xa05")` -- but every
        # call site here is gated by a pattern whose classes are the literal
        # ASCII ranges `[0-9]`, so none of them ever reaches a conversion. Neither
        # does PyYAML 6.0.3: its own resolver patterns carry no `\\d` and no
        # `re.ASCII`, so a fullwidth or Arabic-Indic digit is a plain STRING to
        # both readers. The second half is the companion that keeps the gate
        # useful: ordinary numbers still resolve to numbers.
        for digits in ("\u0665", "\uff15", "\u0966", "\u06f5", "\uff10\uff10",
                       "1\uff10", "\uff11.\uff15", "\u2460", "\u00b2"):
            self.assertEqual(parse("a: %s\n" % digits), [{"a": digits}])
        self.assertEqual(parse("a: 202\uff16-08-20\n"), [{"a": "202\uff16-08-20"}])
        self.assertEqual(parse("a: \uff10x\uff11f\n"), [{"a": "\uff10x\uff11f"}])
        self.assertEqual(parse("port: 8080\n"), [{"port": 8080}])
        self.assertEqual(parse("a: 5\nb: -5\nc: 1.5\nd: .5\ne: 5.\n"),
                         [{"a": 5, "b": -5, "c": 1.5, "d": 0.5, "e": 5.0}])

    def test_scalars_resolve_the_way_kubernetes_yaml_resolves_them(self):
        docs = parse("i: 8080\nf: 1.5\nt: true\nf2: false\nnil: null\ntilde: ~\ns: 200m\nq: \"8080\"\n")
        self.assertEqual(docs, [{"i": 8080, "f": 1.5, "t": True, "f2": False, "nil": None,
                                 "tilde": None, "s": "200m", "q": "8080"}])

    def test_a_quoted_number_is_a_string_not_a_number(self):
        self.assertNotEqual(parse('port: "8080"\n'), parse("port: 8080\n"))


class ReaderFailsClosed(unittest.TestCase):
    """Anything the reader cannot read unambiguously is refused, not guessed."""

    def reject(self, text: str, needle: str):
        with self.assertRaises(CRC.CensusError) as caught:
            parse(text)
        self.assertIn(needle, str(caught.exception))

    def test_tabs(self):
        self.reject("a:\n\tb: 1\n", "tab characters are refused")

    def test_carriage_returns(self):
        self.reject("a: 1\r\n", "carriage returns are refused")

    def test_control_characters(self):
        self.reject("a: \x01\n", "control character")

    def test_directives(self):
        self.reject("%YAML 1.1\n---\na: 1\n", "YAML directives are refused")

    def test_anchors(self):
        self.reject("spec: &wide\n  egress: [{}]\n", "refused")

    def test_aliases(self):
        self.reject("spec: *wide\n", "refused")

    def test_merge_keys(self):
        self.reject("spec:\n  <<: *wide\n", "merge keys are refused")

    def test_explicit_tags(self):
        self.reject("kind: !!str NetworkPolicy\n", "refused")

    def test_duplicate_block_keys(self):
        self.reject("kind: NetworkPolicy\nkind: ConfigMap\n", "duplicate mapping key")

    def test_duplicate_flow_keys(self):
        self.reject("spec: {a: 1, a: 2}\n", "duplicate mapping key")

    def test_a_spaced_duplicate_is_still_a_duplicate(self):
        self.reject("kind: NetworkPolicy\nkind : ConfigMap\n", "duplicate mapping key")

    def test_non_string_keys(self):
        self.reject("8080: http\n", "non-string mapping key")

    def test_ambiguous_booleans(self):
        self.reject("enabled: yes\n", "resolves to a boolean under YAML 1.1")

    def test_sexagesimal_numbers(self):
        self.reject("value: 1:30\n", "sexagesimal")

    def test_leading_zero_integers(self):
        self.reject("value: 0755\n", "leading zero")

    def test_radix_integers(self):
        self.reject("value: 0x1F90\n", "hexadecimal, octal, and binary")

    def test_infinity(self):
        self.reject("value: .inf\n", "infinity")

    def test_exponent_numbers(self):
        # 1.2 says float, 1.1 says string, and 1.1 is what PyYAML 6.0.3 and
        # sigs.k8s.io/yaml implement. Two answers is one too many.
        for form in ("1e3", "1.0e3", "1.0e+3"):
            self.reject("value: %s\n" % form, "exponent number forms are refused")

    def test_digit_group_underscores(self):
        # the ported reader's differential review measured this one: `a: 1_000` was ACCEPTED
        # and read as the string "1_000" while the oracle PyYAML 6.0.3 read the
        # integer 1000. Same class as the exponent forms above -- one spelling,
        # two answers -- so it is a refusal now, and the offending line is named.
        for form in ("1_000", "1_000_000", "+1_0", "-1_0", "1_0.5", "1.0_5",
                     ".5_0", "1_0e1_0", "1_"):
            self.reject("value: %s\n" % form, "digit-group underscores are refused")
        self.reject("value: 1_000\n", "line 1")

    def test_a_quoted_underscored_number_is_still_an_ordinary_string(self):
        # The refusal must not swallow legitimate text: only a PLAIN scalar is
        # ambiguous. Quoted, `1_000` is the string both YAML versions agree on,
        # and an identifier that merely contains an underscore is untouched.
        self.assertEqual(parse('value: "1_000"\n'), [{"value": "1_000"}])
        self.assertEqual(parse("value: '1_000'\n"), [{"value": "1_000"}])
        self.assertEqual(parse("value: app_name\n"), [{"value": "app_name"}])
        self.assertEqual(parse("value: _1\n"), [{"value": "_1"}])

    def test_byte_order_marks(self):
        # The other divergence the ported reader's differential review measured: PyYAML and the YAML
        # spec strip a leading BOM, so THEY see the key `kind`; this reader kept
        # it and saw a different key, which is precisely how a document stops
        # being recognised as a policy. Refused everywhere, never stripped --
        # no rendered byte is silently discarded.
        self.reject("\ufeffkind: NetworkPolicy\n", "byte-order mark")
        self.reject("\ufeffkind: NetworkPolicy\n", "line 1")
        self.reject("kind: NetworkPolicy\n\ufeffmetadata:\n  name: a\n", "line 2")
        self.reject("kind: Network\ufeffPolicy\n", "byte-order mark")

    def test_yaml_11_timestamps(self):
        # the ported reader's differential review measured this class: `a: 2026-08-20` was
        # ACCEPTED and read as the string "2026-08-20" while the oracle PyYAML
        # 6.0.3 built `datetime.date(2026, 8, 20)`. YAML 1.2's core schema has
        # no timestamp type, so one spelling has two meanings -- an object and
        # a string -- and this reader refuses to pick. The four forms the
        # receipt enumerated come first.
        for form in ("2026-08-20", "2026-08-20T10:30:00Z", "2026-08-20 10:30:00",
                     "2001-12-14 21:59:43.10 -5", "2026-8-20 10:30:00",
                     "2026-08-20 10:30:00.5", "2026-08-20 10:30:00 +5:30",
                     "2026-08-20 10:30:00-5", "2026-08-20T10:30:00+05:00"):
            self.reject("value: %s\n" % form, "timestamp scalars are refused")
        self.reject("value: 2026-08-20\n", "line 1")
        # In key position too: the census matches on keys before anything else.
        self.reject("2026-08-20: a\n", "timestamp scalars are refused")

    def test_a_quoted_timestamp_is_still_an_ordinary_string(self):
        # The refusal must not over-reach: only a PLAIN timestamp is ambiguous,
        # and only the shapes PyYAML's own resolver VALUES are timestamps. The
        # near-misses below are strings to both readers and must stay readable
        # -- version numbers especially, since this chart renders a plain-v
        # image tag and a bare numeric chart version.
        self.assertEqual(parse('value: "2026-08-20"\n'), [{"value": "2026-08-20"}])
        self.assertEqual(parse("value: '2026-08-20'\n"), [{"value": "2026-08-20"}])
        self.assertEqual(parse("value: 2026-8-20\n"), [{"value": "2026-8-20"}])
        self.assertEqual(parse("value: 2026-08\n"), [{"value": "2026-08"}])
        self.assertEqual(parse("value: 2026-08-20x\n"), [{"value": "2026-08-20x"}])
        self.assertEqual(parse("value: 2026-08-20T10:30\n"), [{"value": "2026-08-20T10:30"}])
        self.assertEqual(parse("value: v0.1.25\n"), [{"value": "v0.1.25"}])
        self.assertEqual(parse("value: 0.1.25\n"), [{"value": "0.1.25"}])

    def test_the_value_key_plain_scalar(self):
        # The other class the ported reader's differential review measured, and the one counterexample
        # to "nothing this reader accepts is refused by the oracle": plain `=`
        # was ACCEPTED here as the string "=" while PyYAML 6.0.3's safe loader
        # raises ConstructorError for it in VALUE position (no constructor for
        # tag:yaml.org,2002:value). Refused in BOTH positions -- in key
        # position the oracle reads "=", so refusing there is this reader being
        # the STRICTER of the two, which is the safe direction.
        self.reject("value: =\n", "YAML 1.1's value key")
        self.reject("value: =\n", "line 1")
        self.reject("=: a\n", "YAML 1.1's value key")
        self.reject("a:\n  - =\n", "YAML 1.1's value key")
        self.reject("a: {b: =}\n", "YAML 1.1's value key")

    def test_a_quoted_value_key_is_still_an_ordinary_string(self):
        # Only the bare, whole scalar `=` is the value key; quoted, or as part
        # of any longer scalar, it is ordinary text both readers agree on.
        self.assertEqual(parse('value: "="\n'), [{"value": "="}])
        self.assertEqual(parse("value: '='\n"), [{"value": "="}])
        self.assertEqual(parse("value: ==\n"), [{"value": "=="}])
        self.assertEqual(parse("value: =x\n"), [{"value": "=x"}])
        self.assertEqual(parse("value: x=\n"), [{"value": "x="}])

    def test_signed_leading_dot_floats_are_strings_on_both_sides(self):
        # the ported reader's differential review measured this one: `-.5` was READ AS THE
        # FLOAT -0.5 here while the oracle PyYAML 6.0.3 read the string "-.5",
        # because its float resolver's leading-dot branch carries NO sign and
        # only its digit-before-the-dot branch does. Closed by transcribing the
        # oracle's own branches rather than by refusing, so this is an
        # AGREEMENT test, not a rejection one: both readers say string.
        for form in ("-.5", "+.5", "-.0", "+.0", "-.25"):
            self.assertEqual(parse("value: %s\n" % form), [{"value": form}])
            self.assertEqual(parse("a: {b: %s}\n" % form), [{"a": {"b": form}}])
            self.assertEqual(parse("a:\n  - %s\n" % form), [{"a": [form]}])

    def test_unsigned_and_digit_led_floats_still_resolve(self):
        # The companion acceptance: the tightening must not cost a single form
        # the oracle really does resolve. Every value below is the identical
        # float object under PyYAML 6.0.3.
        self.assertEqual(parse("value: .5\n"), [{"value": 0.5}])
        self.assertEqual(parse("value: .0\n"), [{"value": 0.0}])
        self.assertEqual(parse("value: 0.5\n"), [{"value": 0.5}])
        self.assertEqual(parse("value: -0.5\n"), [{"value": -0.5}])
        self.assertEqual(parse("value: +0.5\n"), [{"value": 0.5}])
        self.assertEqual(parse("value: 5.\n"), [{"value": 5.0}])
        self.assertEqual(parse("value: -5.\n"), [{"value": -5.0}])
        self.assertEqual(parse("value: 00.5\n"), [{"value": 0.5}])
        # ... and a bare dot is a string to both, as it always was.
        self.assertEqual(parse("value: .\n"), [{"value": "."}])

    def test_unicode_line_breaks(self):
        # NEL, LINE SEPARATOR and PARAGRAPH SEPARATOR are LINE BREAKS to a real
        # YAML reader and ordinary characters to one that only splits on `\n`,
        # so a stream carrying one has a different number of LINES there than
        # here -- PyYAML either refuses it outright or reads a scalar this
        # reader never saw. Refused everywhere in the stream, never translated.
        for ch, needle in (("\u0085", "NEL (U+0085)"),
                           ("\u2028", "LINE SEPARATOR (U+2028)"),
                           ("\u2029", "PARAGRAPH SEPARATOR (U+2029)")):
            self.reject("kind: Network%sPolicy\n" % ch, needle)
            self.reject('kind: "Network%sPolicy"\n' % ch, needle)
            self.reject("kind: 'Network%sPolicy'\n" % ch, needle)
            self.reject("%skind: NetworkPolicy\n" % ch, needle)
            self.reject("kind: NetworkPolicy%s\n" % ch, needle)
            self.reject("kind: |\n  Network%sPolicy\n" % ch, needle)
            self.reject("ki%snd: NetworkPolicy\n" % ch, needle)
            self.reject("a: {b: x%sy}\n" % ch, needle)
            self.reject("kind: Network%sPolicy\n" % ch, "line 1")
            self.reject("a: 1\nkind: Network%sPolicy\n" % ch, "line 2")

    def test_an_escaped_line_break_character_is_still_produced(self):
        # The refusal is about the render's own BYTES. `\\N`, `\\L` and `\\P`
        # inside a double-quoted scalar PRODUCE these characters, and PyYAML
        # 6.0.3 produces exactly the same string, so refusing them here would
        # be over-reach into a case where the two readers already agree.
        self.assertEqual(parse(r'kind: "a\Nb"' + "\n"), [{"kind": "a\u0085b"}])
        self.assertEqual(parse(r'kind: "a\Lb"' + "\n"), [{"kind": "a\u2028b"}])
        self.assertEqual(parse(r'kind: "a\Pb"' + "\n"), [{"kind": "a\u2029b"}])
        self.assertEqual(parse(r'kind: "a\x85b"' + "\n"), [{"kind": "a\u0085b"}])
        self.assertEqual(parse(r'kind: "a\u2028b"' + "\n"), [{"kind": "a\u2028b"}])

    def test_c1_control_characters(self):
        # PyYAML's reader rejects the WHOLE STREAM for any of U+0080-U+009F
        # (they are outside its printable set), so a render this gate read
        # happily would be a render nothing can install.
        for code in (0x80, 0x81, 0x84, 0x86, 0x8A, 0x90, 0x9B, 0x9F):
            ch = chr(code)
            self.reject("kind: Network%sPolicy\n" % ch, "C1 control character U+%04X" % code)
            self.reject('kind: "Network%sPolicy"\n' % ch, "C1 control character")
            self.reject("ki%snd: NetworkPolicy\n" % ch, "C1 control character")
        self.reject("kind: Network\x80Policy\n", "line 1")
        self.reject("a: 1\nkind: Network\x80Policy\n", "line 2")

    def test_every_yaml_reader_forbidden_code_point_is_refused(self):
        # YAML 1.2.2 and PyYAML 6.0.3 exclude exactly the surrogate block plus
        # U+FFFE/U+FFFF from otherwise printable non-ASCII code points. This
        # expectation is deliberately written independently of production's
        # guard: deleting or narrowing that guard must make this test red.
        forbidden = list(range(0xD800, 0xE000)) + [0xFFFE, 0xFFFF]
        self.assertEqual(len(forbidden), 2050)
        for code in forbidden:
            with self.subTest(codepoint="U+%04X" % code):
                self.reject("# hostile %s\na: 1\n" % chr(code),
                            "YAML-forbidden code point U+%04X" % code)

    def test_yaml_reader_forbidden_endpoints_are_refused_before_parsing(self):
        # Comments, keys, values, quoted scalars and block scalar bodies all
        # take the same stream-level path; none may hide the endpoint members.
        placements = (
            "# hostile %s\na: 1\n",
            "key%s: value\n",
            "value: plain%svalue\n",
            'value: "quoted%svalue"\n',
            "value: |\n  block%svalue\n",
        )
        for code in (0xD800, 0xDFFF, 0xFFFE, 0xFFFF):
            for placement in placements:
                with self.subTest(codepoint="U+%04X" % code, placement=placement):
                    self.reject(placement % chr(code),
                                "YAML-forbidden code point U+%04X" % code)

    def test_yaml_reader_forbidden_boundaries_remain_readable(self):
        # The exact companions on both sides of each excluded range, including
        # supplementary noncharacters explicitly admitted by c-printable.
        for code in (0xD7FF, 0xE000, 0xFFFD, 0x10000,
                     0x1FFFE, 0x1FFFF, 0x10FFFF):
            ch = chr(code)
            with self.subTest(codepoint="U+%X" % code):
                self.assertEqual(parse("value: a%sb\n" % ch),
                                 [{"value": "a%sb" % ch}])

    def test_raw_production_stdin_refuses_forbidden_and_malformed_bytes(self):
        # Exercise `main()` through its real byte stdin. Valid UTF-8 encodings
        # for U+FFFE/U+FFFF and malformed 80 (preserved as U+DC80 by
        # surrogateescape) must all die at the same pre-parse guard, not later
        # on an unrelated inventory assertion.
        hostile = ((b"# hostile \xef\xbf\xbe\n", "U+FFFE"),
                   (b"# hostile \xef\xbf\xbf\n", "U+FFFF"),
                   (b"# hostile \x80\n", "U+DC80"))
        command = [sys.executable, "-I", "-B", str(HERE / "chart_render_census.py"),
                   "census", "--chart", str(REAL_CHART),
                   "--release", "raw-input", "--namespace", "raw-input"]
        for raw, codepoint in hostile:
            with self.subTest(raw=raw.hex()):
                result = subprocess.run(command, input=raw, capture_output=True,
                                        check=False)
                diagnostic = result.stderr.decode("ascii")
                self.assertEqual(result.returncode, 1, diagnostic)
                self.assertIn("YAML-forbidden code point " + codepoint, diagnostic)
                self.assertIn("line 1", diagnostic)
                self.assertNotIn("complete render carries", diagnostic)

    def test_the_c1_refusal_stops_at_u00a0(self):
        # The range is U+0080-U+009F and nothing above it: a refusal that ate
        # ordinary letters would break every render carrying a name, a symbol
        # or a translated label. U+0085 is excluded here only because it is
        # already refused as a LINE BREAK by the test above.
        for code in (0xA0, 0xA9, 0xE9, 0xFF, 0x100, 0x2013, 0x4E2D, 0x1F600):
            ch = chr(code)
            self.assertEqual(parse("kind: Network%sPolicy\n" % ch),
                             [{"kind": "Network%sPolicy" % ch}])
            self.assertEqual(parse('kind: "Network%sPolicy"\n' % ch),
                             [{"kind": "Network%sPolicy" % ch}])
            self.assertEqual(parse("ki%snd: NetworkPolicy\n" % ch),
                             [{"ki%snd" % ch: "NetworkPolicy"}])
        self.assertEqual(parse(r'kind: "a\_b"' + "\n"), [{"kind": "a\xa0b"}])

    def test_flow_context_colon_glued_keys(self):
        # Inside a flow collection a colon only ENDS a key when a space or a
        # flow indicator follows it, so PyYAML reads `{a:1}` as the single
        # plain scalar `a:1` with NO value. This reader used to split at the
        # colon and hand back `{a: 1}` -- a mapping the installer never sees.
        for form in ("{a:1}", "{a :1}", "{a:1, b: 2}", "{a:b:c}", "{a:1}"):
            self.reject("value: %s\n" % form, "glued to the next character")
        self.reject("value: {a:1}\n", "line 1")

    def test_a_spaced_or_quoted_flow_key_still_reads(self):
        # The companion acceptance: only the GLUED spelling is ambiguous.
        # PyYAML reads every line below exactly as this reader does, including
        # the JSON-style quoted key whose colon may legally be adjacent.
        self.assertEqual(parse("value: {a: 1}\n"), [{"value": {"a": 1}}])
        self.assertEqual(parse("value: {a : 1}\n"), [{"value": {"a": 1}}])
        self.assertEqual(parse('value: {"a":1}\n'), [{"value": {"a": 1}}])
        self.assertEqual(parse("value: {'a':1}\n"), [{"value": {"a": 1}}])
        self.assertEqual(parse("value: [a:1]\n"), [{"value": ["a:1"]}])
        self.assertEqual(parse("value: a:1\n"), [{"value": "a:1"}])

    def test_flow_plain_scalars_end_at_a_nested_indicator(self):
        # PyYAML's `scan_plain` ends a plain scalar inside a flow collection at
        # any of `,?[]{}`. Reading straight past them made `{b: 1 [}` the
        # scalar "1 [" here and a parse error there.
        self.reject("a: {b: 1 [}\n", "unexpected character")
        self.reject("a: {b: k {}\n", "unexpected character")
        self.reject("a: [1 {]\n", "unexpected character")
        self.reject("a: {b: -?}\n", "block sequence indicator")
        self.reject("a: {- k: v}\n", "is refused")
        self.reject("a: {1 [: v}\n", "is refused")
        self.reject("a: {1 #: v}\n", "is refused")

    def test_indicator_leading_plain_keys(self):
        # `_scan_key` refused only `& * ! ?` and `<<` while `_scan_value`
        # refused the wider indicator set, so `@foo:`, `` `foo: ``, `|foo:`,
        # `>foo:` and `,foo:` were keys here and hard scanner errors in the
        # tool that installs the render. One shared constant now, both sides.
        for ch in "@`|>%,]}":
            self.reject("%sfoo: v\n" % ch, "refused")
            self.reject("first: 1\n%sfoo: v\n" % ch, "refused")
        for ch in "@`|>%[{":
            self.reject("a: {%sfoo: v}\n" % ch, "refused")
        self.reject("first: 1\n[foo: v\n", "refused")
        self.reject("first: 1\n{foo: v\n", "refused")
        self.reject("@foo: v\n", "line 1")
        self.reject("first: 1\n@foo: v\n", "line 2")

    def test_indicator_leading_plain_values(self):
        for ch in "@`%,]}":
            self.reject("value: %sfoo\n" % ch, "refused")
        # `|` and `>` in this position are read as a block scalar HEADER first,
        # which is its own refusal with its own message; PyYAML refuses them
        # too ("expected chomping or indentation indicators").
        for ch in "|>":
            self.reject("value: %sfoo\n" % ch, "block scalar header")
        for ch in "@`|>%,}":
            self.reject("value: [%sfoo]\n" % ch, "refused")
        # `:` opens a legal plain scalar in BLOCK context and an illegal one
        # inside a flow collection -- the one deliberate, measured asymmetry.
        self.reject("a: {b: :foo}\n", "refused")
        self.reject("a: [:foo]\n", "refused")
        self.reject("value: @foo\n", "line 1")

    def test_the_indicators_a_plain_scalar_may_still_open_with(self):
        # The companion acceptance, one line per measured asymmetry: PyYAML
        # reads every one of these, so refusing them would be over-reach.
        self.assertEqual(parse("value: -foo\n"), [{"value": "-foo"}])
        self.assertEqual(parse("-foo: v\n"), [{"-foo": "v"}])
        self.assertEqual(parse("value: -5\n"), [{"value": -5}])
        self.assertEqual(parse("value: :foo\n"), [{"value": ":foo"}])
        self.assertEqual(parse(":foo: v\n"), [{":foo": "v"}])
        self.assertEqual(parse("value: a@b\n"), [{"value": "a@b"}])
        self.assertEqual(parse("value: a,b\n"), [{"value": "a,b"}])
        self.assertEqual(parse("value: a|b\n"), [{"value": "a|b"}])
        self.assertEqual(parse("value: http://x\n"), [{"value": "http://x"}])

    def test_the_merge_key_plain_scalar(self):
        # `=`'s twin, one tag along: PyYAML resolves a plain `<<` to
        # tag:yaml.org,2002:merge, its safe loader has no constructor for that
        # tag, and `a: <<` raises a ConstructorError instead of parsing. It was
        # already refused in KEY position and accepted as the string "<<" in
        # value position -- the direction a reader must never be looser in.
        self.reject("value: <<\n", "YAML 1.1's merge key")
        self.reject("value: <<\n", "line 1")
        self.reject("a:\n  - <<\n", "YAML 1.1's merge key")
        self.reject("a: {b: <<}\n", "YAML 1.1's merge key")
        self.reject("a: [<<]\n", "YAML 1.1's merge key")

    def test_a_quoted_merge_key_is_still_an_ordinary_string(self):
        # Only the bare, whole scalar `<<` is the merge key.
        self.assertEqual(parse('value: "<<"\n'), [{"value": "<<"}])
        self.assertEqual(parse("value: '<<'\n"), [{"value": "<<"}])
        self.assertEqual(parse("value: <<<\n"), [{"value": "<<<"}])
        self.assertEqual(parse("value: x<<\n"), [{"value": "x<<"}])
        self.assertEqual(parse("value: <\n"), [{"value": "<"}])

    def test_a_comment_inside_a_plain_mapping_key(self):
        # ` #` opens a comment, so real YAML ends the scalar there and the line
        # stops being a mapping entry at all: `k #: v` is the plain scalar "k"
        # to PyYAML and was the key "k #" here.
        self.reject("k #: v\n", "may not carry a comment")
        self.reject("first: 1\nk #: v\n", "may not carry a comment")
        self.reject("first: 1\nk #: v\n", "line 2")

    def test_comments_around_a_value_are_still_comments(self):
        # The companion acceptance: a comment after a value, a `#` with no
        # space before it, and a whole-line comment all still read.
        self.assertEqual(parse("kind: NetworkPolicy  # trailing\n"),
                         [{"kind": "NetworkPolicy"}])
        self.assertEqual(parse("kind: a#b\n"), [{"kind": "a#b"}])
        self.assertEqual(parse("a#b: v\n"), [{"a#b": "v"}])
        self.assertEqual(parse("# whole line\nkind: NetworkPolicy\n"),
                         [{"kind": "NetworkPolicy"}])

    def test_underscored_sexagesimals(self):
        # YAML 1.1's sexagesimal resolvers take digit-group underscores in
        # every group, so `1_:0` is the integer 60 to PyYAML and was the string
        # "1_:0" here. Found by this PR's own exhaustive fuzz of the number
        # alphabet, not by the receipt.
        for form in ("1_:0", "5_:9", "1_0:3_0", "1_:0.5", "-1_:0", "1:3_0"):
            self.reject("value: %s\n" % form, "sexagesimal")
        self.reject("value: 1_:0\n", "line 1")

    def test_sexagesimal_neighbours_that_carry_no_colon_still_read(self):
        # The refusal needs a colon: an ordinary underscored identifier, a
        # quoted sexagesimal, and a plain time-looking STRING are untouched.
        self.assertEqual(parse('value: "1_:0"\n'), [{"value": "1_:0"}])
        self.assertEqual(parse("value: app_name\n"), [{"value": "app_name"}])
        self.assertEqual(parse("value: _1\n"), [{"value": "_1"}])

    def test_a_plain_scalar_opening_with_a_sequence_indicator(self):
        # Real YAML refuses this. So must this reader: being more permissive
        # than the tools that install the render is its own kind of hole.
        self.reject("a: - 1\n", "block sequence indicator")

    def test_unterminated_flow_collections(self):
        self.reject("egress: [{}\n", "unterminated flow")

    def test_unterminated_quoted_scalars(self):
        self.reject('name: "shadow\n', "unterminated double-quoted scalar")

    def test_a_plain_scalar_may_not_continue_on_the_next_line(self):
        # Real YAML folds this into "Network Policy". This reader refuses it
        # rather than fold, so a value that continues is never half-read.
        self.reject("kind: Network\n  Policy\n", "unexpected indentation")

    def test_a_plain_scalar_document_may_not_continue_on_the_next_line(self):
        self.reject("---\nNetwork\n  Policy\n", "multi-line plain scalars are refused")

    def test_content_on_a_document_start_line(self):
        self.reject("--- kind: NetworkPolicy\n", "content on a document-start line")

    def test_a_mapping_indicator_inside_a_plain_scalar(self):
        self.reject("a: b: c\n", "mapping indicator")

    def test_unexpected_indentation(self):
        self.reject("a: 1\n  b: 2\n", "unexpected indentation")

    def test_a_unicode_space_after_a_block_scalar_header(self):
        # `str.split(None, 1)` splits on PYTHON's whitespace, so `|\xa0` came
        # back as the header `|` with no trailing text and `a: |\xa0` parsed as
        # an ordinary literal block scalar here -- while PyYAML 6.0.3 raises a
        # ScannerError on the U+00A0 after the indicator. Splitting on the
        # ASCII space alone puts the character back in the header, where the
        # header loop refuses it.
        for ch in ("\xa0", "\u1680", "\u2000", "\u202f", "\u3000"):
            self.reject("a: |%s\n  x\n" % ch, "unsupported block scalar header")
            self.reject("a: >%s\n  x\n" % ch, "unsupported block scalar header")
            self.reject("a: |%s# c\n  x\n" % ch, "block scalar header")
            self.reject("a: |2%s\n   x\n" % ch, "unsupported block scalar header")
            self.reject("a: | %s\n  x\n" % ch, "unexpected text after a block scalar header")
        self.reject("a: |\xa0\n  x\n", "line 1")

    def test_unicode_whitespace_after_a_value_is_trailing_content(self):
        # The same Unicode-strip leak one method along: `_require_trailing_blank`
        # stripped it away and read on, where PyYAML refuses the stream. A
        # character YAML does not call whitespace cannot follow a closed value.
        for ch in ("\xa0", "\u2000", "\u3000"):
            self.reject("a: [1] %s\n" % ch, "unexpected trailing content")
            self.reject('a: "x" %s\n' % ch, "unexpected trailing content")
            self.reject("a: [1]%s\n" % ch, "unexpected trailing content")

    def test_a_document_end_marker_before_any_document(self):
        # `...` ENDS a document; PyYAML has none to end here and raises. This
        # reader used to skip the line and return ZERO documents -- a whole
        # stream read as nothing at all.
        self.reject("...\n", "before any document")
        self.reject("...\n...\n", "before any document")
        self.reject("# c\n...\n", "before any document")
        self.reject("...\nfoo: v\n", "before any document")
        self.reject("...\n", "line 1")

    def test_content_after_a_document_end_marker(self):
        # And the other half: PyYAML accepts only a directive, a `---`, another
        # `...` or end-of-stream after a document-end marker, and raises a
        # ParserError on anything else. This reader used to read straight on,
        # so `x: 1\n...\nfoo: v` was TWO documents here and a refused stream
        # there -- accept-where-the-declared-oracle-refuses.
        self.reject("x: 1\n...\nfoo: v\n", "content after a document-end marker")
        self.reject("x: 1\n...\n# c\nfoo: v\n", "content after a document-end marker")
        self.reject("x: 1\n...\n...\nfoo: v\n", "content after a document-end marker")
        self.reject("a:\n  - 1\n...\nb: 2\n", "content after a document-end marker")
        self.reject("x: 1\n...\nfoo: v\n", "line 3")

    def test_a_document_boundary_is_spelled_never_inferred(self):
        # the ported reader's differential review measured this class, and it was
        # structurally unreachable to rounds one through four because every
        # alphabet they swept was newline-free. `documents()` started a new
        # document wherever a top-level node happened to end -- which is
        # wherever the next line is not more indented. PyYAML 6.0.3 does
        # something else in every one of these: it FOLDS the next line into the
        # node above (`a` / `b` is the ONE scalar "a b" there and was ['a','b']
        # here) or it refuses the stream outright (`-` / `a` and `x` /
        # `kind: v` are both ScannerErrors there and were two documents here).
        # A document boundary is spelled `---`; it is never inferred.
        for text in ("a\nb\n", "a\nb\nc\n", "-\na\n", "x\nkind: v\n",
                     "[1]\nb\n", "{a: 1}\nb\n", '"q"\nb\n', "'q'\nb\n",
                     "- a\nb: 1\n", "-\n- a\nb\n", "null\napiVersion: v1\n"):
            self.reject(text, "may begin only after a `---` document-start line")
        self.reject("a\nb\n", "line 2")
        self.reject("-\n- a\nb\n", "line 3")

    def test_the_multi_line_plain_scalar_claim_is_now_true(self):
        # The claim this module has carried since it was written was FALSE at
        # the pre-repair head: the reader was not refusing a plain scalar that
        # continued onto the next line, it was silently splitting the stream
        # into documents. An indented continuation hit the older refusal; a
        # continuation at the same indentation hit nothing at all. Both refuse
        # now, so the claim states what the code does.
        self.reject("a\n b\n", "multi-line plain scalars are refused")
        self.reject("a\n  b\n", "multi-line plain scalars are refused")
        self.reject("---\nNetwork\n  Policy\n", "multi-line plain scalars are refused")
        self.reject("kind: Network\n  Policy\n", "unexpected indentation")
        self.reject("kind: NetworkPolicy\nshadow\n", "neither a mapping key")

    def test_a_wide_whitespace_only_line_pushes_the_block_indent_past_its_content(self):
        # The third member of that class, and the one repaired by REFUSAL rather
        # than by agreement -- because the oracle refuses it too. The block's
        # indentation is the widest run of leading whitespace the oracle
        # crosses on its way to the first content line, a whitespace-only line
        # included, so three spaces above a two-space body put the body OUTSIDE
        # the block: PyYAML 6.0.3 reads an empty scalar and its parser then
        # raises on the orphaned line. This reader used to swallow the line as
        # block content and read on -- accept-where-the-oracle-refuses.
        self.reject("a: >\n   \n  x\n", "unexpected indentation inside a block mapping")
        self.reject("a: |\n   \n  x\n", "unexpected indentation inside a block mapping")
        self.reject("top:\n  a: >\n     \n    x\n", "unexpected indentation")
        self.reject("a: >\n   \n  x\n", "line 3")

    def test_a_unicode_space_does_not_make_a_document_marker(self):
        # `raw.strip()` turned `---\xa0` and `...\xa0` into markers here while
        # PyYAML reads them as ordinary plain scalars (its own check wants a
        # space, tab, line break or end-of-stream after the three characters).
        self.reject("a: 1\n---\xa0\nb: 2\n", "neither a mapping key")
        self.reject("a: 1\n...\xa0\nb: 2\n", "neither a mapping key")
        self.reject("a: 1\n... \xa0\n", "content on a document-end line")
        self.reject("... \xa0\n", "content on a document-end line")
        self.reject("a: 1\n--- \xa0\n", "content on a document-start line")


class EveryGuardClauseTheKillBatteryReachedIsPinned(unittest.TestCase):
    """One test per SURVIVING mutant of the ported reader's kill battery.

    Two divergence classes were closed by repairs to the reader; the kill
    battery then asked the next question -- is every clause those repairs
    introduced actually load bearing? It mutates each such guard clause
    INDEPENDENTLY (each `_ascii_*` call site, `_document_marker`,
    `_read_document`, and every clause inside `_bs_indentation`, `_bs_breaks`,
    `_bs_skip_indent`, `_bs_has_more`, `_block_scalar_body` and
    `_line_break_after`) -- 84 mutants -- and runs the whole suite and the
    census gate against each. Sixty-nine died. The nine tests below kill nine
    of the fifteen that survived; the other six are PROVEN equivalent by
    measurement and are named in the module's own comments rather than pinned
    by a test that no input could fail.

    The first is the differential review's own finding, and the only survivor
    that was WRONG rather than merely unpinned.
    """

    def reject(self, text: str, needle: str):
        with self.assertRaises(CRC.CensusError) as caught:
            parse(text)
        self.assertIn(needle, str(caught.exception))

    def test_keep_chomping_counts_only_the_breaks_the_stream_really_has(self):
        # THE SURVIVOR THAT MATTERED. Dropping `_line_break_after(k)` from
        # `_bs_breaks`'s loop condition survived the entire suite AND the gate
        # while diverging from PyYAML 6.0.3 on 928 members of the reviewer's
        # corpus and 1,100 of the battery's own. `_bs_breaks` counts BLANK LINES,
        # and a line is only blank if a BREAK follows it: a final
        # whitespace-only line with no trailing newline is the end of the
        # stream, not a blank line, so keep chomping has nothing extra to put
        # back. Without the clause, `a: |+` / ` x` / ` ` gained a newline the
        # oracle does not produce -- content invented inside a scalar.
        # Every value below is PyYAML 6.0.3's own on the same input.
        self.assertEqual(parse("a: |+\n x\n "), [{"a": "x\n"}])
        self.assertEqual(parse("a: |+\n  x\n  "), [{"a": "x\n"}])
        self.assertEqual(parse("a: >+\n\n    x\n "), [{"a": "\nx\n"}])
        self.assertEqual(parse("top:\n  a: |+\n    x\n    "), [{"top": {"a": "x\n"}}])
        # ... and the companion that keeps the clause from over-reaching: WITH
        # the final newline the same line really is a blank line, and keep
        # chomping really does put it back.
        self.assertEqual(parse("a: |+\n x\n \n"), [{"a": "x\n\n"}])
        self.assertEqual(parse("a: |+\n  x\n  \n"), [{"a": "x\n\n"}])
        self.assertEqual(parse("a: >+\n\n    x\n \n"), [{"a": "\nx\n\n"}])
        # ... and a final line WIDER than the block indent is content on both
        # sides, terminated or not, so the clause has not eaten that either.
        self.assertEqual(parse("a: |+\n x\n  "), [{"a": "x\n "}])
        self.assertEqual(parse("a: |+\n  x\n   "), [{"a": "x\n "}])

    def test_a_dash_carrying_unicode_whitespace_is_not_a_sequence_entry(self):
        # `_ascii_rstrip(body) == "-"` in `_mapping`: with Python's Unicode
        # rstrip, `-\xa0` became a block sequence indicator and the line was
        # refused with the WRONG reason. PyYAML 6.0.3 raises a ScannerError on
        # both spellings ("could not find expected ':'"), and it is the same
        # class as every other Unicode-strip leak that review closed: YAML's
        # whitespace is space and tab, so `-\xa0` is a plain scalar starting
        # with a dash, not a dash followed by whitespace.
        for ch in ("\xa0", "\u2000", "\u3000"):
            self.reject("a: 1\n-%s\n" % ch, "neither a mapping key")
            self.reject("a:\n-%s\n" % ch, "neither a mapping key")
        # ... and the ASCII companions, each PyYAML's own answer: a dash with a
        # real space IS a sequence entry, and a dash INSIDE a scalar is not.
        self.assertEqual(parse("a:\n- \n"), [{"a": [None]}])
        self.assertEqual(parse("a:\n- x\n"), [{"a": ["x"]}])
        self.assertEqual(parse("a:\n  -\xa0\n"), [{"a": "-\xa0"}])
        self.assertEqual(parse("-\xa0\n"), ["-\xa0"])
        self.reject("a: 1\n- \n", "a block sequence entry appears where a mapping key")

    def test_the_mutation_builders_read_yamls_whitespace_too(self):
        # Three more `_ascii_rstrip` sites, all in the self-test machinery
        # rather than the reader: `_find_block`, `_insert_into_policy_file` and
        # `_end_a_document_with_a_marker`. Python's Unicode rstrip made each of
        # them treat a line carrying a trailing U+00A0 as a structural line --
        # an anchor match, a `---` separator -- which is a mutation applied
        # somewhere the render does not actually have that structure. A
        # mutation battery that anchors on the wrong line proves nothing about
        # the right one.
        self.assertEqual(
            CRC._find_block(CRC._split("kind: NetworkPolicy \nmetadata:\n"),
                            ["kind: NetworkPolicy"]), 0)
        with self.assertRaises(CRC.CensusError):
            CRC._find_block(CRC._split("kind: NetworkPolicy\xa0\nmetadata:\n"),
                            ["kind: NetworkPolicy"])
        self.assertEqual(CRC._end_a_document_with_a_marker("a\n---\nb\n"), "a\n...\nb\n")
        with self.assertRaises(CRC.CensusError):
            CRC._end_a_document_with_a_marker("kind: NetworkPolicy\n---\xa0\nkind: Service\n")
        glued = CRC._insert_into_policy_file(
            "kind: NetworkPolicy\nmetadata:\n---\xa0\nkind: Service\n", "kind: X\n")
        self.assertTrue(glued.endswith("---\nkind: X"), glued)
        spelled = CRC._insert_into_policy_file(
            "kind: NetworkPolicy\nmetadata:\n---\nkind: Service\n", "kind: X\n")
        self.assertEqual(spelled,
                         "kind: NetworkPolicy\nmetadata:\n---\nkind: X\n---\nkind: Service\n")

    def test_the_end_of_stream_helpers_answer_for_a_line_that_is_not_there(self):
        # `_line_break_after`'s past-the-end guard and `_bs_has_more`'s. Both
        # survived every input the corpus could reach, because the block-scalar
        # arithmetic never asks them past the end -- so they are pinned here by
        # direct call instead. A guard nothing exercises is a guard that can
        # rot, and both of these would answer TRUE or raise IndexError without
        # the clause.
        reader = CRC.Reader("a\n", "<t>")
        self.assertFalse(reader._line_break_after(1))
        self.assertFalse(reader._line_break_after(99))
        self.assertFalse(reader._bs_has_more(1, 0))
        self.assertFalse(reader._bs_has_more(99, 0))

    def test_a_bare_line_end_is_more_input_only_when_a_break_follows(self):
        # `_bs_has_more`'s last clause, the oracle's `peek() != '\0'`: standing
        # just past a line's text is more input when a break follows and
        # end-of-stream when none does.
        terminated = CRC.Reader("a\n", "<t>")
        self.assertTrue(terminated._bs_has_more(0, 1))
        self.assertTrue(terminated._bs_has_more(0, 0))
        unterminated = CRC.Reader("a", "<t>")
        self.assertFalse(unterminated._bs_has_more(0, 1))
        self.assertTrue(unterminated._bs_has_more(0, 0))

    def test_the_reader_records_whether_the_stream_ended_in_a_newline(self):
        # The fact `_line_break_after` is built on, pinned as a fact. Popping
        # the split artefact destroys it, which is why it is recorded first.
        self.assertTrue(CRC.Reader("a: |\n  x\n", "<t>").ends_with_newline)
        self.assertFalse(CRC.Reader("a: |\n  x", "<t>").ends_with_newline)
        self.assertTrue(CRC.Reader("a\n\n", "<t>").ends_with_newline)
        self.assertFalse(CRC.Reader("a\n\nb", "<t>").ends_with_newline)


class CensusFixture(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.chart = fixture_chart(Path(self._tmp.name))
        self.facts = CRC.ChartFacts(self.chart, FIXTURE_RELEASE, FIXTURE_NAMESPACE)

    def census(self, text: str):
        return CRC.census(text, self.facts)

    def reject(self, text: str, needle: str):
        with self.assertRaises(CRC.CensusError) as caught:
            self.census(text)
        self.assertIn(needle, str(caught.exception))


class CensusAcceptsThePinnedRender(CensusFixture):
    def test_the_pinned_render_passes(self):
        self.assertEqual(self.census(render())["objects"], 4)

    def test_chart_facts_come_from_metadata_and_values(self):
        self.assertEqual(self.facts.chart_name, FIXTURE_CHART_NAME)
        self.assertEqual(self.facts.peer_namespace, FIXTURE_PEER_NAMESPACE)
        self.assertEqual(self.facts.peer_app_name, FIXTURE_PEER_APP)
        self.assertEqual(self.facts.peer_instance, FIXTURE_PEER_INSTANCE)
        self.assertEqual(self.facts.service_port, FIXTURE_PORT)

    def test_a_render_carrying_a_multi_line_value_still_passes(self):
        # The acceptance companion to those refusals: tightening the
        # document boundary and transcribing the block-scalar rules must not
        # cost a render a legal multi-line value.
        #
        # the ported reader's differential review found this companion BLESSING A RENDER
        # THE REAL API SERVER PARTIALLY REFUSES. It carried the multi-line
        # value in a LABEL, and Kubernetes label values may not contain a
        # newline: measured against v1.36.3, `kubectl apply` exits 1, the
        # ServiceAccount, Service and Deployment are created, and the
        # NetworkPolicy alone is rejected -- the workload installs WITHOUT its
        # deny while the census reports "4 installable objects, exactly one
        # NetworkPolicy". The census refuses that render now; the shape lives
        # on in `test_a_multi_line_label_value_is_refused` below.
        #
        # A multi-line value belongs where Kubernetes permits arbitrary
        # strings, which is an ANNOTATION -- `kubectl apply` on exactly the
        # render below exits 0 and creates all four objects on that same
        # server. So the companion proves what it means to prove, and keeps
        # block-scalar coverage on BOTH sides: the annotation carries a blank
        # line, a more-indented line and a whitespace-only line, and the policy
        # label carries a strip-chomped block scalar whose value is a legal
        # label.
        note = ("  annotations:\n"
                "    note: |\n"
                "      first\n"
                "\n"
                "       indented\n"
                "       \n"
                "      last\n")
        base = render()
        account = ("kind: ServiceAccount\nmetadata:\n  name: %s\n" % FIXTURE_CHART_NAME)
        self.assertIn(account, base)
        label = "    reviewed: |-\n      by-hand\n"
        label_anchor = "    app.kubernetes.io/name: %s\n" % FIXTURE_CHART_NAME
        self.assertIn(label_anchor, base)
        mutated = (base
                   .replace(account, account + note, 1)
                   .replace(label_anchor, label_anchor + label, 1))
        self.assertNotEqual(mutated, base)
        result = self.census(mutated)
        self.assertEqual(result["objects"], 4)
        self.assertEqual(result["policy"]["metadata"]["labels"]["reviewed"], "by-hand")
        accounts = [o for o in CRC.flatten(parse(mutated))
                    if o["kind"] == "ServiceAccount"]
        self.assertEqual(len(accounts), 1)
        self.assertEqual(accounts[0]["metadata"]["annotations"]["note"],
                         "first\n\n indented\n \nlast\n")

    def test_the_peer_instance_may_be_stated_by_the_caller(self):
        facts = CRC.ChartFacts(self.chart, FIXTURE_RELEASE, FIXTURE_NAMESPACE, "another-instance")
        self.assertEqual(facts.peer_instance, "another-instance")
        with self.assertRaises(CRC.CensusError):
            CRC.census(render(), facts)


class CensusRefusesASecondPolicy(CensusFixture):
    """The exact shapes from the sibling repository's security receipt, and
    their cousins.
    """

    def test_the_spaced_key_same_file_shadow_policy(self):
        # The [P1] finding, verbatim: valid YAML, invisible to a raw-line
        # census, an additive allow-all for every Pod once applied.
        self.reject(render() + SHADOW_ALLOW_ALL_SPACED, "carries 2 NetworkPolicy objects")

    def test_a_quoted_key_shadow_policy(self):
        shadow = SHADOW_ALLOW_ALL_SPACED.replace("kind : NetworkPolicy", '"kind": NetworkPolicy')
        self.reject(render() + shadow, "carries 2 NetworkPolicy objects")

    def test_a_flow_style_shadow_document(self):
        shadow = ("---\n{apiVersion: networking.k8s.io/v1, kind: NetworkPolicy, "
                  "metadata: {name: shadow}, spec: {podSelector: {}, "
                  "policyTypes: [Egress], egress: [{}]}}\n")
        self.reject(render() + shadow, "carries 2 NetworkPolicy objects")

    def test_a_generic_list_wrapper_is_flattened_and_counted(self):
        wrapper = textwrap.dedent(
            """\
            ---
            apiVersion: v1
            kind: List
            items:
              - apiVersion: networking.k8s.io/v1
                kind: NetworkPolicy
                metadata:
                  name: shadow
                spec:
                  podSelector: {}
                  policyTypes: [Egress]
                  egress: [{}]
            """
        )
        self.reject(render() + wrapper, "carries 2 NetworkPolicy objects")

    def test_a_typed_list_wrapper_is_flattened_and_counted(self):
        wrapper = textwrap.dedent(
            """\
            ---
            apiVersion: networking.k8s.io/v1
            kind: NetworkPolicyList
            items:
              - apiVersion: networking.k8s.io/v1
                kind: NetworkPolicy
                metadata:
                  name: shadow
                spec:
                  podSelector: {}
                  policyTypes: [Egress]
                  egress: [{}]
            """
        )
        self.reject(render() + wrapper, "carries 2 NetworkPolicy objects")

    def test_a_wrapper_is_flattened_into_its_items_not_merely_rejected(self):
        # "Deliberately flattened and inspected", stated directly: the
        # wrapper disappears and the object it carried is what gets censused.
        # Without this, a wrapper could be refused for the wrong reason and
        # nobody would notice that flattening had stopped working.
        wrapper = textwrap.dedent(
            """\
            apiVersion: v1
            kind: List
            items:
              - apiVersion: v1
                kind: List
                items:
                  - apiVersion: networking.k8s.io/v1
                    kind: NetworkPolicy
                    metadata:
                      name: inner
              - apiVersion: v1
                kind: ConfigMap
                metadata:
                  name: also-inner
            """
        )
        flat = CRC.flatten(parse(wrapper))
        self.assertEqual([o["kind"] for o in flat], ["NetworkPolicy", "ConfigMap"])

    def test_a_wrapper_whose_items_cannot_be_inspected_is_refused(self):
        wrapper = "---\napiVersion: v1\nkind: List\nitems: elsewhere\n"
        self.reject(render() + wrapper, "cannot be inspected is refused")

    def test_a_wrapper_carrying_unaccounted_keys_is_refused(self):
        wrapper = "---\napiVersion: v1\nkind: List\nitems: []\nrules: [{}]\n"
        self.reject(render() + wrapper, "unexpected keys")

    def test_a_policy_under_another_kind_trips_the_inventory(self):
        foreign = textwrap.dedent(
            """\
            ---
            apiVersion: cilium.io/v2
            kind: CiliumNetworkPolicy
            metadata:
              name: shadow
            spec:
              endpointSelector: {}
            """
        )
        self.reject(render() + foreign, "object inventory is not the pinned one")

    def test_any_extra_document_trips_the_inventory(self):
        extra = "---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: extra\n"
        self.reject(render() + extra, "object inventory is not the pinned one")

    def test_a_document_nobody_spelled_is_refused(self):
        # The document-boundary shadow, at census scale. A top-level `null` is a whole
        # legal document; the reader used to END it at the next line and open a
        # SECOND document there, although the stream spelled no `---`. The
        # wrapper below carries no items, so the census counted the same four
        # objects and passed -- while PyYAML 6.0.3 refuses this stream outright.
        #
        # What `kubectl apply` does with it was measured during the ported
        # reader's work (not re-measured here), against
        # a real Kubernetes v1.36.3 API server, because the claim that stood
        # here -- that it "would install nothing" -- was false. It is a PARTIAL
        # APPLY: all four objects are created and the command THEN exits 1 on
        # the unreadable tail. That is the stronger reason to refuse, not the
        # weaker one: a half-applied file leaves a cluster in a state no render
        # describes. Put a policy in those `items` and the same trick is how a
        # second policy appears where a reviewer counted one.
        conjured = "---\nnull\napiVersion: v1\nkind: List\nitems: []\n"
        self.reject(render() + conjured,
                    "may begin only after a `---` document-start line")

    def test_a_block_scalar_that_swallows_the_next_line_is_refused(self):
        # The other document-boundary shadow: a whitespace-only line WIDER than the
        # block body sets the block's indentation past that body, so the oracle
        # reads an empty scalar and raises on the orphaned line. This reader
        # used to swallow the line as block content and read on. Written under
        # `metadata.labels`, whose CONTENT the census deliberately does not
        # pin, so the mutation reaches the reader instead of tripping a
        # different assertion first.
        base = render()
        anchor = "    app.kubernetes.io/name: %s\n" % FIXTURE_CHART_NAME
        self.assertIn(anchor, base)
        swallowed = base.replace(
            anchor, anchor + "    shadow-note: |\n       \n      shadow-marker\n", 1)
        self.assertNotEqual(swallowed, base)
        self.reject(swallowed, "unexpected indentation inside a block mapping")

    def test_a_missing_document_trips_the_inventory(self):
        text = render()
        head, _, _ = text.partition("---\napiVersion: apps/v1")
        self.reject(head, "object inventory is not the pinned one")


class CensusRefusesAWidenedPolicy(CensusFixture):
    """Every promise the census makes about the one policy it does find."""

    def widen(self, old: str, new: str) -> str:
        base = render()
        self.assertIn(old, base, "the mutation anchor is not in the render")
        mutated = base.replace(old, new, 1)
        self.assertNotEqual(mutated, base, "the mutation changed nothing")
        return mutated

    def test_one_empty_egress_rule_is_an_allowance(self):
        self.reject(self.widen("  egress: []", "  egress: [{}]"), "an exactly empty list is pinned")

    def test_an_empty_egress_mapping_is_refused(self):
        self.reject(self.widen("  egress: []", "  egress: {}"), "an exactly empty list is pinned")

    def test_a_dns_exception_is_refused(self):
        self.reject(self.widen("  egress: []",
                               "  egress:\n    - ports:\n        - port: 53\n          protocol: UDP"),
                    "an exactly empty list is pinned")

    def test_dropping_the_egress_policy_type_is_refused(self):
        self.reject(self.widen("    - Ingress\n    - Egress", "    - Ingress"), "policyTypes")

    def test_an_empty_pod_selector_is_refused(self):
        selector = ("  podSelector:\n    matchLabels:\n"
                    "      app.kubernetes.io/name: %s\n"
                    "      app.kubernetes.io/instance: %s" % (FIXTURE_CHART_NAME, FIXTURE_RELEASE))
        self.reject(self.widen(selector, "  podSelector: {}"), "podSelector")

    def test_a_pod_selector_naming_another_app_is_refused(self):
        self.reject(self.widen("      app.kubernetes.io/name: %s\n" % FIXTURE_CHART_NAME,
                               "      app.kubernetes.io/name: %s-elsewhere\n" % FIXTURE_CHART_NAME),
                    "podSelector")

    def test_a_second_ingress_rule_is_refused(self):
        self.reject(self.widen("          protocol: TCP", "          protocol: TCP\n    - {}"),
                    "ingress is not the one rule")

    def test_dropping_the_peer_instance_is_refused(self):
        self.reject(self.widen("\n              app.kubernetes.io/instance: %s" % FIXTURE_PEER_INSTANCE, ""),
                    "ingress is not the one rule")

    def test_an_unpinned_spec_key_is_refused(self):
        self.reject(self.widen("  egress: []", "  egress: []\n  shadowKey: true"), "spec keys")

    def test_a_respelled_but_widened_egress_is_still_refused(self):
        self.reject(self.widen("  egress: []", "  egress : [{}]"), "an exactly empty list is pinned")

    def test_a_respelled_but_unchanged_policy_still_passes(self):
        # Normalisation must not turn a legal respelling into a false alarm:
        # the census judges meaning, and this render means the same thing.
        base = render()
        respelled = (base
                     .replace("kind: NetworkPolicy", '"kind": NetworkPolicy', 1)
                     .replace("  egress: []", "  egress : []", 1))
        self.assertNotEqual(respelled, base)
        self.assertEqual(CRC.census(respelled, self.facts)["objects"], 4)

    def test_the_wrong_policy_entirely_is_refused(self):
        # The expectation is stated by the census, never read from the input:
        # a render whose policy is a different object cannot talk its way in.
        base = render()
        wrong = base.replace("  name: ingress-to-%s" % FIXTURE_CHART_NAME,
                             "  name: something-else", 1)
        self.reject(wrong, "is named")


class CensusRefusesWhatKubernetesRefuses(CensusFixture):
    """"N INSTALLABLE objects" has to mean objects Kubernetes will install.

    the ported reader's differential review measured the first census-vs-cluster gap, and it
    ran in the fatal direction: a render carrying a multi-line value in a LABEL
    censused GREEN while a real v1.36.3 API server refuses the NetworkPolicy
    for it and applies the ServiceAccount, Service and Deployment anyway --
    the workload up, its deny missing, the gate reporting four installable
    objects. Every rule below was probed from BOTH sides against that same
    server; the module's own "What `installable` has to mean" comment records
    the measurements this suite turns into assertions.
    """

    POLICY_LABELS = "    app.kubernetes.io/name: %s\n" % FIXTURE_CHART_NAME
    ACCOUNT = "kind: ServiceAccount\nmetadata:\n  name: %s\n" % FIXTURE_CHART_NAME

    def policy_label(self, spelling: str) -> str:
        base = render()
        self.assertIn(self.POLICY_LABELS, base)
        mutated = base.replace(self.POLICY_LABELS, self.POLICY_LABELS + spelling, 1)
        self.assertNotEqual(mutated, base)
        return mutated

    def account_block(self, block: str) -> str:
        base = render()
        self.assertIn(self.ACCOUNT, base)
        mutated = base.replace(self.ACCOUNT, self.ACCOUNT + block, 1)
        self.assertNotEqual(mutated, base)
        return mutated

    def object_with(self, **metadata) -> list:
        return [{"apiVersion": "v1", "kind": "ConfigMap",
                 "metadata": dict({"name": "probe"}, **metadata)}]

    def test_a_multi_line_label_value_is_refused(self):
        # The measured gap itself, in the shape the acceptance companion used
        # to bless. Against Kubernetes v1.36.3:
        #
        #     $ kubectl apply -f multiline-label.yaml     # rc=1
        #     serviceaccount/<chart> created
        #     service/<chart> created
        #     deployment.apps/<chart> created
        #     The NetworkPolicy "ingress-to-<chart>" is invalid:
        #       metadata.labels: Invalid value: "first\n\n indented\n \nlast\n"
        #
        # Three objects installed, the policy refused. The census said four.
        note = ("    note: |\n"
                "      first\n"
                "\n"
                "       indented\n"
                "       \n"
                "      last\n")
        self.reject(self.policy_label(note), "is not a valid label value")
        self.reject(self.policy_label(note), "NetworkPolicy ingress-to-%s" % FIXTURE_CHART_NAME)

    def test_label_values_follow_the_api_servers_own_rule(self):
        # Accepted on the real server, so accepted here.
        for written in ("''", "a", "MyValue", "'12345'", "a_b.c-d", "a" * 63,
                        "0.1.25", '"0.1.25"'):
            self.assertEqual(self.census(self.policy_label("    probe: %s\n" % written))["objects"],
                             4, written)
        # Refused on the real server, so refused here.
        for written in ("'-abc'", "'abc-'", "'.abc'", "'-'", "'a b'", "'a/b'",
                        "\xe9", "'_a'", "'a.'"):
            self.reject(self.policy_label("    probe: %s\n" % written),
                        "is not a valid label value")
        self.reject(self.policy_label("    probe: %s\n" % ("a" * 64)),
                    "is longer than 63 bytes")

    def test_label_keys_follow_the_api_servers_own_rule(self):
        for key in ("a", "a" * 63, "A_b.c-d", "example.com/a",
                    (("a" * 61 + ".") * 4 + "a" * 5) + "/a"):
            self.assertEqual(self.census(self.policy_label("    %s: enabled\n" % key))["objects"],
                             4, key)
        self.reject(self.policy_label("    a/b/c: enabled\n"), "carries more than one `/`")
        self.reject(self.policy_label("    /a: enabled\n"), "has an empty prefix")
        self.reject(self.policy_label("    example.com/: enabled\n"), "has an empty name part")
        self.reject(self.policy_label("    '': enabled\n"), "has an empty name part")
        self.reject(self.policy_label("    -a: enabled\n"), "is not a valid qualified name")
        self.reject(self.policy_label("    %s: enabled\n" % ("a" * 64)),
                    "has a name part longer than 63 bytes")
        # The prefix is a LOWERCASE DNS subdomain; the name part is not, which
        # is why `A_b.c-d` above is legal and these two are not.
        self.reject(self.policy_label("    Example.com/a: enabled\n"),
                    "not a lowercase DNS subdomain")
        self.reject(self.policy_label("    exa_mple.com/a: enabled\n"),
                    "not a lowercase DNS subdomain")
        self.reject(self.policy_label("    %s/a: enabled\n" % (("a" * 61 + ".") * 4 + "a" * 6)),
                    "has a prefix longer than 253 bytes")

    def test_annotation_keys_follow_the_label_key_rule_and_values_are_free(self):
        # The whole reason an annotation is the right home for a multi-line
        # value: Kubernetes validates annotation KEYS exactly as label keys and
        # leaves annotation VALUES alone. Measured both ways on the real
        # server -- a newline-bearing value and a non-ASCII one are both
        # accepted as annotation values and both refused as label values.
        free = ("  annotations:\n"
                "    note: |\n"
                "      first\n"
                "\n"
                "      last\n"
                "    unicode: \xe9\u4e2d\n")
        self.assertEqual(self.census(self.account_block(free))["objects"], 4)
        self.reject(self.account_block("  annotations:\n    a/b/c: enabled\n"),
                    "carries more than one `/`")
        self.reject(self.account_block("  annotations:\n    %s: enabled\n" % ("a" * 64)),
                    "has a name part longer than 63 bytes")
        self.reject(self.account_block("  annotations:\n    note: 5\n"),
                    "is 5, not a string")

    def test_the_annotation_size_ceiling_is_the_api_servers_own(self):
        # 262144 bytes accepted, 262145 refused -- measured with
        # `kubectl create --dry-run=server`, because `kubectl apply` adds its
        # own last-applied-configuration annotation and would have moved the
        # boundary. The sum is over every key AND value.
        limit = CRC.ANNOTATIONS_MAX_BYTES
        CRC.check_installable(self.object_with(annotations={"a": "x" * (limit - 1)}))
        with self.assertRaises(CRC.CensusError) as caught:
            CRC.check_installable(self.object_with(annotations={"a": "x" * limit}))
        self.assertIn("Kubernetes caps them at %d" % limit, str(caught.exception))
        # Counted in BYTES, not characters: two-byte characters count twice.
        CRC.check_installable(self.object_with(annotations={"a": "\xe9" * ((limit - 1) // 2)}))
        with self.assertRaises(CRC.CensusError):
            CRC.check_installable(self.object_with(annotations={"a": "\xe9" * (limit // 2)}))

    def test_a_non_string_label_value_is_refused(self):
        # "json: cannot unmarshal number into Go struct field
        # ObjectMeta.metadata.labels of type string" -- the server refuses
        # these before validation even runs.
        for written in ("5", "true", "1.5"):
            self.reject(self.policy_label("    probe: %s\n" % written), "not a string")

    def test_a_null_label_value_is_the_one_deliberate_over_refusal(self):
        # Measured: the API server ACCEPTS a null label value and stores an
        # empty label for it. This gate refuses it anyway -- coercing a value
        # nobody wrote into a value the render does not say is exactly the
        # guess every other rule here declines to make, and refusing is the
        # direction that cannot hide a policy. Pinned as an over-refusal so
        # nobody later mistakes it for the server's own rule.
        self.reject(self.policy_label("    probe: null\n"), "not a string")
        self.reject(self.policy_label("    probe: ~\n"), "not a string")
        # ... while the EMPTY STRING, which is what the server would have
        # stored, still reads and still passes.
        self.assertEqual(self.census(self.policy_label("    probe: ''\n"))["objects"], 4)

    def test_object_names_must_be_names_kubernetes_accepts(self):
        subdomain = ("a" * 61 + ".") * 4 + "a" * 5
        for name in ("a-b.c", "1abc", subdomain):
            CRC.check_installable([{"apiVersion": "v1", "kind": "ServiceAccount",
                                    "metadata": {"name": name}}])
        for name in ("a_b", "AbC", "abc.", "-abc", subdomain + "a"):
            with self.assertRaises(CRC.CensusError) as caught:
                CRC.check_installable([{"apiVersion": "v1", "kind": "ServiceAccount",
                                        "metadata": {"name": name}}])
            self.assertIn("lowercase RFC 1123 subdomain", str(caught.exception))
        for metadata in ({}, {"name": ""}, {"name": 5}):
            with self.assertRaises(CRC.CensusError):
                CRC.check_installable([{"apiVersion": "v1", "kind": "ServiceAccount",
                                        "metadata": metadata}])
        with self.assertRaises(CRC.CensusError) as caught:
            CRC.check_installable([{"apiVersion": "v1", "kind": "ServiceAccount"}])
        self.assertIn("carries no metadata mapping", str(caught.exception))

    def test_a_service_name_is_a_dns_label_not_a_subdomain(self):
        # The rule that would have been wrong if it had been reasoned about
        # instead of measured: a Service name may START WITH A DIGIT on
        # v1.36.3, but it may not contain a dot and may not exceed 63 bytes --
        # while a NetworkPolicy of the same name is fine.
        for name in ("abc", "1abc", "a-b", "s" + "a" * 62):
            CRC.check_installable([{"apiVersion": "v1", "kind": "Service",
                                    "metadata": {"name": name}}])
        for name in ("a.b", "Abc", "abc-", "s" + "a" * 63):
            with self.assertRaises(CRC.CensusError) as caught:
                CRC.check_installable([{"apiVersion": "v1", "kind": "Service",
                                        "metadata": {"name": name}}])
            self.assertIn("lowercase RFC 1123 LABEL", str(caught.exception))
        CRC.check_installable([{"apiVersion": "networking.k8s.io/v1",
                                "kind": "NetworkPolicy", "metadata": {"name": "a.b"}}])

    def test_the_namespace_must_be_a_name_a_namespace_could_have(self):
        CRC.check_installable(self.object_with(namespace="a-b"))
        for namespace in ("A", "a.b", "", "n" * 64, 5):
            with self.assertRaises(CRC.CensusError) as caught:
                CRC.check_installable(self.object_with(namespace=namespace))
            self.assertIn("no such namespace can ever exist", str(caught.exception))

    def test_every_selector_is_a_label_map_at_any_depth(self):
        # `matchLabels`, a Service's `spec.selector` and a Pod's `nodeSelector`
        # are all validated by the API server with the same rules, wherever
        # they sit -- `spec.podSelector.matchLabels`, `spec.selector` and
        # `spec.template.spec.nodeSelector` each refused `a\nb` and `a/b/c` on
        # the real server -- and so is a nested `spec.template.metadata`.
        bad = "a\nb"
        for obj in (
            {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
             "metadata": {"name": "p"}, "spec": {"podSelector": {"matchLabels": {"k": bad}}}},
            {"apiVersion": "v1", "kind": "Service", "metadata": {"name": "s"},
             "spec": {"selector": {"k": bad}}},
            {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "d"},
             "spec": {"template": {"spec": {"nodeSelector": {"k": bad}}}}},
            {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "d"},
             "spec": {"template": {"metadata": {"labels": {"k": bad}}}}},
            {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "d"},
             "spec": {"selector": {"matchLabels": {"a/b/c": "v"}}}},
        ):
            with self.assertRaises(CRC.CensusError):
                CRC.check_installable([obj])
        # ... and a Service selector that is not a mapping at all.
        with self.assertRaises(CRC.CensusError):
            CRC.check_installable([{"apiVersion": "v1", "kind": "Service",
                                    "metadata": {"name": "s"},
                                    "spec": {"selector": "elsewhere"}}])

    def test_a_label_spelled_matchLabels_is_still_a_label(self):
        # The companion that keeps the selector walk from over-reaching:
        # ObjectMeta is checked and then not descended into, so a label whose
        # KEY happens to be `matchLabels` is an ordinary label -- Kubernetes
        # installs it, and refusing it would be a false alarm.
        CRC.check_installable(self.object_with(labels={"matchLabels": "v",
                                                       "nodeSelector": "v"}))
        CRC.check_installable(self.object_with(annotations={"matchLabels": "a\nb"}))

    def test_the_pinned_render_is_not_over_refused(self):
        # The whole point of the acceptance companions, restated for this
        # class: every rule above must leave the real shape alone. The fixture
        # render carries `app.kubernetes.io/*` keys, a quoted version value,
        # matchLabels on both selector sides and a namespace -- and it passes.
        self.assertEqual(self.census(render())["objects"], 4)


class PolicyIsBoundToTheWorkload(CensusFixture):
    """A policy that selects no Pod governs nothing, however perfect its text.

    Every assertion in the classes above reads the POLICY. None of them can
    notice `spec.podSelector` drifting off the workload, because the policy's
    own text stays untouched and correct while the Deployment's Pod-template
    labels move out from under it -- and Kubernetes then matches the policy
    against zero Pods, leaving those Pods with full outbound access. These
    tests pin the assertion that closes that, in both directions and in the
    two forms of over-selection.
    """

    POLICY_DOCUMENT_END = "---\napiVersion: v1\nkind: ServiceAccount"

    def policy_document(self, text: str) -> str:
        head, marker, _ = text.partition(self.POLICY_DOCUMENT_END)
        self.assertEqual(marker, self.POLICY_DOCUMENT_END, "the render lost its shape")
        return head

    def bind(self, *, namespace=FIXTURE_NAMESPACE, pod_selector=None, pod_labels=None,
             workload_selector=None, workloads=1, template=True):
        """Call the binding assertion directly, on objects built by hand."""
        if pod_selector is None:
            pod_selector = {"matchLabels": {"app.kubernetes.io/name": FIXTURE_CHART_NAME,
                                            "app.kubernetes.io/instance": FIXTURE_RELEASE}}
        if pod_labels is None:
            pod_labels = {"app.kubernetes.io/name": FIXTURE_CHART_NAME,
                          "app.kubernetes.io/instance": FIXTURE_RELEASE}
        if workload_selector is None:
            workload_selector = {"matchLabels": dict(pod_labels)}
        policy = {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
                  "metadata": {"name": "p", "namespace": FIXTURE_NAMESPACE},
                  "spec": {"podSelector": pod_selector}}
        spec = {"selector": workload_selector}
        if template:
            spec["template"] = {"metadata": {"labels": pod_labels}}
        objects = [policy]
        for index in range(workloads):
            objects.append({"apiVersion": "apps/v1", "kind": "Deployment",
                            "metadata": {"name": "d%d" % index, "namespace": namespace},
                            "spec": spec})
        return CRC.bind_policy_to_workload(objects, policy)

    def refuse(self, needle: str, **kwargs):
        with self.assertRaises(CRC.CensusError) as caught:
            self.bind(**kwargs)
        self.assertIn(needle, str(caught.exception))

    # --- the assertion is not vacuous in the accepting direction -----------

    def test_the_pinned_render_binds_its_one_workload(self):
        bound = CRC.census(render(), self.facts)
        self.assertEqual(bound["workload"]["kind"], "Deployment")
        self.assertEqual(bound["workload"]["metadata"]["namespace"], FIXTURE_NAMESPACE)

    def test_pod_labels_beyond_the_selector_still_bind(self):
        # Kubernetes matchLabels is a SUBSET test, and this gate must not be
        # stricter than Kubernetes: the real render's Pods carry
        # `managed-by` and `version` labels the selector never mentions.
        bound = self.bind(pod_labels={"app.kubernetes.io/name": FIXTURE_CHART_NAME,
                                      "app.kubernetes.io/instance": FIXTURE_RELEASE,
                                      "app.kubernetes.io/managed-by": "Helm",
                                      "extra": "value"})
        self.assertEqual(bound["pod_labels"]["extra"], "value")

    # --- direction 1: the workload moves, the policy stays ------------------

    def test_retargeting_the_pod_template_labels_is_refused(self):
        # THE HOLE, as a whole render: the policy document comes out
        # byte-identical, so nothing that reads the policy can see this.
        base = render()
        mutated = CRC.mutate(base, self.facts, "workload-pod-labels-retargeted")
        self.assertEqual(self.policy_document(mutated), self.policy_document(base),
                         "the mutation must leave the policy untouched to prove the point")
        self.reject(mutated, "selects ZERO of this workload's Pods")

    def test_dropping_the_instance_label_from_the_pods_is_refused(self):
        base = render()
        mutated = CRC.mutate(base, self.facts, "workload-pod-labels-drop-the-instance")
        self.assertEqual(self.policy_document(mutated), self.policy_document(base))
        self.reject(mutated, "selects ZERO of this workload's Pods")

    def test_moving_the_workload_to_another_namespace_is_refused(self):
        # A NetworkPolicy governs Pods in its OWN namespace, so the same
        # zero-Pod outcome arrives by a road the label comparison never sees.
        base = render()
        mutated = CRC.mutate(base, self.facts, "workload-moved-to-another-namespace")
        self.assertEqual(self.policy_document(mutated), self.policy_document(base))
        self.reject(mutated, "governs Pods in its OWN namespace only")

    def test_a_deployment_that_does_not_match_its_own_template_is_refused(self):
        base = render()
        mutated = CRC.mutate(base, self.facts,
                             "workload-selector-detached-from-its-template")
        self.assertEqual(self.policy_document(mutated), self.policy_document(base))
        self.reject(mutated, "creates no Pods at all")

    # --- direction 2: the policy moves, the workload stays ------------------

    def test_the_binding_alone_refuses_a_selector_that_names_another_app(self):
        # The pinned-object comparison in `census` catches this too. That is
        # deliberate redundancy across two INDEPENDENT derivations -- one from
        # constants, one from the rendered workload -- so this test calls the
        # binding directly to show it does not lean on the other.
        self.refuse("selects ZERO of this workload's Pods",
                    pod_selector={"matchLabels": {
                        "app.kubernetes.io/name": FIXTURE_CHART_NAME + "-elsewhere",
                        "app.kubernetes.io/instance": FIXTURE_RELEASE}})

    # --- direction 3: it matches the workload, AND something unintended -----

    def test_a_selector_without_the_instance_key_is_refused_though_it_matches(self):
        # The subtle one. `{name}` is a subset of the Pod labels, so the match
        # test PASSES -- and the selector also governs every other release of
        # this chart in the namespace. Refused on the identity keys instead.
        labels = {"app.kubernetes.io/name": FIXTURE_CHART_NAME,
                  "app.kubernetes.io/instance": FIXTURE_RELEASE}
        selector = {"app.kubernetes.io/name": FIXTURE_CHART_NAME}
        self.assertEqual(CRC._unsatisfied(selector, labels), [],
                         "this selector really does match the workload")
        self.refuse("omits", pod_selector={"matchLabels": selector})

    def test_an_empty_pod_selector_is_refused_and_the_reason_is_recorded(self):
        # The deliberate ruling, pinned so a later reader cannot mistake it
        # for an oversight: `podSelector: {}` selects EVERY Pod in the
        # namespace, which for the egress half denies more, not less. It is
        # refused because it would make this assertion vacuous -- it matches
        # this workload for the same reason it matches everything, so the
        # drift above becomes undetectable again by emptying the selector --
        # and because the same object's ingress allow-list would then apply
        # to co-tenant Pods nobody reviewed.
        self.refuse("would make this assertion vacuous", pod_selector={})
        self.refuse("an always-true selector is not a binding",
                    pod_selector={"matchLabels": {}})

    def test_match_expressions_are_refused_rather_than_guessed_at(self):
        self.refuse("refused rather than guessed at", pod_selector={
            "matchExpressions": [{"key": "app.kubernetes.io/name", "operator": "Exists"}]})
        self.refuse("refused rather than guessed at", pod_selector={
            "matchLabels": {"app.kubernetes.io/name": FIXTURE_CHART_NAME,
                            "app.kubernetes.io/instance": FIXTURE_RELEASE},
            "matchExpressions": []})

    # --- the workload side has to be knowable at all ------------------------

    def test_the_render_must_carry_exactly_one_workload(self):
        self.refuse("exactly one is required", workloads=0)
        self.refuse("exactly one is required", workloads=2)

    def test_a_pod_template_without_labels_cannot_be_bound(self):
        self.refuse("declares no spec.template.metadata.labels", template=False)
        self.refuse("no labels at all", pod_labels={},
                    workload_selector={"matchLabels": {"a": "b"}})

    def test_a_non_string_label_is_refused_rather_than_compared(self):
        with self.assertRaises(CRC.CensusError) as caught:
            self.bind(pod_labels={"app.kubernetes.io/name": 5})
        self.assertIn("not a string label", str(caught.exception))

    def test_the_workload_selector_must_be_a_matchLabels_selector_too(self):
        self.refuse("exactly one key -- matchLabels -- is accepted here",
                    workload_selector={})


class MutationBattery(CensusFixture):
    def test_every_mutation_name_is_unique(self):
        names = [name for name, _ in CRC.mutations(self.facts)]
        self.assertEqual(len(names), len(set(names)))

    def test_an_unknown_mutation_is_refused(self):
        with self.assertRaises(CRC.CensusError):
            CRC.mutate(render(), self.facts, "no-such-mutation")

    def test_yaml_forbidden_code_point_mutation_is_killed_by_the_reader(self):
        hostile = CRC.mutate(render(), self.facts,
                             "shadow-yaml-forbidden-code-point")
        self.assertIn("\ufffe", hostile)
        with self.assertRaises(CRC.CensusError) as caught:
            CRC.census(hostile, self.facts)
        self.assertIn("YAML-forbidden code point U+FFFE", str(caught.exception))

    def test_the_gate_script_pins_the_battery_at_its_real_size(self):
        # One fact in two files: the shell floor and the battery itself.
        # If they can disagree, the floor is decoration.
        script = GATE_SCRIPT.read_text(encoding="utf-8")
        line = [l for l in script.split("\n") if l.startswith("minimum_census_mutations=")]
        self.assertEqual(len(line), 1, "the gate script must pin the census battery exactly once")
        pinned = int(line[0].split("=", 1)[1])
        self.assertEqual(pinned, len(CRC.mutations(self.facts)))


class RealChartFiles(unittest.TestCase):
    """The reader must read this repository's own chart files, not just fixtures."""

    def test_the_real_chart_metadata_and_values_parse(self):
        facts = CRC.ChartFacts(REAL_CHART, "release", "namespace")
        self.assertEqual(facts.chart_name, "lidersea-com")
        self.assertTrue(facts.peer_namespace)
        self.assertTrue(facts.peer_app_name)
        self.assertTrue(facts.peer_instance)
        self.assertIsInstance(facts.service_port, int)

    def test_the_template_source_parses_only_after_helm_renders_it(self):
        # Guards a tempting shortcut: the TEMPLATE is not YAML (it carries Go
        # template actions), so nothing here may census template source in
        # place of a render.
        template = (REAL_CHART / "templates" / "network-policy.yaml").read_text(encoding="utf-8")
        self.assertIn("{{", template)
        with self.assertRaises(CRC.CensusError):
            CRC.parse_documents(template, "<template>")


if __name__ == "__main__":
    unittest.main()
