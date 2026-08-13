#!/usr/bin/env bash
# chart-ingress-pin — render the chart and prove its ingress NetworkPolicy
# admits EXACTLY ONE peer, named by every fact it takes to name one connector:
# peer namespace + peer app name + peer instance.
#
# Why the instance matters. The peer namespace is shared: it holds several
# per-site connectors that publish the SAME app.kubernetes.io/name and are
# separated only by app.kubernetes.io/instance. Select on namespace and app
# name alone and the policy admits all of them — narrow to read, wide in
# effect. The deployed policy has always carried the instance pin; this gate
# exists so no render can ship a policy weaker than it.
#
# HOW THIS GATE READS THE RENDER — the security-critical part. It does NOT
# count `- from:` lines and inspect the first: that is bypassable. A second
# ingress rule with no `from` — an empty rule (`- {}`), a flow-style rule, or a
# ports-only rule — renders an allow-all while a `from`-line count stays at
# one, and reading only the first rule never sees it. Instead this gate
# extracts the whole rendered `spec.ingress` sub-tree by indentation (the
# policy's `egress: []` and everything else in the spec are outside that
# sub-tree and untouched) and asserts, structurally:
#   1. the value is a block sequence of EXACTLY ONE rule item, and
#   2. that sub-tree equals, in full, the one rule built from the values —
# so ANY extra rule, extra peer, dropped selector, or altered field, in block
# or flow style, fails the gate. The parser is stdlib Python (this repository
# is stdlib-only): no PyYAML, no yq, so it runs wherever helm does.
#
# Three assertions, all failing closed:
#   a. the DEFAULT render — no flags, shipped values — is exactly one rule
#      pinning namespace + app name + instance, compared in full;
#   b. a blank instance and an absent instance are BOTH refused by schema
#      validation, and refused by name, so nothing can render unpinned;
#   c. a different instance moves the pin: the render is again exactly one
#      rule, now carrying the overridden instance and none of the default,
#      with app name and namespace unchanged — precisely why the app name
#      alone cannot tell two connectors apart.
#
# Expectations come from chart/values.yaml, the provider binding point, so the
# peer identity is stated in exactly one place and this file names no provider.
set -euo pipefail

chart_dir="${CHART_DIR:-chart}"
kube_version="${KUBE_VERSION:-v1.36.0}"
release_name=ingress-pin
values_file="${chart_dir}/values.yaml"

# Stands in for any other connector sharing the peer namespace. Deliberately
# not the default.
probe_instance=another-connector-instance

fail() {
  printf 'chart-ingress-pin: %s\n' "$1" >&2
  exit 1
}

# The structural core, stdlib Python only. It carries no provider name and no
# single-quote character, so it embeds cleanly here. Modes:
#   read-values <values.yaml>                 prints ns, app, instance, port
#   assert-one-rule <ns> <app> <inst> <port>  reads a render on stdin, asserts
py_core='
import sys

def die(msg):
    sys.stderr.write("chart-ingress-pin: " + msg + "\n")
    sys.exit(1)

def indent_of(s):
    return len(s) - len(s.lstrip(" "))

def block_scalars(lines, header):
    out = {}
    inside = False
    for line in lines:
        if line.rstrip() == header + ":":
            inside = True
            continue
        if inside:
            if line.strip() == "":
                continue
            if indent_of(line) == 0:
                break
            if indent_of(line) == 2 and not line.lstrip().startswith("#"):
                k, sep, v = line.strip().partition(":")
                if not sep:
                    continue
                v = v.split(" #", 1)[0].strip().strip(chr(34) + chr(39))
                out[k.strip()] = v
    return out

def cmd_read_values(path):
    with open(path) as fh:
        lines = fh.read().split("\n")
    ing = block_scalars(lines, "ingress")
    svc = block_scalars(lines, "service")
    for key in ("peerNamespace", "peerAppName", "peerInstance"):
        if not ing.get(key):
            die("chart values declare no ingress." + key)
    if not svc.get("port"):
        die("chart values declare no service.port")
    sys.stdout.write("\n".join([ing["peerNamespace"], ing["peerAppName"],
                                ing["peerInstance"], svc["port"]]) + "\n")

def extract_ingress(text):
    lines = text.split("\n")
    spec_idx = [i for i, l in enumerate(lines) if l.rstrip() == "spec:"]
    if len(spec_idx) != 1:
        die("expected exactly one top-level spec:; found %d" % len(spec_idx))
    i = spec_idx[0] + 1
    ing_i = None
    while i < len(lines):
        l = lines[i]
        if l.strip() == "":
            i += 1
            continue
        if indent_of(l) == 0:
            break
        s = l.strip()
        if indent_of(l) == 2 and s.split(":", 1)[0] == "ingress":
            if s != "ingress:":
                die("spec.ingress rendered inline (%r); expected a block sequence" % s)
            ing_i = i
            break
        i += 1
    if ing_i is None:
        die("no spec.ingress block in the render")
    block = []
    j = ing_i + 1
    while j < len(lines):
        l = lines[j]
        if l.strip() == "":
            block.append(l)
            j += 1
            continue
        if l.rstrip() == "---":
            break
        if indent_of(l) <= 2:
            break
        block.append(l)
        j += 1
    while block and block[-1].strip() == "":
        block.pop()
    if not block:
        die("spec.ingress block is empty")
    return block

def cmd_assert(ns, app, inst, port):
    block = extract_ingress(sys.stdin.read())
    rule_items = [l for l in block if indent_of(l) == 4 and l.lstrip().startswith("-")]
    if len(rule_items) != 1:
        die("spec.ingress is a sequence of %d rules; exactly one is allowed, "
            "so a second rule cannot widen the policy unseen:\n%s"
            % (len(rule_items), "\n".join(block)))
    expected = [
        "    - from:",
        "        - namespaceSelector:",
        "            matchLabels:",
        "              kubernetes.io/metadata.name: " + ns,
        "          podSelector:",
        "            matchLabels:",
        "              app.kubernetes.io/name: " + app,
        "              app.kubernetes.io/instance: " + inst,
        "      ports:",
        "        - port: " + port,
        "          protocol: TCP",
    ]
    if block != expected:
        die("the rendered spec.ingress does not equal the one rule declared "
            "in values.\nexpected:\n%s\n\nrendered:\n%s"
            % ("\n".join(expected), "\n".join(block)))

mode = sys.argv[1]
if mode == "read-values":
    cmd_read_values(sys.argv[2])
elif mode == "assert-one-rule":
    cmd_assert(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])
else:
    die("unknown mode " + mode)
'

# render prints the NetworkPolicy document alone, at the platform Kubernetes
# target. Extra arguments go straight to helm.
render() {
  helm template "${release_name}" "${chart_dir}" \
    --kube-version "${kube_version}" \
    --show-only templates/network-policy.yaml "$@"
}

# The peer identity comes from values (the single binding point), never from
# this script.
if ! readvals="$(python3 -c "${py_core}" read-values "${values_file}")"; then
  fail "could not read the peer identity from ${values_file}"
fi
{
  IFS= read -r peer_namespace
  IFS= read -r peer_app_name
  IFS= read -r peer_instance
  IFS= read -r service_port
} <<EOF
${readvals}
EOF

[ -n "${peer_namespace}" ] || fail "chart values declare no ingress.peerNamespace"
[ -n "${peer_app_name}" ] || fail "chart values declare no ingress.peerAppName"
[ -n "${peer_instance}" ] || fail "chart values declare no ingress.peerInstance"
[ -n "${service_port}" ] || fail "chart values declare no service.port"
[ "${peer_instance}" != "${probe_instance}" ] ||
  fail "the probe instance must differ from the default, or assertion (c) proves nothing"

# (a) The default render is exactly one rule pinning the full peer identity.
render | python3 -c "${py_core}" assert-one-rule \
  "${peer_namespace}" "${peer_app_name}" "${peer_instance}" "${service_port}"
echo "chart-ingress-pin: (a) default render is exactly one rule pinning namespace + app name + instance"

# (b) A blank instance and an absent instance both fail schema validation, by
# name, so an unpinned peer selector is unrepresentable.
for blank_value in '' null; do
  if refusal="$(render --set "ingress.peerInstance=${blank_value}" 2>&1)"; then
    fail "ingress.peerInstance='${blank_value}' rendered instead of failing validation — an unpinned peer selector must be unrepresentable"
  fi
  case "${refusal}" in
    *peerInstance*) ;;
    *) fail "ingress.peerInstance='${blank_value}' was refused, but not over the instance pin: ${refusal}" ;;
  esac
done
echo "chart-ingress-pin: (b) blank and absent instance both refused by schema validation"

# (c) A different instance moves the pin and nothing else: again exactly one
# rule, now the probe instance, the default gone, app name and namespace
# unchanged. Asserting the whole rule equals the expected block with the probe
# instance substituted proves all three at once.
render --set "ingress.peerInstance=${probe_instance}" | python3 -c "${py_core}" assert-one-rule \
  "${peer_namespace}" "${peer_app_name}" "${probe_instance}" "${service_port}"
echo "chart-ingress-pin: (c) the instance discriminates peers sharing one app name"

echo "chart-ingress-pin: the rendered policy admits exactly one connector"
