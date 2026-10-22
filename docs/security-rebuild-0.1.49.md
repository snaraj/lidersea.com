# Security rebuild 0.1.49

This source change rebuilds the site with the fixed Go 1.26.10 and Node
24.22.1 toolchains. Node's bundled npm is 11.19.1. The ratings collector
remains off, the shipped snapshot has no feed URLs, and the chart still
requires denied egress. Publishing source or an image does not activate a
running deployment.

## Public artifact selection

The Dockerfile binds these multi-architecture image indices:

| Input | SHA-256 |
| --- | --- |
| Node 24.22.1 trixie-slim | `43b9ba1142b8dcf33fa8f922ca1be85714adc444e0586c7cf7726daaeabc1bea` |
| Go 1.26.10 trixie | `909771fef53e3dcb0950255f0c9a8b4728c3b841e61509c7b29b098de7ee02d4` |
| Distroless static-debian13 nonroot | `d62067879de890a1def9da0e7766b7d20810a5e5555cef8506b752437d7a3e88` |

Resolve and verify each pinned public artifact, rather than trusting its tag.
The distroless amd64 child is
`d4df213e27178b79e05ee2bdf8a23d8c54baab3b5a0dc083b039ad9929fa4219`;
the arm64 child is
`8a198f3cf5e9b249577c18010ec18382a3e9f94a6e5676d57b1ff8438ae113e9`.
Their complete `/etc/ssl/certs/ca-certificates.crt` files are byte-identical:
SHA-256 `e9c7b63ee2623386e9b0a3ee32f499d01a8ea23dc83b8383ddff9f8e749543b7`.
The image trust directory contains only that bundle. The selection uses the
vendor's public image directly, with no host-derived or custom CA material.

## Certificate verification evidence

The public [negative-chain archive](https://emudhra.we-have-a-problem.com/chains.zip)
used on 2026-10-21 has SHA-256
`8a2edc81b6c51e3ad27d45ca1e441ec84c961e2dee0fc547f2a02c0f74315f95`.
All twelve PEM chains were verified with their corresponding DNS names and
server-auth purpose, using the complete candidate bundle and no ambient CA
file or directory. Each fails with an unavailable issuer; valid chains for
GitHub, GHCR and Python pass. Reproduce the OpenSSL check for each fixture:

```sh
openssl verify -CAfile candidate-ca.pem -no-CApath -no-CAstore \
  -purpose sslserver -verify_hostname "$fixture_hostname" \
  -untrusted "$fixture_pem" "$fixture_pem"
```

A fresh Linux/arm64 process compiled with the pre-fix Go 1.27.2 additionally
used `x509.SystemCertPool()` with no trust overrides. In the previous pinned
distroless image it accepts all twelve negative chains; in the selected image
it rejects all twelve. The same three valid controls pass both. This isolates
the trust-store repair from Go's newer built-in distrust behavior. The actual
application build uses fixed Go 1.26.10, independently of that diagnostic.
These checks establish artifact trust behavior, not evidence of interception
or a live application probe.

The full source, dependency, image, signature and release gates still apply.
Deployment must separately bind the published signed image digest and verify
serving health; neither a local build nor a merged source change proves that
running Pods use the repaired artifact. A rollback must retain a patched
binary and trust store rather than restoring the affected artifact.
