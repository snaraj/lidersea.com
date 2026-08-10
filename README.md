# lidersea.com

[![PR gate](https://github.com/snaraj/lidersea.com/actions/workflows/pr-gate.yml/badge.svg?branch=main)](https://github.com/snaraj/lidersea.com/actions/workflows/pr-gate.yml)
[![CodeQL](https://github.com/snaraj/lidersea.com/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/snaraj/lidersea.com/actions/workflows/codeql.yml)
[![Release](https://img.shields.io/github/v/release/snaraj/lidersea.com?sort=semver)](https://github.com/snaraj/lidersea.com/releases)
[![Go coverage](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fsnaraj%2Flidersea.com%2Fbadges%2Fgo-coverage.json&label=go%20coverage)](https://github.com/snaraj/lidersea.com/actions/workflows/pr-gate.yml)
[![Frontend coverage](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fsnaraj%2Flidersea.com%2Fbadges%2Ffrontend-coverage.json&label=frontend%20coverage)](https://github.com/snaraj/lidersea.com/actions/workflows/pr-gate.yml)
[![Go version](https://img.shields.io/github/go-mod/go-version/snaraj/lidersea.com)](go.mod)
[![License: MIT](https://img.shields.io/github/license/snaraj/lidersea.com)](LICENSE)

The web home of Lidersea — luxury yacht maintenance, customization, and
detailing. This site is built to the same standard as the craft it
represents: a Svelte frontend embedded into a single dependency-free Go
binary, shipped as a distroless multi-arch container and a Helm chart,
deployed by digest behind Cloudflare.

## How it works

```mermaid
flowchart LR
    dev[Svelte source] -->|vite build| dist[Hashed static bundle]
    dist -->|go:embed| bin[Go binary]
    bin -->|3-stage build| img["Distroless image (amd64+arm64)"]
    chart[Helm chart] --> rel
    img -->|cosign signed, digest pinned| rel[Release vX.Y.Z]
    rel -->|GitOps pulls by digest| k8s[Kubernetes on the platform]
    k8s --> cf[Cloudflare Tunnel] --> visitors((Visitors))
```

The Go service serves the embedded bundle with strict caching, conditional
requests, security headers, and `/livez` + `/readyz` probes on port 8080,
with no runtime dependency beyond the Go standard library.

## Development

```sh
# Frontend first — the Go embed test expects the built bundle.
cd frontend
npm ci --ignore-scripts
npm run check && npm test && npm run build

# Backend
cd ..
go vet ./... && go test ./...

# Container (both production architectures)
docker build .
```

Toolchain pins live in CI (`node 24.19.0`, `npm 11.17.0`, `go 1.26.5`);
CI is authoritative.

## Releases

Pushing `vX.Y.Z` (matching `VERSION` and the chart version — CI enforces
the three-way lock) publishes everything at once:

- `ghcr.io/snaraj/lidersea-com:vX.Y.Z` — multi-arch image, keyless-signed
  (Cosign), with SBOM and SLSA provenance; deployment consumes the digest.
- `ghcr.io/snaraj/charts/lidersea-com` — the Helm chart as a signed OCI
  artifact at the same version.
- A GitHub Release recording the immutable digests.

Version tags are immutable and never reused — the publisher refuses, with
no override. History lives in [CHANGELOG.md](CHANGELOG.md); the security
posture in [SECURITY.md](SECURITY.md).

## Media

Small UI assets live under `frontend/src/assets/` in documented categories
with size ceilings. Heavy media (portfolio video, high-resolution
photography, audio) never enters this repository or the image — it is
served from dedicated platform storage, built for it.

## License

Code is [MIT](LICENSE). Site content — text, images, video, audio,
branding — is **all rights reserved**; the license does not extend to it.
