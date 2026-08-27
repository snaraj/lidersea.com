#!/usr/bin/env bash
# Install the exact pinned CI tools with SHA-256-verified downloads, outside
# the checkout so tree scanners never scan the scanners. Mirrors the pattern
# proven in snaraj/website-infrastructure.
set -euo pipefail

GITLEAKS_VERSION=v8.30.1
GITLEAKS_SHA256=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb
HELM_VERSION=v3.19.2
HELM_SHA256=2114c9dea2844dce6d0ee2d792a9aae846be8cf53d5b19dc2988b5a0e8fec26e
TRIVY_VERSION=v0.73.0
TRIVY_SHA256=2edd39da482bb4e9831962487b68f68e3928ec3137794757f54d00383d79547b

: "${RUNNER_TEMP:?GitHub Actions must provide RUNNER_TEMP}"
install_root="$(mktemp -d "${RUNNER_TEMP%/}/site-ci-tools.XXXXXX")"
download_root="$(mktemp -d "${RUNNER_TEMP%/}/site-ci-downloads.XXXXXX")"
trap 'rm -rf -- "${download_root}"' EXIT

fetch_verify() {
  local url="$1" sha="$2" out="$3"
  curl --proto '=https' --tlsv1.2 -sSfL "${url}" -o "${out}"
  printf '%s  %s\n' "${sha}" "${out}" | sha256sum -c - >/dev/null
}

fetch_verify \
  "https://github.com/gitleaks/gitleaks/releases/download/${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION#v}_linux_x64.tar.gz" \
  "${GITLEAKS_SHA256}" "${download_root}/gitleaks.tar.gz"
tar -xzf "${download_root}/gitleaks.tar.gz" -C "${download_root}" gitleaks
install -m 0755 "${download_root}/gitleaks" "${install_root}/gitleaks"

fetch_verify \
  "https://get.helm.sh/helm-${HELM_VERSION}-linux-amd64.tar.gz" \
  "${HELM_SHA256}" "${download_root}/helm.tar.gz"
tar -xzf "${download_root}/helm.tar.gz" -C "${download_root}" linux-amd64/helm
install -m 0755 "${download_root}/linux-amd64/helm" "${install_root}/helm"

# Install the scanner directly from Aqua's immutable release archive. Do not
# add trivy-action/setup-trivy: the Trivy action ecosystem suffered a 2026
# tag/Release compromise, while this path has one reviewed archive URL and one
# repository-owned SHA-256 lock.
fetch_verify \
  "https://github.com/aquasecurity/trivy/releases/download/${TRIVY_VERSION}/trivy_${TRIVY_VERSION#v}_Linux-64bit.tar.gz" \
  "${TRIVY_SHA256}" "${download_root}/trivy.tar.gz"
tar -xzf "${download_root}/trivy.tar.gz" -C "${download_root}" trivy
install -m 0755 "${download_root}/trivy" "${install_root}/trivy"

echo "${install_root}" >> "${GITHUB_PATH}"
"${install_root}/gitleaks" version
"${install_root}/helm" version --short
test "$("${install_root}/trivy" --version | awk 'NR == 1 {print $2}')" = "${TRIVY_VERSION#v}"
"${install_root}/trivy" --version
