#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 4 ]; then
  printf 'usage: %s <ghcr-alias> <expected-digest|-> <accept> <label>\n' "$0" >&2
  exit 2
fi

alias_reference="$1"
expected_digest="$2"
accept="$3"
label="$4"
: "${RUNNER_TEMP:?GitHub Actions must provide RUNNER_TEMP}"
: "${GITHUB_ACTOR:?GitHub Actions must provide GITHUB_ACTOR}"
: "${GHCR_PASSWORD:?GitHub Actions must provide GHCR_PASSWORD}"

if [[ ! "${alias_reference}" =~ ^ghcr\.io/[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)+:[A-Za-z0-9_.-]+$ ]]; then
  printf 'DENY: registry alias is not an exact ghcr.io name:tag reference\n' >&2
  exit 1
fi
if [ "${expected_digest}" != - ] && \
   [[ ! "${expected_digest}" =~ ^sha256:[0-9a-f]{64}$ ]]; then
  printf 'DENY: expected registry alias digest is malformed\n' >&2
  exit 1
fi
if [[ ! "${label}" =~ ^[a-z0-9-]+$ ]] || [ -z "${accept}" ]; then
  printf 'DENY: registry alias resolver label or media type is malformed\n' >&2
  exit 1
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
contract="${script_dir}/release_contract.py"
reference="${alias_reference#ghcr.io/}"
repository="${reference%:*}"
version="${reference##*:}"
credentials="${RUNNER_TEMP}/${label}.netrc"
token_file="${RUNNER_TEMP}/${label}-token.json"
body="${RUNNER_TEMP}/${label}-manifest.json"
headers="${RUNNER_TEMP}/${label}-headers.txt"
trap 'rm -f -- "${credentials}" "${token_file}" "${body}" "${headers}"' EXIT
umask 077
printf 'machine ghcr.io\nlogin %s\npassword %s\n' \
  "${GITHUB_ACTOR}" "${GHCR_PASSWORD}" > "${credentials}"
curl --fail-with-body --silent --show-error --location \
  --proto '=https' --tlsv1.2 --netrc-file "${credentials}" \
  --get --data-urlencode "scope=repository:${repository}:pull" \
  'https://ghcr.io/token' > "${token_file}"
token="$(python3 -I -B "${contract}" registry-token --token-json "${token_file}")"
rm -f -- "${credentials}" "${token_file}"

resolve_once() {
  local status
  rm -f -- "${body}" "${headers}"
  if ! status="$(curl --silent --show-error --location \
    --proto '=https' --tlsv1.2 --output "${body}" \
    --dump-header "${headers}" --write-out '%{http_code}' \
    --header "Authorization: Bearer ${token}" \
    --header "Accept: ${accept}" \
    "https://ghcr.io/v2/${repository}/manifests/${version}")"; then
    return 75
  fi
  local -a args=(
    registry-manifest
    --http-status "${status}"
    --body "${body}"
    --headers "${headers}"
  )
  if [ "${expected_digest}" != - ]; then
    args+=(--expected-digest "${expected_digest}")
  fi
  python3 -I -B "${contract}" "${args[@]}"
}

for attempt in 1 2 3 4 5; do
  set +e
  resolved="$(resolve_once)"
  status=$?
  set -e
  if [ "${status}" -eq 0 ]; then
    printf '%s\n' "${resolved}"
    exit 0
  fi
  if [ "${status}" -ne 75 ]; then
    exit "${status}"
  fi
  printf 'registry alias response was lost; retrying exact observation (%s/5)\n' \
    "${attempt}" >&2
  sleep "${attempt}"
done

printf 'DENY: registry alias response remained unavailable after five observations\n' >&2
exit 1
