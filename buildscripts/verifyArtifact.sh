#!/bin/bash
# Verifies a local file against Artifactory checksum headers from a HEAD request

verifyArtifact_get_header_value() {
  local header_name="$1"
  local headers="$2"
  echo "${headers}" | awk -v header="${header_name}" '
    BEGIN { IGNORECASE=1; value="" }
    $1 ~ header":" { sub(/^[^:]+:[[:space:]]*/, ""); value=$0 }
    END { gsub(/\r/, "", value); print value }
  '
}

verifyArtifact_local_md5() {
  if command -v md5sum >/dev/null 2>&1; then
    md5sum "$1" | awk '{print $1}'
  else
    md5 -q "$1"
  fi
}

verifyArtifact_local_sha1() {
  if command -v sha1sum >/dev/null 2>&1; then
    sha1sum "$1" | awk '{print $1}'
  else
    shasum -a 1 "$1" | awk '{print $1}'
  fi
}

verifyArtifact_local_sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

# HEAD via curl; uses JF_ACCESS_TOKEN, JF_USER/JF_PASSWORD, or no auth.
verifyArtifact_head_request_curl() {
  local dl_url="$1"
  if [[ -n "${JF_ACCESS_TOKEN:-}" ]]; then
    curl -sfILg -H "Authorization:Bearer ${JF_ACCESS_TOKEN}" "${dl_url}"
  elif [[ -n "${JF_USER:-}" ]]; then
    curl -sfILg -u "${JF_USER}:${JF_PASSWORD:-}" "${dl_url}"
  else
    curl -sfILg "${dl_url}"
  fi
}

# HEAD via JFrog CLI (uses configured server credentials from jf c).
verifyArtifact_head_request_jf() {
  local repo_path="$1"
  repo_path="${repo_path#/}"
  jf rt curl -X HEAD -sI "/${repo_path}"
}

verifyArtifact_storage_request_jf() {
  local repo_path="$1"
  repo_path="${repo_path#/}"
  local repo="${repo_path%%/*}"
  local path="${repo_path#*/}"
  jf rt curl -s "/api/storage/${repo}/${path}"
}

verifyArtifact_artifact_url_to_storage_url() {
  local artifact_url="$1"
  local prefix suffix
  if [[ "${artifact_url}" =~ /artifactory/ ]]; then
    prefix="${artifact_url%%/artifactory/*}"
    suffix="${artifact_url#*/artifactory/}"
    suffix="${suffix%%\?*}"
    echo "${prefix}/artifactory/api/storage/${suffix}"
    return 0
  fi
  return 1
}

verifyArtifact_storage_request_curl() {
  local storage_url="$1"
  if [[ -n "${JF_ACCESS_TOKEN:-}" ]]; then
    curl -sfLg -H "Authorization:Bearer ${JF_ACCESS_TOKEN}" "${storage_url}"
  elif [[ -n "${JF_USER:-}" ]]; then
    curl -sfLg -u "${JF_USER}:${JF_PASSWORD:-}" "${storage_url}"
  else
    curl -sfLg "${storage_url}"
  fi
}

verifyArtifact_stderr_indicates_auth_failure() {
  [[ -f "$1" ]] && grep -qiE '401|403|Unauthorized|Forbidden' "$1"
}

verifyArtifact_parse_storage_checksums() {
  local json="$1"
  local -a _cs
  if command -v jq >/dev/null 2>&1; then
    REMOTE_MD5=$(echo "${json}" | jq -r '.checksums.md5 // empty')
    REMOTE_SHA1=$(echo "${json}" | jq -r '.checksums.sha1 // empty')
    REMOTE_SHA256=$(echo "${json}" | jq -r '.checksums.sha256 // empty')
    return 0
  fi
  if command -v python3 >/dev/null 2>&1; then
    _cs=$(echo "${json}" | python3 -c 'import json,sys; c=json.load(sys.stdin).get("checksums",{}); print(c.get("md5") or ""); print(c.get("sha1") or ""); print(c.get("sha256") or "")')
    REMOTE_MD5=$(printf '%s\n' "${_cs}" | sed -n '1p')
    REMOTE_SHA1=$(printf '%s\n' "${_cs}" | sed -n '2p')
    REMOTE_SHA256=$(printf '%s\n' "${_cs}" | sed -n '3p')
    return 0
  fi
  return 1
}

verifyArtifact_load_remote_checksums_from_headers() {
  local headers="$1"
  REMOTE_MD5=$(verifyArtifact_get_header_value "X-Checksum-Md5" "${headers}")
  REMOTE_SHA1=$(verifyArtifact_get_header_value "X-Checksum-Sha1" "${headers}")
  REMOTE_SHA256=$(verifyArtifact_get_header_value "X-Checksum-Sha256" "${headers}")
  [[ -n "${REMOTE_MD5}" && -n "${REMOTE_SHA1}" ]]
}

verifyArtifact_load_remote_checksums_jf() {
  local repo_path="$1"
  local headers json head_err

  REMOTE_MD5=""
  REMOTE_SHA1=""
  REMOTE_SHA256=""

  head_err=$(mktemp "${TMPDIR:-/tmp}/frogbot-head.XXXXXX")
  if headers=$(verifyArtifact_head_request_jf "${repo_path}" 2>"${head_err}") \
    && verifyArtifact_load_remote_checksums_from_headers "${headers}"; then
    rm -f "${head_err}"
    return 0
  fi
  if verifyArtifact_stderr_indicates_auth_failure "${head_err}"; then
    echo "Artifactory HEAD request was rejected (401/403). Check jf CLI credentials." >&2
    rm -f "${head_err}"
    return 1
  fi
  rm -f "${head_err}"

  echo "Checksum headers not returned by HEAD; using Artifactory Storage API ..." >&2
  if ! json=$(verifyArtifact_storage_request_jf "${repo_path}"); then
    echo "Failed to fetch Artifactory storage metadata for /${repo_path#/}." >&2
    return 1
  fi
  if ! verifyArtifact_parse_storage_checksums "${json}"; then
    echo "jq or python3 is required to parse Artifactory storage metadata." >&2
    return 1
  fi
  if [[ -z "${REMOTE_MD5}" || -z "${REMOTE_SHA1}" ]]; then
    echo "Artifactory storage metadata did not include md5/sha1 checksums for /${repo_path#/}." >&2
    return 1
  fi
  return 0
}

verifyArtifact_load_remote_checksums_curl() {
  local artifact_url="$1"
  local headers json storage_url head_err

  REMOTE_MD5=""
  REMOTE_SHA1=""
  REMOTE_SHA256=""

  head_err=$(mktemp "${TMPDIR:-/tmp}/frogbot-head.XXXXXX")
  if headers=$(verifyArtifact_head_request_curl "${artifact_url}" 2>"${head_err}") \
    && verifyArtifact_load_remote_checksums_from_headers "${headers}"; then
    rm -f "${head_err}"
    return 0
  fi
  if verifyArtifact_stderr_indicates_auth_failure "${head_err}"; then
    echo "Artifactory HEAD request was rejected (401/403). Check JF_ACCESS_TOKEN or JF_USER/JF_PASSWORD." >&2
    rm -f "${head_err}"
    return 1
  fi
  rm -f "${head_err}"

  if ! storage_url=$(verifyArtifact_artifact_url_to_storage_url "${artifact_url}"); then
    echo "Cannot derive Artifactory Storage API URL from ${artifact_url}." >&2
    return 1
  fi

  echo "Checksum headers not returned by HEAD; using Artifactory Storage API ..." >&2
  if ! json=$(verifyArtifact_storage_request_curl "${storage_url}"); then
    echo "Failed to fetch Artifactory storage metadata from ${storage_url}." >&2
    return 1
  fi
  if ! verifyArtifact_parse_storage_checksums "${json}"; then
    echo "jq or python3 is required to parse Artifactory storage metadata." >&2
    return 1
  fi
  if [[ -z "${REMOTE_MD5}" || -z "${REMOTE_SHA1}" ]]; then
    echo "Artifactory storage metadata did not include md5/sha1 checksums." >&2
    return 1
  fi
  return 0
}

verifyArtifact_compare_local_to_remote() {
  local local_file="$1"
  local file_md5 file_sha1 file_sha256

  if [[ -z "${REMOTE_MD5}" || -z "${REMOTE_SHA1}" ]]; then
    echo "Artifactory did not return checksum headers; cannot verify ${local_file}." >&2
    return 1
  fi

  file_md5=$(verifyArtifact_local_md5 "${local_file}")
  file_sha1=$(verifyArtifact_local_sha1 "${local_file}")
  file_sha256=$(verifyArtifact_local_sha256 "${local_file}")
  if [[ "${file_md5}" != "${REMOTE_MD5}" || "${file_sha1}" != "${REMOTE_SHA1}" ]] \
    || { [[ -n "${REMOTE_SHA256}" ]] && [[ "${file_sha256}" != "${REMOTE_SHA256}" ]]; }; then
    echo "Checksum verification failed for ${local_file}." >&2
    echo "Remote md5=${REMOTE_MD5} sha1=${REMOTE_SHA1} sha256=${REMOTE_SHA256}" >&2
    echo "Local  md5=${file_md5} sha1=${file_sha1} sha256=${file_sha256}" >&2
    return 1
  fi

  return 0
}

# Verifies local file against remote Artifactory artifact.
# Usage:
#   verifyArtifact.sh --file <path> --url <full-artifactory-url>
#   verifyArtifact.sh --file <path> --repo-path <repo/path> --jf-cli
verifyArtifact_file() {
  local local_file=""
  local artifact_url=""
  local repo_path=""
  local use_jf_cli=0
  local on_failure=""

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --file)
        local_file="$2"
        shift 2
        ;;
      --url)
        artifact_url="$2"
        shift 2
        ;;
      --repo-path)
        repo_path="$2"
        shift 2
        ;;
      --jf-cli)
        use_jf_cli=1
        shift
        ;;
      --on-failure)
        on_failure="$2"
        shift 2
        ;;
      *)
        echo "Unknown argument: $1" >&2
        return 1
        ;;
    esac
  done

  if [[ -z "${local_file}" ]]; then
    echo "--file is required." >&2
    return 1
  fi
  if [[ ! -f "${local_file}" ]]; then
    echo "Local file not found: ${local_file}" >&2
    return 1
  fi

  if [[ "${FROGBOT_INSECURE_SKIP_CHECKSUM_VERIFICATION:-}" = "1" ]]; then
    echo "WARNING: skipping checksum verification (FROGBOT_INSECURE_SKIP_CHECKSUM_VERIFICATION=1)." >&2
    echo "Skipped checksum verification for ${local_file}."
    return 0
  fi

  if [[ "${use_jf_cli}" -eq 1 ]]; then
    if [[ -z "${repo_path}" ]]; then
      echo "--repo-path is required with --jf-cli." >&2
      return 1
    fi
    if ! verifyArtifact_load_remote_checksums_jf "${repo_path}"; then
      [[ -n "${on_failure}" ]] && rm -f "${on_failure}"
      return 1
    fi
    if ! verifyArtifact_compare_local_to_remote "${local_file}"; then
      [[ -n "${on_failure}" ]] && rm -f "${on_failure}"
      return 1
    fi
    echo "Checksum verification passed for ${local_file} (repo path: /${repo_path#/})."
    return 0
  fi

  if [[ -z "${artifact_url}" ]]; then
    echo "--url is required unless --jf-cli is set." >&2
    return 1
  fi
  if ! verifyArtifact_load_remote_checksums_curl "${artifact_url}"; then
    [[ -n "${on_failure}" ]] && rm -f "${on_failure}"
    return 1
  fi
  if ! verifyArtifact_compare_local_to_remote "${local_file}"; then
    [[ -n "${on_failure}" ]] && rm -f "${on_failure}"
    return 1
  fi

  echo "Checksum verification passed for ${local_file}."
  return 0
}

verifyArtifact_main() {
  set -euo pipefail
  if ! verifyArtifact_file "$@"; then
    exit 1
  fi
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  verifyArtifact_main "$@"
fi
