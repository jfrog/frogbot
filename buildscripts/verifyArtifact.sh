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

verifyArtifact_compare_checksums() {
  local local_file="$1"
  local headers="$2"

  local remote_md5 remote_sha1 remote_sha256
  local file_md5 file_sha1 file_sha256

  remote_md5=$(verifyArtifact_get_header_value "X-Checksum-Md5" "${headers}")
  remote_sha1=$(verifyArtifact_get_header_value "X-Checksum-Sha1" "${headers}")
  remote_sha256=$(verifyArtifact_get_header_value "X-Checksum-Sha256" "${headers}")

  if [[ -z "${remote_md5}" || -z "${remote_sha1}" ]]; then
    echo "Artifactory did not return checksum headers; cannot verify ${local_file}." >&2
    return 1
  fi

  file_md5=$(verifyArtifact_local_md5 "${local_file}")
  file_sha1=$(verifyArtifact_local_sha1 "${local_file}")
  file_sha256=$(verifyArtifact_local_sha256 "${local_file}")
  if [[ "${file_md5}" != "${remote_md5}" || "${file_sha1}" != "${remote_sha1}" ]] \
    || { [[ -n "${remote_sha256}" ]] && [[ "${file_sha256}" != "${remote_sha256}" ]]; }; then
    echo "Checksum verification failed for ${local_file}." >&2
    echo "Remote md5=${remote_md5} sha1=${remote_sha1} sha256=${remote_sha256}" >&2
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

  local headers=""
  if [[ "${use_jf_cli}" -eq 1 ]]; then
    if [[ -z "${repo_path}" ]]; then
      echo "--repo-path is required with --jf-cli." >&2
      return 1
    fi
    if ! headers=$(verifyArtifact_head_request_jf "${repo_path}"); then
      echo "Failed to fetch Artifactory file details for /${repo_path#/}." >&2
      [[ -n "${on_failure}" ]] && rm -f "${on_failure}"
      return 1
    fi
  else
    if [[ -z "${artifact_url}" ]]; then
      echo "--url is required unless --jf-cli is set." >&2
      return 1
    fi
    if ! headers=$(verifyArtifact_head_request_curl "${artifact_url}"); then
      echo "Failed to fetch Artifactory file details for ${artifact_url}." >&2
      [[ -n "${on_failure}" ]] && rm -f "${on_failure}"
      return 1
    fi
  fi

  if ! verifyArtifact_compare_checksums "${local_file}" "${headers}"; then
    [[ -n "${on_failure}" ]] && rm -f "${on_failure}"
    return 1
  fi

  if [[ "${use_jf_cli}" -eq 1 ]]; then
    echo "Checksum verification passed for ${local_file} (repo path: /${repo_path#/})."
  else
    echo "Checksum verification passed for ${local_file}."
  fi
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
