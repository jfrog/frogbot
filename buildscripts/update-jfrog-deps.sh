#!/bin/bash
set -euo pipefail

BOLD="\033[1m"
GREEN="\033[0;32m"
YELLOW="\033[0;33m"
CYAN="\033[0;36m"
RED="\033[0;31m"
RESET="\033[0m"

GOMOD="go.mod"
COMMENT_REPLACE=true
# Used for go get / go mod tidy when resolving modules (override e.g. for a corporate proxy).
JFROG_DEPS_GOPROXY="${JFROG_DEPS_GOPROXY:-direct}"

usage() {
    echo -e "${BOLD}Usage:${RESET} $0 [OPTIONS] [dep1 dep2 ...]"
    echo
    echo "Update JFrog Go dependencies to their latest versions."
    echo "With no dependency names, updates all known JFrog modules; otherwise only those listed."
    echo
    echo -e "${BOLD}Options:${RESET}"
    echo "  -a, --all            Explicitly update all JFrog dependencies (same as passing no names)"
    echo "  --keep-replace       Don't comment out active 'replace' directives (default: comment them out)"
    echo "  -h, --help           Show this help message"
    echo
    echo -e "${BOLD}Environment:${RESET}"
    echo "  JFROG_DEPS_GOPROXY   GOPROXY for go get / go mod tidy (default: direct)"
    echo
    echo -e "${BOLD}Individual dependencies (pass one or more):${RESET}"
    echo "  client-go        github.com/jfrog/jfrog-client-go        @master"
    echo "  cli-core         github.com/jfrog/jfrog-cli-core/v2      @master"
    echo "  cli-artifactory  github.com/jfrog/jfrog-cli-artifactory  @main"
    echo "  build-info-go    github.com/jfrog/build-info-go          @main"
    echo "  cli-security     github.com/jfrog/jfrog-cli-security      @latest (tag)"
    echo "  froggit-go       github.com/jfrog/froggit-go             @latest (tag)"
    echo "  gofrog           github.com/jfrog/gofrog                 @latest (tag)"
    echo
    echo -e "${BOLD}Examples:${RESET}"
    echo "  $0                                # Update all JFrog deps"
    echo "  $0 --all                          # Same as no arguments"
    echo "  $0 client-go cli-core             # Update only those"
    echo "  $0 --keep-replace                 # Update all, leave replace directives as-is"
    echo "  JFROG_DEPS_GOPROXY=https://proxy.golang.org $0   # Use a different GOPROXY"
}

log_info()  { echo -e "${CYAN}[INFO]${RESET}  $*"; }
log_ok()    { echo -e "${GREEN}[OK]${RESET}    $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
log_error() { echo -e "${RED}[ERROR]${RESET} $*"; }

ALL_KEYS="client-go cli-core cli-artifactory cli-security build-info-go froggit-go gofrog"

resolve_dep() {
    case "$1" in
        client-go)       echo "github.com/jfrog/jfrog-client-go|master" ;;
        cli-core)        echo "github.com/jfrog/jfrog-cli-core/v2|master" ;;
        cli-artifactory) echo "github.com/jfrog/jfrog-cli-artifactory|main" ;;
        build-info-go)   echo "github.com/jfrog/build-info-go|main" ;;
        cli-security)    echo "github.com/jfrog/jfrog-cli-security|latest" ;;
        froggit-go)      echo "github.com/jfrog/froggit-go|latest" ;;
        gofrog)          echo "github.com/jfrog/gofrog|latest" ;;
        *)               return 1 ;;
    esac
}

comment_out_jfrog_replaces() {
    if [[ ! -f "$GOMOD" ]]; then
        log_error "Cannot find $GOMOD"
        return 1
    fi

    local count
    count=$(grep -cE '^[[:space:]]*replace[[:space:]]+github\.com/jfrog/' "$GOMOD" 2>/dev/null || true)

    if [[ "$count" -eq 0 ]]; then
        log_info "No active jfrog replace directives found"
        return 0
    fi

    log_warn "Found ${BOLD}${count}${RESET} active jfrog replace directive(s) — commenting out"

    # macOS sed requires '' after -i; use a temp file for portability
    local tmp
    tmp=$(mktemp)
    while IFS= read -r line; do
        if echo "$line" | grep -qE '^[[:space:]]*replace[[:space:]]+github\.com/jfrog/'; then
            log_info "  Commenting: ${line}"
            echo "// ${line}" >> "$tmp"
        else
            echo "$line" >> "$tmp"
        fi
    done < "$GOMOD"
    mv "$tmp" "$GOMOD"
    log_ok "Replace directives commented out"
}

update_dep() {
    local key="$1"
    local entry
    entry=$(resolve_dep "$key") || { log_error "Unknown dependency: ${key} (known: ${ALL_KEYS})"; return 1; }
    local module="${entry%%|*}"
    local ref="${entry##*|}"
    log_info "Updating ${BOLD}${key}${RESET} → ${module}@${ref}"
    if GOPROXY="$JFROG_DEPS_GOPROXY" go get "${module}@${ref}"; then
        log_ok "${key} updated"
    else
        log_error "Failed to update ${key}"
        return 1
    fi
}

# --- Main ---

explicit_all=false
specific_deps=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        -a|--all)           explicit_all=true; shift ;;
        --keep-replace)     COMMENT_REPLACE=false; shift ;;
        -h|--help)          usage; exit 0 ;;
        -*)                 log_error "Unknown option: $1"; usage; exit 1 ;;
        *)                  specific_deps+=("$1"); shift ;;
    esac
done

# Comment out active replace directives before updating
if [[ "$COMMENT_REPLACE" == true ]]; then
    comment_out_jfrog_replaces
    echo
fi

failed=0
keys_to_update=""

if ((${#specific_deps[@]} > 0)); then
    if [[ "$explicit_all" == true ]]; then
        log_warn "${BOLD}--all${RESET} is ignored when dependency names are listed"
    fi
    log_info "Updating ${BOLD}${specific_deps[*]}${RESET}…"
    echo
    keys_to_update="${specific_deps[*]}"
else
    log_info "Updating ${BOLD}all${RESET} JFrog dependencies…"
    echo
    keys_to_update="$ALL_KEYS"
fi

for dep in $keys_to_update; do
    update_dep "$dep" || ((failed++)) || true
done

echo
if [[ $failed -gt 0 ]]; then
    log_warn "${failed} update(s) failed"
else
    log_ok "All updates succeeded"
fi

log_info "Running go mod tidy…"
GOPROXY="$JFROG_DEPS_GOPROXY" go mod tidy
log_ok "go mod tidy done"

log_info "Running go vet ./…"
if ! go vet ./...; then
    log_error "go vet failed"
    exit 1
fi
log_ok "go vet passed"

exit "$failed"
