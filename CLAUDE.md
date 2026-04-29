# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Test

**Build** (produces `frogbot` binary in project root):
```sh
./buildscripts/build.sh        # Unix
.\buildscripts\build.bat       # Windows
```

**Generate mocks** (ALWAYS run before running tests):
```sh
go generate ./...
```
This regenerates `testdata/vcsclientmock.go` via `golang/mock/mockgen`.

**Run all tests** (requires JFrog platform credentials):
```sh
export JF_URL=<your-jfrog-url>
export JF_ACCESS_TOKEN=<your-access-token>
go test -v ./...
```

**Run a single test**:
```sh
go test -v -run TestName ./path/to/package/
```

**Format code** (ALWAYS run before submitting PRs):
```sh
go fmt ./...
```

Pull requests MUST target the `dev` branch.

## Architecture

Frogbot is a Git bot with two top-level commands:

- **`scan-pull-request` (spr)** — scans a PR for new vulnerabilities before merge (`scanpullrequest/`)
- **`scan-repository` (cfpr)** — scans the default branch and opens fix PRs (`scanrepository/`)

### Execution Flow

`main.go` → `commands.go:Exec()` → `utils.GetFrogbotDetails()` → `BuildServerConfigFile()` → `command.Run(repository, vcsClient)` → `SanitizeEnv()`

After config is loaded, ALL `JF_*` env vars are unset via `SanitizeEnv()` (even on error, via defer). DON'T rely on env vars being present after `GetFrogbotDetails()` returns.

Both commands implement `FrogbotCommand`: `Run(config utils.Repository, client vcsclient.VcsClient) error`.

### Key Packages

| Package | Purpose |
|---|---|
| `utils/getconfiguration.go` | Reads env vars → `FrogbotDetails`; auto-detects GitHub Actions, GitLab CI, Azure Pipelines, Jenkins |
| `utils/scandetails.go` | `ScanDetails`: holds audit context, runs `audit.RunAudit()`, controls diff-scan vs full-scan mode |
| `utils/git.go` | `GitManager`: wraps `go-git/v5` for cloning, branch creation, commits, pushes |
| `utils/outputwriter/` | `OutputWriter` interface: `StandardOutput` (GitHub/GitLab/Azure) vs `SimplifiedOutput` (Bitbucket Server — no image support) |
| `utils/issues/` | `ScansIssuesCollection`: aggregates SCA, SAST, Secrets, IaC, License findings |
| `scanpullrequest/` | Diff scan: source vs target branch; posts inline review comments + summary |
| `scanrepository/` | Full scan of configured branches; invokes `packageupdaters/` to create fix PRs |
| `packageupdaters/` | `PackageUpdater` interface + per-ecosystem strategies (Go, npm, Maven, Gradle, Python, NuGet, Yarn, pnpm, Conan) |

### Configuration

All config comes from env vars at runtime via `utils/getconfiguration.go`. Key vars:

- `JF_URL`, `JF_ACCESS_TOKEN` — JFrog platform connection
- `JF_GIT_PROVIDER` — `github`, `gitlab`, `bitbucketServer`, `azureRepos`
- `JF_GIT_OWNER`, `JF_GIT_REPO`, `JF_GIT_TOKEN` — repository targeting
- `JF_GIT_PULL_REQUEST_ID` — required for `scan-pull-request`
- `JF_GIT_BASE_BRANCH` — required for `scan-repository`

If Xray ≥ `3.117.0`, a config profile is fetched from XSC (`xsc.GetConfigProfileByUrl()`). The XSC profile **overrides** env var defaults for scan behavior. SAST/Secrets/IaC are explicitly disabled in the fetched profile — Frogbot runs **SCA only** in PR scans.

`BuildServerConfigFile()` creates a temporary JFrog config directory using `jfrog-cli-core`. DON'T write persistent JFrog CLI config; always use this temp-file pattern.

### Non-Obvious Behaviors

- **Indirect dependencies are skipped**: `ErrUnsupportedFix` with `IndirectDependencyFixNotSupported` causes the updater to skip — fixing indirects can break other deps. DON'T add indirect dependency fixes without understanding this constraint.
- **Build tools are never updated**: `BuildToolsDependenciesMap` (per-ecosystem) excludes tools like pip, setuptools, wheel. DON'T add them to the fix list.
- **Branch/commit/PR title templates**: Support `{IMPACTED_PACKAGE}`, `{FIX_VERSION}`, `{BRANCH_NAME_HASH}` placeholders in `GitManager`. ALWAYS use these placeholders when constructing fix branch names.
- **OutputWriter selection**: Bitbucket Server requires `SimplifiedOutput` (no inline comments, no images). The adapter is chosen in `utils/getconfiguration.go` based on `JF_GIT_PROVIDER`.

### Local Dependency Overrides

`go.mod` has an active `replace` for `jfrog-cli-security => ../jfrog-cli-security`. Other replacements (core, client, froggit-go) are commented out for easy local development.

### Testing Patterns

- ALWAYS use `testdata/vcsclientmock.go` (gomock) to mock `VcsClient` — DO NOT make real VCS API calls in unit tests.
- Use `utils/testsutils.go` helpers: `SetEnvsAndAssertWithCallback()` for env setup, `CopyTestdataProjectsToTemp()` for project fixtures.
- Integration tests (`{github,gitlab,azure,bitbucket_server}_test.go` in root) require VCS-specific tokens (`FROGBOT_TESTS_GITHUB_TOKEN`, etc.) and a live JFrog platform.

## Code Style

- DON'T add comments for self-explanatory code; ONLY comment complex logic, edge cases, or non-obvious assumptions.
- ALWAYS put comments above the relevant line, never inline.
- DON'T start function descriptions with the function name.
