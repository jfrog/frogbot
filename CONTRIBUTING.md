# 📖 Guidelines

## Branch Structure

This repository has two branches that accept pull requests:

| Branch | Purpose                                                                                                                                                          |
|--------|------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `main` | **V3 — active development.** All new features, improvements, and bug fixes go here. PRs are opened directly against `main`.                                      |
| `v2_main` | **V2 — maintenance only. Not intended for new contributions.** Only critical bug and security fixes are accepted here, and only until V2's official end-of-life. |

> **⚠️ V2 is on sunset.** Frogbot V2 is no longer accepting new features or general code contributions. The `v2_main` branch exists solely for critical bug and security patches until official end-of-life. If you want to contribute something new, please target the `main` branch (V3).

### Contributing to V3 (active development)

- Open pull requests directly against the **`main`** branch.
- If the existing tests do not already cover your changes, please add tests.
- Please run `go fmt ./...` for formatting the code before submitting the pull request.

### Contributing a critical fix to V2

- Open pull requests against the **`v2_main`** branch.
- Only critical bug fixes and security patches are accepted — no new features, no refactoring, no general improvements.
- Clearly explain in your PR description why the fix is critical and cannot be addressed in V3 instead.

# ⚒️ Building and Testing the Sources

## Build Frogbot

Make sure Go is installed by running:

```
go version
```

Clone the sources and CD to the root directory of the project:

```
git clone https://github.com/jfrog/frogbot.git
cd frogbot
```

Build the sources as follows:

On Unix based systems run:

```
./buildscripts/build.sh
```

On Windows run:

```
.\buildscripts\build.bat
```

Once completed, you'll find the frogbot executable at the current directory.

## Tests

Before running the tests, generate mocks by running the following command from within the root directory of the project:

```sh
go generate ./...
```

To run the tests, follow these steps:

1. Set the `JF_URL` & `JF_ACCESS_TOKEN` environment variables with your JFrog platform credentials.
2. Execute the following command:

```sh
go test -v ./...
```
