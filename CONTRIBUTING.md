# 📖 Guidelines

- If the existing tests do not already cover your changes, please add tests,
- Pull requests should be created on the _dev_ branch,
- Please run `go fmt ./...` for formatting the code before submitting the pull request.

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
2. execute the following command:

```sh
go test -v ./...
```
