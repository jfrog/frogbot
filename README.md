# FrogBot

Automated dependencies scanning using JFrog Xray.

## Project Status

[![Build status](https://github.com/jfrog/frogbot/actions/workflows/test.yml/badge.svg)](https://github.com/jfrog/frogbot/actions/workflows/test.yml) [![GitHub Action Test](https://github.com/jfrog/frogbot/actions/workflows/action-test.yml/badge.svg)](https://github.com/jfrog/frogbot/actions/workflows/action-test.yml)


## Usage

- [Overview](#overview)
- [Usage](#usage)
  - [Using Frogbot with GitHub Actions](#using-frogbot-with-github-actions)
  - [Using Frogbot with GitLab CI](#using-frogbot-with-gitlab-ci)
  - [Using Frogbot with Jenkins](#using-frogbot-with-jenkins)
  - [Download Frogbot through Artifactory](#download-frogbot-through-artifactory)
- [Building and Testing the Sources](#building-and-testing-the-sources)
  - [Build Frogbot](#build-frogbot)
  - [Tests](#test)
- [Code Contributions](#code-contributions)
- [Release Notes](#release-notes)

## Using Frogbot with GitHub Actions

TODO

## Using Frogbot with GitLab CI

TODO

## Using Frogbot with Jenkins

TODO

## Download Frogbot through Artifactory

TODO

# Building and Testing the Sources

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

Once completed, you'll find the bi executable at the current directory.

## Tests

To run the tests, execute the following command from within the root directory of the project:

```sh
go test -v ./...
```

# Code Contributions

We welcome community contribution through pull requests.

# Release Notes

The release notes are available [here](RELEASE.md#release-notes).
