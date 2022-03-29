# FrogBot

## Project Status

[![Build status](https://github.com/jfrog/frogbot/actions/workflows/test.yml/badge.svg)](https://github.com/jfrog/frogbot/actions/workflows/test.yml) [![GitHub Action Test](https://github.com/jfrog/frogbot/actions/workflows/action-test.yml/badge.svg)](https://github.com/jfrog/frogbot/actions/workflows/action-test.yml)
[![Coverage Status](https://coveralls.io/repos/github/jfrog/frogbot/badge.svg?branch=dev)](https://coveralls.io/github/jfrog/frogbot?branch=dev)

## What is Frogbot?

Frogbot is a Git bot that scans your pull requests with JFrog Xray for security vulnerabilities. Frogbot can be easily triggered following the creation of a new pull request. Frogbot adds the scan results as a comment on the pull request. If no vulnerabilities are found, Frogbot will also add a comment, confirming this. Currently GitHub and GitLab are supported. Bitbucket will be supported soon.

## How does it work?

After a new pull request is created, one of the maintainers can add the "Frogbot scan" label to the pull request. Frogbot will then be triggered and the pull request will be scanned. The scan output will include only new vulnerabilities added by the pull request. Vulnerabilities that existed in the code prior to the pull request created will not be added to the report.

## Contributions

We welcome pull requests from the community. To help us improving this project, please read our [contribution](./CONTRIBUTING.md#guidelines) Guide.

## Usage

- [FrogBot](#frogbot)
  - [Project Status](#project-status)
  - [Usage](#usage)
  - [Using Frogbot with GitHub Actions](#using-frogbot-with-github-actions)
  - [Using Frogbot with GitLab CI](#using-frogbot-with-gitlab-ci)
  - [Using Frogbot with Jenkins](#using-frogbot-with-jenkins)
  - [Download Frogbot through Artifactory](#download-frogbot-through-artifactory)
- [Building and Testing the Sources](#building-and-testing-the-sources)
  - [Build Frogbot](#build-frogbot)
  - [Tests](#tests)
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

# Release Notes

The release notes are available [here](RELEASE.md#release-notes).
