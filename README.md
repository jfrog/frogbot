<div align="center">
  
# JFrog Frogbot

[![Frogbot](images/frogbot-intro.png)](#readme)

[![Scanned by Frogbot](https://raw.github.com/jfrog/frogbot/master/images/frogbot-badge.svg)](https://docs.jfrog-applications.jfrog.io/jfrog-applications/frogbot)
[![Go Report Card](https://goreportcard.com/badge/github.com/jfrog/frogbot)](https://goreportcard.com/report/github.com/jfrog/frogbot)

| Branch |                                                                                                                                                                                    Status                                                                                                                                                                                    |
|:------:|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------:|
| master | [![Build status](https://github.com/jfrog/frogbot/actions/workflows/test.yml/badge.svg?branch=master)](https://github.com/jfrog/frogbot/actions/workflows/test.yml?branch=master)  [![GitHub Action Test](https://github.com/jfrog/frogbot/actions/workflows/action-test.yml/badge.svg?branch=master)](https://github.com/jfrog/frogbot/actions/workflows/action-test.yml?branch=master) |
|  dev   |                [![Build status](https://github.com/jfrog/frogbot/actions/workflows/test.yml/badge.svg?branch=dev)](https://github.com/jfrog/frogbot/actions/workflows/test.yml?branch=dev)  [![GitHub Action Test](https://github.com/jfrog/frogbot/actions/workflows/action-test.yml/badge.svg?branch=dev)](https://github.com/jfrog/frogbot/actions/workflows/action-test.yml?branch=dev)                |

</div>

<div id="what-is-frogbot"></div>

## 🤖 About JFrog Frogbot
### Overview

JFrog Frogbot is a Git bot that scans your Git repositories for security vulnerabilities.
1. It scans pull requests immediately after they are opened but before they are merged. This process notifies you if the pull request is about to introduce new vulnerabilities to your code. This unique capability ensures the code is scanned and can be fixed even before vulnerabilities are introduced into the codebase.
2. It scans the Git repository periodically and creates pull requests with fixes for detected vulnerabilities.

### Why use JFrog Frogbot?
- **Software Composition Analysis (SCA)**: Scan your project dependencies for security issues. For selected security issues, get leverage-enhanced CVE data from our JFrog Security Research team. Frogbot uses JFrog's vast vulnerabilities database, to which we continuously add new component vulnerability data.
- **Validate Dependency Licenses**: Ensure that the licenses for the project's dependencies are in compliance with a predefined list of approved licenses.
- **Static Application Security Testing (SAST)**: Provides fast and accurate security-focused engines that detect zero-day security vulnerabilities on your source code sensitive operations, while minimizing false positives.
- **CVE Vulnerability Contextual Analysis**: This feature uses the code context to eliminate false positive reports on vulnerable dependencies that are not applicable to the code. For CVE vulnerabilities that are applicable to your code, Frogbot will create pull request comments on the relevant code lines with full descriptions regarding the security issues caused by the CVE. Vulnerability Contextual Analysis is currently supported for Python, JavaScript, and Java code.
- **Secrets Detection**: Detect any secrets left exposed inside the code. to stop any accidental leak of internal tokens or credentials.
- **Infrastructure as Code scans (IaC)**: Scan Infrastructure as Code (Terraform) files for early detection of cloud and infrastructure misconfigurations.

## 🏁 Getting started
Read the [Frogbot Documentation](https://jfrog.com/help/r/jfrog-security-user-guide/shift-left-on-security/frogbot) to get started.  

## 📛 Adding the Frogbot badge

You can show people that your repository is scanned by Frogbot by adding a badge to the README of your Git repository.

![](./images/frogbot-badge.svg)

You can add this badge by copying the following markdown snippet and pasting it into your repository's README.md file.
```
[![Scanned by Frogbot](https://raw.github.com/jfrog/frogbot/master/images/frogbot-badge.svg)](https://docs.jfrog-applications.jfrog.io/jfrog-applications/frogbot)
```

## 🔥 Reporting issues

Please help us improve Frogbot by [reporting issues](https://github.com/jfrog/frogbot/issues/new/choose) you encounter.

<div id="contributions"></div>

## 💻 Contributions

We welcome pull requests from the community. To help us improve this project, please read our [Contribution](./CONTRIBUTING.md#-guidelines) guide.
