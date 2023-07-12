<div align="center">

# JFrog Frogbot

[![Frogbot](images/frogbot-intro.png)](#readme)

[![Scanned by Frogbot](https://raw.github.com/jfrog/frogbot/master/images/frogbot-badge.svg)](https://github.com/jfrog/frogbot#readme)
[![Go Report Card](https://goreportcard.com/badge/github.com/jfrog/frogbot)](https://goreportcard.com/report/github.com/jfrog/frogbot)

| Branch |                                                                                                                                                                                    Status                                                                                                                                                                                    |
|:------:|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------:|
| master | [![Build status](https://github.com/jfrog/frogbot/actions/workflows/test.yml/badge.svg?branch=master)](https://github.com/jfrog/frogbot/actions/workflows/test.yml?branch=master)  [![GitHub Action Test](https://github.com/jfrog/frogbot/actions/workflows/action-test.yml/badge.svg?branch=master)](https://github.com/jfrog/frogbot/actions/workflows/action-test.yml?branch=master) |
|  dev   |                [![Build status](https://github.com/jfrog/frogbot/actions/workflows/test.yml/badge.svg?branch=dev)](https://github.com/jfrog/frogbot/actions/workflows/test.yml?branch=dev)  [![GitHub Action Test](https://github.com/jfrog/frogbot/actions/workflows/action-test.yml/badge.svg?branch=dev)](https://github.com/jfrog/frogbot/actions/workflows/action-test.yml?branch=dev)                |

</div>

## Table of contents

- [🤖 About JFrog Frogbot](#-about-jfrog-frogbot)
- [🖥️ Installing Frogbot](#️-installing-frogbot)
- [🚥 Using Frogbot](#-using-frogbot)
- [📛 Adding the Frogbot badge](#-adding-the-frogbot-badge)
- [🔥 Reporting issues](#-reporting-issues)
- [💻 Contributions](#-contributions)

<div id="what-is-frogbot"></div>

## 🤖 About JFrog Frogbot
### Overview

JFrog Frogbot is a Git bot that scans your git repositories for security vulnerabilities.
1. It scans pull requests immediately after they are opened but before they are merged. This process notifies you if the pull request is about to introduce new vulnerabilities to your code. This unique capability ensures that the code is scanned and can be fixed even before vulnerabilities are introduced into the codebase.
2. It scans the Git repository periodically and creates pull requests with fixes for vulnerabilities that are detected.

It supports the following Git providers:
- Azure Repos
- Bitbucket Server
- GitHub
- GitLab

### Why use JFrog Frogbot?
- **Software Composition Analysis (SCA)**: Scan your project dependencies for security issues. For selected security issues, get leverage-enhanced CVE data that is provided by our JFrog Security Research team. Frogbot uses JFrog's vast vulnerabilities database, to which we continuously add new component vulnerability data. Also included is VulnDB, the industry's most comprehensive security database, to further extend the range of vulnerabilities detected and fixed by Frogbot.
- **Vulnerability Contextual Analysis**: This feature uses the code context to eliminate false positive reports on vulnerable dependencies that are not applicable to the code. Vulnerability Contextual Analysis is currently supported for Python and JavaScript code.

> **_NOTE:_** **Vulnerability Contextual Analysis** require the [JFrog Advanced Security Package](https://jfrog.com/xray/).

### What's needed for the setup?
- Frogbot uses a JFrog environment to scan your Git repositories. If you don't have a JFrog environment, you can set up one for free, and use it with no limits.
- Frogbot also requires a runtime environment for the scanning. The following environments are supported:

  - GitHub Actions
  - JFrog Pipelines
  - Jenkins
  - Azure Pipelines

## 🖥️ Installing Frogbot

<details>
  <summary>Step 1 - Optionally set up a FREE JFrog Environment in the Cloud</summary>

Frogbot requires a JFrog environment to scan your projects. If you don't have an environment, we can set up a free environment in the cloud for you. Just run one of the following commands in your terminal to set up an environment in less than a minute.

The commands will do the following:

1. Install [JFrog CLI](https://www.jfrog.com/confluence/display/CLI/JFrog+CLI) on your machine.
2. Create a FREE JFrog environment in the cloud for you.

**For macOS and Linux, use curl**

```
curl -fL "https://getcli.jfrog.io?setup" | sh
```

**For Windows, use PowerShell**

```
powershell "Start-Process -Wait -Verb RunAs powershell '-NoProfile iwr https://releases.jfrog.io/artifactory/jfrog-cli/v2-jf/[RELEASE]/jfrog-cli-windows-amd64/jf.exe -OutFile $env:SYSTEMROOT\system32\jf.exe'" ; jf setup
```

After the setup is complete, you'll receive an email with your JFrog environment connection details, which can be stored as secrets in Git.

</details>

<details>
  <summary>Step 2 - Install Frogbot</summary>

- [Installing Frogbot on Azure Repos repositories](docs/install-azure-repos.md)
- [Installing Frogbot on Bitbucket Server repositories](docs/install-bitbucket-server.md)
- [Installing Frogbot on GitHub repositories](docs/install-github.md)
- [Installing Frogbot on GitLab repositories](docs/install-gitlab.md)

</details>

<details>
  <summary>Step 3 - Customize settings with frogbot-config.yml file if needed</summary>
    
- 
- [Creating the frogbot-config.yml File](docs/frogbot-config.md)

</details>

<div id="reporting-issues"></div>

## 🚥 Frogbot's Commands
<details>
  <summary>Scanning pull requests</summary>

### General

Frogbot uses [JFrog Xray](https://jfrog.com/xray/) (version 3.29.0 and above is required) to scan your pull requests. It adds the scan results as a comment on the pull request. If no new vulnerabilities are found, Frogbot will also add a comment, confirming this.

Supported package management tools:

- Go
- Gradle
- Maven
- .NET
- npm
- NuGet
- Pip
- Pipenv
- Poetry
- Yarn 2

### Scan results

Frogbot adds the scan results to the pull request in the following format:

#### 👍 No issues

If no new vulnerabilities are found, Frogbot automatically adds the following comment to the pull request:

[![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/noVulnerabilityBannerPR.png)](#-no-issues)

#### 👎 Issues were found

If new vulnerabilities are found, Frogbot adds them as a comment on the pull request. For example:

[![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/vulnerabilitiesBannerPR.png)](#-issues)
|                                                      SEVERITY                                                       | CONTEXTUAL ANALYSIS                  | DIRECT DEPENDENCIES                  | IMPACTED DEPENDENCY                   | FIXED VERSIONS                       |
|:-------------------------------------------------------------------------------------------------------------------:| :----------------------------------: | :----------------------------------: | :-----------------------------------: | :---------------------------------: |
|   ![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/notApplicableCritical.png)<br>Critical    | $\color{#3CB371}{\textsf{Not Applicable}}$ |minimist:1.2.5 | minimist:1.2.5 | [0.2.4]<br>[1.2.6] |
|   ![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/applicableHighSeverity.png)<br>    High   | $\color{#FF7377}{\textsf{Applicable}}$ |protobufjs:6.11.2 | protobufjs:6.11.2 | [6.11.3] |
|     ![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/notApplicableHigh.png)<br>    High      | $\color{#3CB371}{\textsf{Not Applicable}}$ |lodash:4.17.19 | lodash:4.17.19 | [4.17.21] |


### 👮 Security note for pull requests scanning 👮

When installing Frogbot using JFrog Pipelines, Jenkins and Azure DevOps, Frogbot will not wait for a maintainer's approval before scanning newly opened pull requests. Using Frogbot with these platforms, however, isn't recommended for open-source projects.

When installing Frogbot using GitHub Actions and GitLab however, Frogbot will initiate the scan only after it is approved by a maintainer of the project. The goal of this review is to ensure that external code contributors don't introduce malicious code as part of the pull request. Since this review step is enforced by Frogbot when used with GitHub Actions and GitLab, it is safe to be used for open-source projects.

</details>

<details>
  <summary>Scanning repositories</summary>

### Automatic pull requests creation
Frogbot scans your Git repositories periodically and automatically creates pull requests for upgrading vulnerable dependencies to a version with a fix.
Supported package management tools:

- Go
- Maven
- npm
- Pip
- Pipenv
- Poetry
- Yarn 2

![](./images/fix-pr.png)

### Adding Security Alerts
For GitHub repositories, issues that are found during Frogbot's periodic scans are also added to the [Security Alerts](https://docs.github.com/en/code-security/code-scanning/automatically-scanning-your-code-for-vulnerabilities-and-errors/managing-code-scanning-alerts-for-your-repository) view in the UI.
The following alert types are supported:

#### CVEs on vulnerable depedencies
![](./images/github-code-scanning.png)

![](./images/github-code-scanning-content.png)

</details>

</details>

## 📛 Adding the Frogbot badge

You can show people that your repository is scanned by Frogbot by adding a badge to the README of your Git repository.

![](./images/frogbot-badge.svg)

You can add this badge by copying the following markdown snippet and pasting it into your repository's README.md file.
```
[![Scanned by Frogbot](https://raw.github.com/jfrog/frogbot/master/images/frogbot-badge.svg)](https://github.com/jfrog/frogbot#readme)
```

## 🔥 Reporting issues

Please help us improve Frogbot by [reporting issues](https://github.com/jfrog/frogbot/issues/new/choose) you encounter.

<div id="contributions"></div>

## 💻 Contributions

We welcome pull requests from the community. To help us improve this project, please read our [Contribution](./CONTRIBUTING.md#-guidelines) guide.
