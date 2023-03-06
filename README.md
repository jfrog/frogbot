<div align="center">

# Frogbot

[![Frogbot](images/frogbot-intro.png)](#readme)

[![Build status](https://github.com/jfrog/frogbot/actions/workflows/test.yml/badge.svg)](https://github.com/jfrog/frogbot/actions/workflows/test.yml) [![GitHub Action Test](https://github.com/jfrog/frogbot/actions/workflows/action-test.yml/badge.svg)](https://github.com/jfrog/frogbot/actions/workflows/action-test.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/jfrog/frogbot)](https://goreportcard.com/report/github.com/jfrog/frogbot)

</div>

## Table of contents

- [What is Frogbot?](#what-is-frogbot)
- [Scan pull requests when they are opened](#scan-pull-requests-when-they-are-opened)
- [Scanning repositories and fixing issues](#scanning-repositories-and-fixing-issues)
- [Installing Frogbot](#installing-frogbot)
- [Reporting issues](#reporting-issues)
- [Contributions](#contributions)

<div id="what-is-frogbot"></div>

## 🤖 What is Frogbot?

Frogbot is a Git bot that scans your pull requests and repositories for security vulnerabilities. You can scan pull requests when they are opened, and Git repositories following new commits.

<a href="https://www.youtube.com/watch?v=aw-AAxtAVwY"><img width="30%" src="./images/frogbot-screencast.png"></a>

## Scan pull requests when they are opened

### General

Frogbot uses [JFrog Xray](https://jfrog.com/xray/) (version 3.29.0 and above is required) to scan your pull requests. It adds the scan results as a comment on the pull request. If no new vulnerabilities are found, Frogbot will also add a comment, confirming this.

Supported platforms:

- Azure Repos
- Bitbucket Server
- GitHub
- GitLab

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

### 🕵️‍♀️ How does Pull Request scanning work?

<details>
  <summary>Azure Repos</summary>

After you create a new pull request, Frogbot will automatically scan it.

> **_NOTE:_** The scan output will include only new vulnerabilities added by the pull request.
> Vulnerabilities that aren't new, and existed in the code before the pull request was created, will not be included in
> the
> report. In order to include all the vulnerabilities in the report, including older ones that weren't added by this
> PR, use the includeAllVulnerabilities parameter in the frogbot-config.yml file.

The Frogbot Azure Repos scan workflow is:

1. The developer opens a pull request.
2. Frogbot scans the pull request and adds a comment with the scan results.
3. Frogbot can be triggered again following new commits, by adding a comment with the `rescan` text.

</details>

<details>
  <summary>Bitbucket Server</summary>

After you create a new pull request, Frogbot will automatically scan it.

> **_NOTE:_** The scan output will include only new vulnerabilities added by the pull request.
> Vulnerabilities that aren't new, and existed in the code before the pull request was created, will not be included in
> the
> report. In order to include all of the vulnerabilities in the report, including older ones that weren't added by this
> PR, use the includeAllVulnerabilities parameter in the frogbot-config.yml file.

The Frogbot scan on Bitbucket Server workflow:

1. The developer opens a pull request.
2. Frogbot scans the pull request and adds a comment with the scan results.
3. Frogbot can be triggered again following new commits, by adding a comment with the `rescan` text.

</details>

<details>
  <summary>GitHub</summary>

After you create a new pull request, the maintainer of the Git repository can trigger Frogbot to scan the pull request from the pull request UI.

> **_NOTE:_** The scan output will include only new vulnerabilities added by the pull request.
> Vulnerabilities that aren't new, and existed in the code before the pull request was created, will not be included in
> the
> report. In order to include all of the vulnerabilities in the report, including older ones that weren't added by this
> PR, use the includeAllVulnerabilities parameter in the frogbot-config.yml file.

The Frogbot GitHub scan workflow is:

1. The developer opens a pull request.
2. The Frogbot workflow automatically gets triggered and a [GitHub environment](https://docs.github.com/en/actions/deployment/targeting-different-environments/using-environments-for-deployment#creating-an-environment) named `frogbot` becomes pending for the maintainer's approval.

[![](./images/github-pending-deployment.png)](#running-frogbot-on-github)

3. The maintainer of the repository reviews the pull request and approves the scan: [![](./images/github-deployment.gif)](#running-frogbot-on-github)
4. Frogbot can be triggered again following new commits, by repeating steps 2 and 3.

</details>

<details>
  <summary>GitLab</summary>

After you create a new merge request, the maintainer of the Git repository can trigger Frogbot to scan the merge request from the merge request UI.

> **_NOTE:_** The scan output will include only new vulnerabilities added by the merge request.
> Vulnerabilities that aren't new, and existed in the code before the merge request was created, will not be included in
> the
> report. In order to include all of the vulnerabilities in the report, including older ones that weren't added by this
> merge request, use the includeAllVulnerabilities parameter in the frogbot-config.yml file.

The Frogbot GitLab flow is as follows:

1. The developer opens a merge request.
2. The maintainer of the repository reviews the merge request and approves the scan by triggering the manual _frogbot-scan_ job.
3. Frogbot is then triggered by the job, it scans the merge request, and adds a comment with the scan results.
4. Frogbot can be triggered again following new commits, by triggering the _frogbot-scan_ job again.
   [GitLab CI Run Button](./images/gitlab-run-button.png)

</details>

### 👮 Security note for pull requests scanning

When installing Frogbot using JFrog Pipelines, Jenkins and Azure DevOps, Frogbot will not wait for a maintainer's approval before scanning newly opened pull requests. Using Frogbot with these platforms, however, isn't recommended for open-source projects.

When installing Frogbot using GitHub Actions and GitLab however, Frogbot will initiate the scan only after it is approved by a maintainer of the project. The goal of this review is to ensure that external code contributors don't introduce malicious code as part of the pull request. Since this review step is enforced by Frogbot when used with GitHub Actions and GitLab, it is safe to be used for open-source projects.

### Scan results

Frogbot adds the scan results to the pull request in the following format:

#### 👍 No issues

If no new vulnerabilities are found, Frogbot automatically adds the following comment to the pull request:

[![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/noVulnerabilityBanner.png)](#-no-issues)

#### 👎 Issues were found

If new vulnerabilities are found, Frogbot adds them as a comment on the pull request. For example:

[![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/vulnerabilitiesBanner.png)](#-issues-were-found)

|                                            SEVERITY                                             | IMPACTED PACKAGE                         | VERSION | FIXED VERSIONS | DIRECT DEPENDENCIES                      | DIRECT DEPENDENCIES VERSIONS | CVE            |
|:-----------------------------------------------------------------------------------------------:|------------------------------------------|---------|----------------|------------------------------------------|:----------------------------:|----------------|
|   ![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/highSeverity.png) High   | github.com/nats-io/nats-streaming-server | v0.21.0 | [0.24.1]       | github.com/nats-io/nats-streaming-server |           v0.21.0            | CVE-2022-24450 |
|   ![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/highSeverity.png) High   | github.com/mholt/archiver/v3             | v3.5.1  |                | github.com/mholt/archiver/v3             |            v3.5.1            |
| ![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/mediumSeverity.png) Medium | github.com/nats-io/nats-streaming-server | v0.21.0 | [0.24.3]       | github.com/nats-io/nats-streaming-server |           v0.21.0            | CVE-2022-26652 |

## Scanning repositories and fixing issues

Frogbot scans your Git repository and automatically opens pull requests for upgrading vulnerable dependencies to a version with a fix.

![](./images/fix-pr.png)

For GitHub repositories, Frogbot also adds [Security Alerts](https://docs.github.com/en/code-security/code-scanning/automatically-scanning-your-code-for-vulnerabilities-and-errors/managing-code-scanning-alerts-for-your-repository) which you can view in the GitHub UI:

![](./images/github-code-scanning.png)

![](./images/github-code-scanning-content.png)

Frogbot uses [JFrog Xray](https://jfrog.com/xray/) for the scanning. The scanning is triggered following commits that are pushed to the repository.

Supported package management tools:

- Go
- Maven
- npm
- Pip
- Pipenv
- Poetry
- Yarn 2

</details>

<div id="installing-frogbot"></div>

## 🖥️ Installing Frogbot

- [Installing Frogbot on Azure Repos repositories](docs/install-azure-repos.md)
- [Installing Frogbot on Bitbucket Server repositories](docs/install-bitbucket-server.md)
- [Installing Frogbot on GitHub repositories](docs/install-github.md)
- [Installing Frogbot on GitLab repositories](docs/install-gitlab.md)

<div id="reporting-issues"></div>

## 🌐 Air-Gapped Environments
Virtually all development organizations need access to remote public resources such as Maven Central, NuGet Gallery, npmjs.org, Docker Hub etc., to download dependencies needed for a build. 

One of the big benefits of using Artifactory is its remote repositories which proxy these remote resources and cache artifacts that are downloaded. This way, once any developer or CI server that has requested an artifact for the first time, it is cached and directly available from the remote repository in Artifactory on the internal network. This is the usual way to work with remote resources through Artifactory.

### How to use Frogbot on Air-Gapped Environments
To use Frogbot with Artifactory on an air-gapped environments you need to set 2 repositories. Please follow the following steps in order to configure these repositories.

#### Step 1
You need a repository that will serve as a remote repository to download Frogbot binary and its dependencies, such as Maven and Gradle build-info extractors.
1. Create a new **Generic** remote repository in your Artifactory instance.
2. Set the remote repository url to [https://releases.jfrog.io](https://releases.jfrog.io).
3. Add to your frogbot template from the "Installing Frogbot" section a new environment variable named `JF_FROGBOT_REPO` with the name of your newly created remote repository as the value. 

#### Step 2
You need a repository that will serve as a remote repository for your dependencies, based on your project technology.
If you don't have one already:
1. Create a new remote repository from with a type that matches your project dependencies.
2. Leave the URL as its default value, or set a custom one if desired.

In your [frogbot-config.yml](docs/templates/.frogbot/frogbot-config.yml) file, set the `repository` field under the relevant `project`
as the name of your dependencies repository.

> Not familiar with the [frogbot-config.yml](docs/templates/.frogbot/frogbot-config.yml) file? Please read [this](docs/frogbot-config.md).

## 🔥 Reporting issues

Please help us improve Frogbot by [reporting issues](https://github.com/jfrog/frogbot/issues/new/choose) you encounter.

<div id="contributions"></div>

## 💻 Contributions

We welcome pull requests from the community. To help us improve this project, please read our [Contribution](./CONTRIBUTING.md#-guidelines) guide.
