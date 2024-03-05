<div align="center">
   
# Frogbot

[![Frogbot](images/frogbot-intro.png)](#readme)

[![Build status](https://github.com/jfrog/frogbot/actions/workflows/test.yml/badge.svg)](https://github.com/jfrog/frogbot/actions/workflows/test.yml) [![GitHub Action Test](https://github.com/jfrog/frogbot/actions/workflows/action-test.yml/badge.svg)](https://github.com/jfrog/frogbot/actions/workflows/action-test.yml)
[![Coverage Status](https://coveralls.io/repos/github/jfrog/frogbot/badge.svg?branch=dev)](https://coveralls.io/github/jfrog/frogbot?branch=dev) [![Go Report Card](https://goreportcard.com/badge/github.com/jfrog/frogbot)](https://goreportcard.com/report/github.com/jfrog/frogbot)

</div>

## 🤖 What is Frogbot?

Frogbot is a Git bot that scans your pull requests for security vulnerabilities using [JFrog Xray](https://jfrog.com/xray/) . Frogbot adds the scan results as a comment on the pull request. If no new vulnerabilities are found, Frogbot will also add a comment, confirming this.
Please note that GitHub and GitLab are currently supported and Bitbucket will be supported soon.
Projects that use one of the following tools to download their dependencies are currently supported.

- Npm
- Maven
- Gradle
- Go
- Pip
- Pipenv
- Nuget
- Dotnet

## 🕵️‍♀️ How does it work?

### General

For security reasons, Frogbot is not triggered automatically.
After you create a new pull request, the maintainer of the git repository can trigger Frogbot to scan the pull request from the pull request UI. The scan output will include only new vulnerabilities added by the pull request. Vulnerabilities that aren't new, and existed in the code prior to the pull request creation, will not be included in the report.

### Running Frogbot on GitHub

1. A developer opens a pull request.
2. If missing, Frogbot creates the `🐸 frogbot scan` label in the repository.
3. A maintainer of the repository assigns the `🐸 frogbot scan` label on the pull request.
4. Frogbot is triggered by the label, scans the pull request, adds a comment with the scan results, and removes the label from the pull request.
5. Frogbot can be triggered again following new commits, by adding the label to the pull request again.

### Running Frogbot on GitLab

1. A developer opens a merge request.
2. A maintainer of the repository triggers the manual **frogbot-scan** job.
3. Frogbot is triggered by the job, scans the merge request, and adds a comment with the scan results.
4. Frogbot can be triggered again following new commits, by triggering the **frogbot-scan** job again
   [![GitLab CI Run Button](./images/gitlab-run-button.png)](#-Using-Frogbot-with-GitLab-CI).

## Pull Request Comments

### 👍 No issues

If no new vulnerabilities are found, Frogbot automatically adds the following comment to the pull request:

[![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/noVulnerabilityBanner.png)](#-no-issues)

### 👎 Issues were found

If new vulnerabilities are found, Frogbot adds them as a comment on the pull request. For example:

[![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/vulnerabilitiesBanner.png)](#-issues-were-found)

|                                            SEVERITY                                             | IMPACTED PACKAGE                         | VERSION | FIXED VERSIONS | COMPONENT                                | COMPONENT VERSION | CVE            |
| :---------------------------------------------------------------------------------------------: | ---------------------------------------- | ------- | -------------- | ---------------------------------------- | :---------------: | -------------- |
|   ![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/highSeverity.png) High   | github.com/nats-io/nats-streaming-server | v0.21.0 | [0.24.1]       | github.com/nats-io/nats-streaming-server |      v0.21.0      | CVE-2022-24450 |
|   ![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/highSeverity.png) High   | github.com/mholt/archiver/v3             | v3.5.1  |                | github.com/mholt/archiver/v3             |      v3.5.1       |
| ![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/mediumSeverity.png) Medium | github.com/nats-io/nats-streaming-server | v0.21.0 | [0.24.3]       | github.com/nats-io/nats-streaming-server |      v0.21.0      | CVE-2022-26652 |

## 🖥️ Installing and Using Frogbot

### General

1. Frogbot requires a JFrog environment to scan pull requests. Don't have a JFrog environment? No problem - [Set Up a FREE JFrog Environment in the Cloud](#set-up-a-free-jfrog-environment-in-the-cloud). You'll later save the connection details (URL, username, and password) as secrets in Git.
2. Setting up Frogbot on a GitHub repository? [Install Frogbot using GitHub Actions](#install-frogbot-using-github-actions)
3. Setting up Frogbot on a GitLab repository? [Install Frogbot using GitLab CI](#install-frogbot-using-gitlab-ci)

### Set up a FREE JFrog Environment in the Cloud

Need a FREE JFrog environment in the cloud, so Frogbot can scan your pull requests?

Just run one of the following commands in your terminal, to set up an environment in less than a minute. The commands will do the following:

1. Install [JFrog CLI](https://www.jfrog.com/confluence/display/CLI/JFrog+CLI) on your machine.
2. Create a FREE JFrog environment in the cloud for you.

After the set up is complete, you'll receive an email with your JFrog environment connection details, which you can then store as secrets in Git.

**On MacOS and Linux using cUrl**

```
curl -fL https://getcli.jfrog.io?setup | sh
```

**On Windows using PowerShell**

```
powershell "Start-Process -Wait -Verb RunAs powershell '-NoProfile iwr https://releases.jfrog.io/artifactory/jfrog-cli/v2-jf/[RELEASE]/jfrog-cli-windows-amd64/jf.exe -OutFile $env:SYSTEMROOT\system32\jf.exe'" ; jf setup
```

### Install Frogbot Using GitHub Actions

1. Make sure you have the connection details of your JFrog environment.
2. Save the JFrog connection details as secrets in GitHub with the following names - **JF_URL**, **JF_USER**, and **JF_PASSWORD** (You can also use **JF_ACCESS_TOKEN** instead of **JF_USER** and **JF_PASSWORD**).
3. Use one of these [GitHub Actions templates](templates/github-actions/README.md#frogbot-gitHub-actions-templates) to create a file named `frogbot.yml`.
4. Push the `frogbot.yml` file to the `.github/workflows` directory in the root of your GitHub repository.

### Install Frogbot Using GitLab CI

1. Make sure you have the connection details of your JFrog environment.
2. Save the JFrog connection details as secrets in GitLab with the following names: _JF_URL_, _JF_USER_ and _JF_PASSWORD_ (You can also use _JF_ACCESS_TOKEN_ instead of _JF_USER_ and _JF_PASSWORD_).
3. Add a job named `frogbot-scan` to your `.gitlab-ci.yml` file in your GitLab repository using the below structure.

**Important Guidelines**

- For npm, pip, pipenv, nuget or dotnet: Make sure to set the command in a way that it downloads your project dependencies as the value of the **JF_INSTALL_DEPS_CMD** variable. For example, `npm i` or `nuget restore`
- Make sure that either **JF_USER** and **JF_PASSWORD** or **JF_ACCESS_TOKEN** are set, but not both.

```yml
frogbot-scan:
  rules:
    - if: $CI_PIPELINE_SOURCE == 'merge_request_event'
  when: manual
  variables:
    # [Mandatory only for project which npm, pip, pipenv, nuget and dotnet]
    # The command that installs the project dependencies (e.g "npm i", "nuget restore" or "dotnet restore")
    JF_INSTALL_DEPS_CMD: ""

    # [Mandatory]
    # JFrog platform URL
    JF_URL: $JF_URL

    # [Mandatory if JF_ACCESS_TOKEN is not provided]
    # JFrog user and password with 'read' permissions for Xray
    JF_USER: $JF_USER
    JF_PASSWORD: $JF_PASSWORD

    # [Mandatory]
    # GitLab accesses token with the following permissions scopes: api, read_api, read_user, read_repository
    JF_GIT_TOKEN: $USER_TOKEN

    # Predefined GitLab variables. There's no need to set them.
    JF_GIT_PROVIDER: gitlab
    JF_GIT_OWNER: $CI_PROJECT_NAMESPACE
    JF_GIT_REPO: $CI_PROJECT_NAME
    JF_GIT_BASE_BRANCH: $CI_MERGE_REQUEST_TARGET_BRANCH_NAME
    JF_GIT_PULL_REQUEST_ID: $CI_MERGE_REQUEST_IID

    # Uncomment the below options if you'd like to use them.

    # [Optional, default: https://gitlab.com]
    # API endpoint to GitLab
    # JF_GIT_API_ENDPOINT: https://gitlab.example.com

    # [Mandatory if JF_USER and JF_PASSWORD are not provided]
    # JFrog access token with 'read' permissions for Xray
    # JF_ACCESS_TOKEN: $JF_ACCESS_TOKEN

    # [Optional, default: "."]
    # Relative path to the project in the git repository
    # JF_WORKING_DIR: path/to/project/dir

    # [Optional]
    # Xray Watches. Learn more about them here: https://www.jfrog.com/confluence/display/JFROG/Configuring+Xray+Watches
    # JF_WATCHES: <watch-1>,<watch-2>...<watch-n>

    # [Optional]
    # JFrog project. Learn more about it here: https://www.jfrog.com/confluence/display/JFROG/Projects
    # JF_PROJECT: <project-key>
  script:
    # For Linux / MacOS runner:
    - curl -fLg "https://releases.jfrog.io/artifactory/frogbot/v1/[RELEASE]/getFrogbot.sh" | sh
    - ./frogbot scan-pull-request

    # For Windows runner:
    # iwr https://releases.jfrog.io/artifactory/frogbot/v1/[RELEASE]/frogbot-windows-amd64/frogbot.exe -OutFile .\frogbot.exe
    # .\frogbot.exe scan-pull-request
```

## 💻 Contributions

We welcome pull requests from the community. To help us improve this project, please read our [Contribution](./CONTRIBUTING.md#-guidelines) guide.
gaiii