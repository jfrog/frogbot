# Frogbot GitHub Actions Templates
## General
Use these templates to install [Frogbot](https://github.com/jfrog/frogbot/blob/master/README.md#frogbot) on your GitHub repository.

## Prerequisites
Make sure to [set up 'frogbot' environment and secrets](../../README.md#setting-up-frogbot-on-github-repositories) in
your GitHub repository.

## Using the Single Repository Templates
1. Use the templates below, depending on the tool used to download dependencies for you project, to create the workflow files.
2. Only if the templates you're using include the `JF_INSTALL_DEPS_CMD` variable, make sure they include the correct command to download your project dependencies. For example, `npm i` or `nuget restore`. 
3. Push the workflow files to the `.github/workflow` directory at the root of your GitHub repository.

## The Available Templates

### Pull Requests Scanning For a Single Repository

Create a file named `frogbot-scan-pull-request.yml` with the content of one of the following templates, depending on the
tool used to download the project dependencies. Make sure to follow the guidelines in the 'Using the Templates' section
above. This will allow Frogbot to scan pull requests for security vulnerabilities after the pull requests are created
and before they are merged.

- [Maven](scan-pull-request/frogbot-scan-pr-maven.yml)
- [Gradle](scan-pull-request/frogbot-scan-pr-gradle.yml)
- [npm](scan-pull-request/frogbot-scan-pr-npm.yml)
- [Yarn 2](scan-pull-request/frogbot-scan-pr-yarn.yml)
- [Pip](scan-pull-request/frogbot-scan-pr-pip.yml)
- [Pipenv](scan-pull-request/frogbot-scan-pr-pipenv.yml)
- [Go](scan-pull-request/frogbot-scan-pr-go.yml)
- [DotNet](scan-pull-request/frogbot-scan-pr-dotnet.yml)
- [NuGet](scan-pull-request/frogbot-scan-pr-nuget.yml)

### Pull Requests Opening For a Single Repository

Create a file named `frogbot-scan-and-fix.yml` with the content of one of the following templates, depending on the tool
used to download the project dependencies. Make sure to follow the guidelines in the 'Using the Templates' section
above. This will make Frogbot open pull requests with fixes for security vulnerabilities found in the GitHub repository.

- [Maven](scan-and-fix/frogbot-scan-and-fix-maven.yml)
- [npm](scan-and-fix/frogbot-scan-and-fix-npm.yml)
- [Go](scan-and-fix/frogbot-scan-and-fix-go.yml)
- [Pip](scan-and-fix/frogbot-scan-and-fix-pip.yml)
- [Yarn 2](scan-and-fix/frogbot-scan-and-fix-yarn.yml)
- [Pipenv](scan-and-fix/frogbot-scan-and-fix-pipenv.yml)

### Scan Open Pull Requests for Multiple Repositories

Create a new repository named `JFrog`.

Make a folder named `.jfrog` under the newly created repository and add a `frogbot-config.yml` file to it, following the
template for `frogbot-config.yml`.

Create a workflow file named [frogbot-scan-pull-requests.yml](scan-pull-requests/frogbot-scan-pull-requests.yml) under
the `.github/workflows` folder in the `JFrog`
repository. Depending on the tool used to download the project dependencies, uncomment the installation prerequisites
inside
the workflow file.

#### Create a GitHub Personal Access Token

To use the [frogbot-scan-pull-requests.yml](scan-pull-requests/frogbot-scan-pull-requests.yml) workflow, you need to set
the GH_PAT environment variable.
Please
follow [GitHub Documentation](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/creating-a-personal-access-token)
to create one with Read and Write permissions to actions, code scanning alerts, commit statuses, pull requests, security
events, and workflows.
