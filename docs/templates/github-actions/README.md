[Go back to the Github Installation documentation page](../../install-github.md)
# Frogbot GitHub Actions Templates
## General
Use these templates to install [Frogbot](https://github.com/jfrog/frogbot/blob/master/README.md#frogbot) on your GitHub repository.

## Prerequisites
Make sure to [set up 'frogbot' environment and secrets](../../install-github.md#installing-frogbot-on-github-repositories) in
your GitHub repository.

## Using the Templates
1. Use the templates below, depending on the tool used to download dependencies for you project, to create the workflow files.
2. Push the workflow files to the `.github/workflows` directory at the root of your GitHub repository.

**IMPORTANT**: The workflow files must be pushed to the target branch before Frogbot is triggered. This means that if, for example, a pull request includes the workflow files and the target branch doesn't, Frogbot will fail to run.

## The Available Templates
### Scan pull requests when they are opened

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
- [Poetry](scan-pull-request/frogbot-scan-pr-poetry.yml)
- [Go](scan-pull-request/frogbot-scan-pr-go.yml)
- [DotNet](scan-pull-request/frogbot-scan-pr-dotnet.yml)
- [NuGet](scan-pull-request/frogbot-scan-pr-nuget.yml)

### Scanning repositories and fixing issues

Create a file named `frogbot-scan-and-fix.yml` with the content of one of the following templates, depending on the tool used to download the project dependencies. Make sure to follow the guidelines in the 'Using the Templates' section above. This will make Frogbot open pull requests with fixes for security vulnerabilities found in the GitHub repository.

- [Maven](scan-and-fix/frogbot-scan-and-fix-maven.yml)
- [npm](scan-and-fix/frogbot-scan-and-fix-npm.yml)
- [Go](scan-and-fix/frogbot-scan-and-fix-go.yml)
- [Pip](scan-and-fix/frogbot-scan-and-fix-pip.yml)
- [Yarn 2](scan-and-fix/frogbot-scan-and-fix-yarn.yml)
- [Pipenv](scan-and-fix/frogbot-scan-and-fix-pipenv.yml)
- [Poetry](scan-and-fix/frogbot-scan-and-fix-poetry.yml)
