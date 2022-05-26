# Frogbot GitHub Actions Templates
## General
Use these templates to install [Frogbot](https://github.com/jfrog/frogbot/blob/master/README.md#frogbot) on your GitHub repository.

## Using the Templates
1. [Install Frogbot](../../README.md#install-frogbot-using-github-actions) in your GitHub repository.
3. Use the templates below, depending on the tool used to download dependencies for you project, to create the workflow files.
4. Only if the template you're using includes the `JF_INSTALL_DEPS_CMD` variable, make sure it includes the correct command to download your project dependencies. For example, `npm i` or `nuget restore`. 
5. Push the workflow files to the `.github/workflow` directory at the root of your GitHub repository.

## The Available Templates
### Pull Requests Scanning
- [Maven](scan-pull-request/frogbot-scan-pr-maven.yml)
- [Gradle](scan-pull-request/frogbot-scan-pr-gradle.yml)
- [npm](scan-pull-request/frogbot-scan-pr-npm.yml)
- [Pip](scan-pull-request/frogbot-scan-pr-pip.yml)
- [Pipenv](scan-pull-request/frogbot-scan-pr-pipenv.yml)
- [Go](scan-pull-request/frogbot-scan-pr-go.yml)
- [DotNet](scan-pull-request/frogbot-scan-pr-dotnet.yml)
- [NuGet](scan-pull-request/frogbot-scan-pr-nuget.yml)
### Pull Requests Opening
- [Maven](create-fix-pull-requests/frogbot-fix-maven.yml)
- [npm](create-fix-pull-requests/frogbot-fix-npm.yml)
- [Go](create-fix-pull-requests/frogbot-fix-go.yml)
