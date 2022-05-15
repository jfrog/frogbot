# Frogbot GitHub Actions Templates
## General
Use these templates to install [Frogbot](https://github.com/jfrog/frogbot/blob/master/README.md#frogbot) on your GitHub repository.

## Using the Templates
1. [Install Frogbot](../../README.md#install-frogbot-using-github-actions) in your GitHub repository.
3. Use one of the templates below, depending on the tool used to download dependencies for you project, to create a file named `frogbot.yml`.
4. Only if the template you're using includes the `JF_INSTALL_DEPS_CMD` variable, make sure it includes the correct command to download your project dependencies. For example, `npm i` or `nuget restore`. 
5. Push the `frogbot.yml` file to the `.github/workflow` directory at the root of your GitHub repository.

## The Available Templates
- [Maven](frogbot-maven.yml)
- [Gradle](frogbot-gradle.yml)
- [npm](frogbot-npm.yml)
- [Pip](frogbot-pip.yml)
- [Pipenv](frogbot-pipenv.yml)
- [Go](frogbot-go.yml)
- [DotNet](frogbot-dotnet.yml)
- [NuGet](frogbot-nuget.yml)
