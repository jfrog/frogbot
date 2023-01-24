[Go back to the main documentation page](../README.md)

# Creating the frogbot-config.yml file

## Overview

The [frogbot-config.yml](templates/.frogbot/frogbot-config.yml) file includes the configuration required for Frogbot to scan your Git repositories.

## Adding the frogbot-config.yml file to Git

1. If you're using one of the below platforms, you can choose a single repository in the organization to include the [frogbot-config.yml](templates/.frogbot/frogbot-config.yml) file.
    - GitHub with Jenkins or JFrog Pipelines
    - Bitbucket Server
    - Azure Repos

   If you're using one of the below platforms, each repository that needs to be scanned by Frogbot should include the [frogbot-config.yml](templates/.frogbot/frogbot-config.yml) file.
    - GitHub with GitHub actions
    - GitLab

2. Push the file to the root of your repository. The path should be: `.frogbot/frogbot-config.yml`

## The file structure
### Params

This section represents a single Git repository. It includes the **git**, **jfrogPlatform** and **scan** sections.

#### git

This section includes the git repository related parameters.

- **repoName** - [Mandatory] The name of the Git repository to scan.
- **branches** - [Mandatory] The branches to scan

#### scan

This section includes the scanning options for Frogbot.

- **includeAllVulnerabilities** - [Optional, Default: false] Frogbot displays all the existing vulnerabilities, including the ones that were added by the pull request and the ones that are inside the target branch already.

- **failOnSecurityIssues** - [Optional. Default: true] Frogbot fails the task if any security issue is found.
- **projects** - List of sub-projects / project dirs.
    - **workingDirs** - [Optional, Default: root directory] A list of relative path's inside the Git repository. Each path should point to the root of a sub-project to be scanned by Frogbot.
    - **installCommand** - [Mandatory for projects which use npm, yarn 2, NuGet and .NET to download their dependencies] The command to download the project dependencies. For example: 'npm install', 'nuget restore'.
    - **pipRequirementsFile** [Mandatory for projects which use the pip package manager to download their dependencies, if pip requires the requirements file]
    - **useWrapper** - [Optional, default: true] Determines whether to use the Gradle Wrapper for projects which are using Gradle.

#### jfrogPlatform

The section includes the JFrog Platform settings

- **jfrogProjectKey** - [Optional] The JFrog project key. Learn more about it [here](https://www.jfrog.com/confluence/display/JFROG/Projects).
- **watches** - [Optional] The list of Xray watches. Learn more about it [here](https://www.jfrog.com/confluence/display/JFROG/Configuring+Xray+Watches).