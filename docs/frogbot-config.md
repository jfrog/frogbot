#  Creating the frogbot-config.yml file

## Overview

The [frogbot-config.yml](templates/.frogbot/frogbot-config.yml) includes the configuration required for Frogbot to scan your Git repositories. If your Git organization includes multiple repositories that need to be scanned, you can either place the [frogbot-config.yml](templates/.frogbot/frogbot-config.yml) file in each repository, or alternatively, place it in a single repository. The repository which includes the [frogbot-config.yml](templates/.frogbot/frogbot-config.yml) file will be referenced as the **Frogbot Management Repository** throughout this documentation.

## Adding the frogbot-config.yml file to Git

1. If you're using one of the following platforms:

- GitHub with Jenkins or JFrog Pipelines
- Bitbucket Server
- Azure Repos Decide which repository in your organization is the **Frogbot Management Repository**.

  If you're using one of the following platforms:
- GitHub with GitHub actions
- GitLab each repository that needs to be scanned by Frogbot should be considered a Frogbot Management Repository.

2. Push a file named frogbot-config.yml to this repository, under a directory named `.frogbot`. The file path should be `.frogbot/frogbot-config.yml`

## The file structure

[frogbot-config.yml](templates/.frogbot/frogbot-config.yml) is a YAML configuration file. The config file defines an array of repositories by specifying the `params` keyword for each repository.

### Params

The `params` section represents a single Git repository. It includes the `git`, `jfrogPlatform` and `scan` sections.

#### git

The `git` section includes the git repository related parameters.

- `repoName` - [Mandatory] The name of the Git repository to scan.
- `branches` - [Mandatory] List of branches to scan

#### scan

This section includes the scanning options for Frogbot.

- `includeAllVulnerabilities` - [Optional, Default: false] Frogbot displays all the existing vulnerabilities, including the ones that were added by the pull request and the ones that are inside the target branch already.

- `failOnSecurityIssues` - [Optional. Default: true] Frogbot fails the task if any security issue is found.
- `projects`
    - List of sub-projects / project dirs.
        - `workingDirs` - [Optional, Default: root directory]
            - A list of relative path's inside the Git repository. Each path should point to the root of a sub-project to be scanned by Frogbot.
        - `installCommand` - [Mandatory for projects which use npm, yarn 2, NuGet and .NET to download their dependencies]
            - The command to download the project dependencies. For example: 'npm install', 'nuget restore'.
        - `pipRequirementsFile` [Mandatory for projects which use the pip package manager to download their dependencies, if pip requires the requirements file ]
        - `useWrapper` [Optional, default: true]
            - Determines whether to use the Gradle Wrapper for projects which are using Gradle.

#### jfrogPlatform

The section includes the JFrog Platform settings

- `jfrogProjectKey` - [Optional]
    - The JFrog project key. Learn more about it here: https://www.jfrog.com/confluence/display/JFROG/Projects.
- `watches` - [Optional]
    - A List of Xray watches. Learn more about them here: https://www.jfrog.com/confluence/display/JFROG/Configuring+Xray+Watches.