#  Creating the frogbot-config.yml file

## Overview

The [frogbot-config.yml](templates/.frogbot/frogbot-config.yml) includes the configuration required for Frogbot to scan your Git repositories. If your Git organization includes multiple repositories that need to be scanned, you can either place the [frogbot-config.yml](templates/.frogbot/frogbot-config.yml) file in each repository, or alternatively, place it in a single repository. The repository which includes the [frogbot-config.yml](templates/.frogbot/frogbot-config.yml) file will be referenced as the **Frogbot Management Repository** throughout this documentation.

## Adding the frogbot-config.yml file to Git

1. Decide which repository in your organization is the **Frogbot Management Repository**.
2. Push a file named frogbot-config.yml to this repository, under a directory named `.frogbot`. The file path should be `.frogbot/frogbot-config.yml`


# The file syntax

[frogbot-config.yml](templates/.frogbot/frogbot-config.yml) is a simple YAML configuration file. The config file defines an array of repositories by specifying the `params` keyword for each repository.
> Most of the properties in the file are **OPTIONAL**, please note the ones that specified as **MANDATORY**.

## Params

Using the `params` we can define the `git`, `jfrogPlatform` and `scan` parameters for each of our repositories.

### git

Allows you to set the git related information.

- `repoName`
    - **MANDATORY**
    - Used to point to the relevant repository.
- `branches`
    - List of `branches` to preform the commands on.
    - If the config file is used to run Frogbot's `scan-and-fix-repos` or `create-fix-pull-requests` commands, it is **MANDATORY** to set this property.

### scan

Allows you to set the scanning features of Frogbot.

- `includeAllVulnerabilities`
    - Displays all existing vulnerabilities, including the ones that were added by the pull request and the ones that are inside the target branch already.

- `failOnSecurityIssues`
    - Fails the Frogbot task if any security issue is found.
- `projects`
    - A list of package manager related projects.
    - Each element in the list represents at least one directory with a common technology.
    - properties:
        - `workingDirs`
            - A list of relative path's to the projects directories in the git repository.
            - Each directory supposed to share the same technology.
            - If not specified, the root directory of the repository will be scanned.
        - `installCommandName`
            - **MANDATORY** for projects which use npm, yarn 2, NuGet and .NET to download their dependencies
            - Represents the installation command (e.g. npm, maven, yarn).
        - `installCommandArgs`
            - Goes along with `installCommandName`, and it is also **MANDATORY** for these projects.
            - Represents the list of arguments to the installation command (e.g. install, i).
        - `pipRequirementsFile`
            - **MANDATORY** for pip only if using a requirements file.
            - If not specified, the command that will install the dependencies with pip is `pip install .`.
        - `useWrapper`
            - For projects which are using Gradle.
            - Disables/Enables building Gradle projects with Gradle Wrapper.

### jfrogPlatform

Allows you to set information related to the JFrog Platform settings.

- `jfrogProjectKey`
    - JFrog project key. Learn more about it here: https://www.jfrog.com/confluence/display/JFROG/Projects.
- `watches`
    - List of Xray watches. Learn more about them here: https://www.jfrog.com/confluence/display/JFROG/Configuring+Xray+Watches.