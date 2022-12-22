# Setting the Frogbot Configuration

## Defining your Frogbot Management

Frogbot configuration is defined in the [frogbot-config](templates/.jfrog/frogbot/frogbot-config.yml) file. To manage the [frogbot-config](templates/.jfrog/frogbot/frogbot-config.yml) file, you need to configure the `Frogbot Management` repository and it can be set in two ways:

1. Establish a new central management repository for the Frogbot Management.

2. Use an existing code repository as the Frogbot Management Repository.

### Central Management Repository

Creating a new management repository as your `Frogbot Management` allows you to store all Frogbot configurations in one location. This allows you to configure multiple repositories and run Frogbot tasks on them simultaneously.

>> NOTE: this kind of `Frogbot Management` is more suitable for the `scan-pull-requests` and the `scan-and-fix-repos` commands, which can operate over multiple repositories as well as single repositories.
>
> **scan-pull-requests** command scans all the open **pull requests** in the configured repositories.
>
> **scan-and-fix-repos** command scans the configured **repositories** following new commits and opens new pull requests with a fix if a vulnerability is found in the repositories.


To set up a new management repository as `Frogbot Management` follow these steps:

1. Create a new repository named `JFrog`.
2. Under the newly created repository, create a `frogbot` directory.
3. Put the [frogbot-config](templates/.jfrog/frogbot/frogbot-config.yml) under the `frogbot` directory.
4. Set the [frogbot-config](templates/.jfrog/frogbot/frogbot-config.yml) to your needs.

### Using Existing Code Repository

The `Frogbot Management` can be also set as one of your existing code repositories. This kind of `Frogbot Management` allow you to set all the Frogbot configuration for this repository.
>> NOTE: this kind of `Frogbot Management` is more suitable for the `scan-pull-request` and the `create-fix-pull-request` commands, which operate over a single repository only. These commands are supported on GitHub, Azure Repos and GitLab.
>
> **scan-pull-request** command is used to scan **pull requests** in the repository for every pull request push.
>
> **create-fix-pull-requests** command is used to scan the **repository** following new commits.

To set up your existing code repository as `Frogbot Management`, follow these steps:

1. Under the root of the chosen repository, create a `.jfrog` directory.
2. Under the newly created `.jfrog` directory, create a `frogbot` directory.
3. Put the [frogbot-config](templates/.jfrog/frogbot/frogbot-config.yml) under the `frogbot` directory.
4. Set the [frogbot-config](templates/.jfrog/frogbot/frogbot-config.yml) to your needs.

# The file syntax

[frogbot-config.yml](templates/.jfrog/frogbot/frogbot-config.yml) is a simple YAML configuration file. The config file defines an array of repositories by specifying each `params` keyword for each repository.
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