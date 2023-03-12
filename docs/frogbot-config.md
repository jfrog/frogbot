[Go back to the main documentation page](https://github.com/jfrog/frogbot)

# Creating the frogbot-config.yml file

## What is the frogbot-config.yml file?
The [frogbot-config.yml](templates/.frogbot/frogbot-config.yml) file includes configuration related to your projects, to help Frogbot scan your Git repositories.

## Is the file mandatory?
Not all projects require the **frogbot-config.yml** file. For projects which have a simple structure, the file isn't mandatory.
As a rule of thumb, if the following conditions apply to your project, you don't have to create the file. 

1. The project has only one descriptor file (pom.xml, package.json, go.mod, etc.) 
2. The descriptor file is at the root directory of the project 

When your Git repository includes multiple projects, and each project has its own own descriptor file (package.json in the case of npm), the **frogbot-config.yml** file should 
include the relative paths to the directories which include descriptor files.
In the following example, there are two descriptor files under `path/to/project-1` and `path/to/project-2`
```yaml
- params:
    git:
      repoName: my-git-repo-name
      branches:
        - master
    scan:
      projects:
        - installCommand: npm i
          workingDirs:
            - path/to/npm/project-1
            - path/to/npm/project-2
```

Here's another example for a repository that uses both `npm` and `nuget` to download the dependencies.
```yaml
- params:
    git:
      repoName: my-git-repo-name
      branches:
        - master
    scan:
      projects:
        - installCommand: npm i
          workingDirs:
            - path/to/node/project
        - installCommand: nuget restore
          workingDirs:
            - path/to/.net/project
```

Here's another example for a repository that uses both `npm` and `mvn` to download the dependencies.
Notice that for Maven projects, there's no need to set the `installCommand` property.
```yaml
- params:
    git:
      repoName: my-git-repo-name
      branches:
        - master
    scan:
      projects:
        - installCommand: npm i
          workingDirs:
            - path/to/node/project
        - workingDirs:
            - path/to/maven/project
```

See the full **frogbot-config.yml** structure [here](templates/.frogbot/frogbot-config.yml).

## Adding the frogbot-config.yml file to Git

1. If you're using one of the below platforms, you can choose a single repository in the organization to include the [frogbot-config.yml](templates/.frogbot/frogbot-config.yml) file.
    - GitHub with Jenkins or JFrog Pipelines
    - Bitbucket Server
    - Azure Repos

   If you're using one of the below platforms, each repository that needs to be scanned by Frogbot should include the [frogbot-config.yml](templates/.frogbot/frogbot-config.yml) file.
    - GitHub with GitHub actions
    - GitLab

2. Push the file to the following path in the root of your repository: `.frogbot/frogbot-config.yml`

## The file structure

The [frogbot-config.yml](templates/.frogbot/frogbot-config.yml) file has the following structure.

### Params

This section represents a single Git repository. It includes the **git**, **jfrogPlatform** and **scan** sections.

#### git

This section includes the git repository related parameters.

- **repoName** - [Mandatory] The name of the Git repository to scan.
- **branches** - [Mandatory] The branches to scan

#### scan

This section includes the scanning options for Frogbot.

- **includeAllVulnerabilities** - [Default: false] Frogbot displays all the existing vulnerabilities, including the ones that were added by the pull request and the ones that are inside the target branch already.

- **failOnSecurityIssues** - [Default: true] Frogbot fails the task if any security issue is found.
- **projects** - List of sub-projects / project dirs.
  - **workingDirs** - [Default: root directory] A list of relative path's inside the Git repository. Each path should point to the root of a sub-project to be scannedby Frogbot.
  - **installCommand** - [Mandatory for projects which use npm, yarn 2, NuGet and .NET to download their dependencies] The command to download the projectdependencies. For example: 'npm install', 'nuget restore'.
  - **pipRequirementsFile** [Mandatory for projects which use the pip package manager to download their dependencies, if pip requires the requirements file]
  - **useWrapper** - [Default: true] Determines whether to use the Gradle Wrapper for projects which are using Gradle.
  - **repository** - [Optional] Name of a Virtual Repository in Artifactory to resolve (download) the project dependencies from.

#### jfrogPlatform

The section includes the JFrog Platform settings

- **jfrogProjectKey** - [Optional] The JFrog project key. Learn more about it [here](https://www.jfrog.com/confluence/display/JFROG/Projects).
- **watches** - [Optional] The list of Xray watches. Learn more about it [here](https://www.jfrog.com/confluence/display/JFROG/Configuring+Xray+Watches).
