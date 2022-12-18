[Go back to the main documentation page](../README.md)
# Installing Frogbot on Azure Repos repositories

To install Frogbot on Azure Repos repositories:

1. Go to Azure DevOps Pipelines of the relevant project, and add `New pipeline`.
2. Set `Azure Repos Git` as your code source.
3. Select the repository you'd like Frogbot to scan.
4. Select 'Starter Pipeline' and use `frogbot-scan-pr.yml` and `frogbot-scan-and-fix.yml`:
5. Make sure you have the connection details of your JFrog environment.
6. In the pipeline page save the JFrog connection details as variables with the
   following names - JF_URL, JF_USER, and JF_PASSWORD.

> **_NOTE:_** You can also use **JF_XRAY_URL** and **JF_ARTIFACTORY_URL** instead of **JF_URL**, and **JF_ACCESS_TOKEN**
> instead of **JF_USER** and **JF_PASSWORD**.

7. To set variables in the pipeline page, click on `Variables` button and set `New variable`:

   ![variables_button.png](../images/azure-variables-button.png)

   ![img_1.png](../images/azure-new-variable.png)

   And set the relevant mandatory variables according the chosen pipeline template.

#### frogbot-scan-pr.yml:

```yaml
# Select on which branches to trigger the pipeline
trigger:
   branches:
      include:
         - master
         - dev
         - main

pool:
   vmImage: ubuntu-latest

jobs:
   - job:
     condition: and(succeeded(), eq(variables['Build.Reason'], 'PullRequest'))
     displayName: "Frogbot Scan Pull Request"
     steps:
        - task: CmdLine@2
          displayName: 'Download and Run Frogbot'
          env:
             # [Mandatory]
             # Azure Repos personal access token with Code -> Read & Write permissions
             JF_GIT_TOKEN: $(USER_TOKEN)

             # [Mandatory only for projects which use npm, yarn 2, NuGet and .NET to download their dependencies]
             # The command that installs the project dependencies (e.g "npm i", "nuget restore" or "dotnet restore")
             JF_INSTALL_DEPS_CMD: ""

             # [Mandatory]
             # JFrog platform URL (This functionality requires version 3.29.0 or above of Xray)
             JF_URL: $(JF_URL)

             # [Mandatory if JF_ACCESS_TOKEN is not provided]
             # JFrog user and password with 'read' permissions for Xray
             JF_USER: $(JF_USER)
             JF_PASSWORD: $(JF_PASSWORD)

             # [Mandatory if JF_USER and JF_PASSWORD are not provided]
             # JFrog access token with 'read' permissions for Xray
             # JF_ACCESS_TOKEN: $(JF_ACCESS_TOKEN)

             # [Optional, default: "."]
             # Relative path to the project in the git repository
             # JF_WORKING_DIR: path/to/project/dir

             # [Optional]
             # Xray Watches. Learn more about them here: https://www.jfrog.com/confluence/display/JFROG/Configuring+Xray+Watches
             # JF_WATCHES: <watch-1>,<watch-2>...<watch-n>

             # [Optional]
             # JFrog project. Learn more about it here: https://www.jfrog.com/confluence/display/JFROG/Projects
             # JF_PROJECT: <project-key>

             # [Optional, default: "FALSE"]
             # Displays all existing vulnerabilities, including the ones that were added by the pull request.
             # JF_INCLUDE_ALL_VULNERABILITIES: "TRUE"

             # [Optional, default: "TRUE"]
             # Fails the Frogbot task if any security issue is found.
             # JF_FAIL: "FALSE"

             # Predefined Azure Pipelines variables. There's no need to set them.
             JF_GIT_PULL_REQUEST_ID: $(System.PullRequest.PullRequestId)
             JF_GIT_PROJECT: $(System.TeamProject)
             JF_GIT_REPO: $(Build.Repository.Name)
             JF_GIT_API_ENDPOINT: $(System.CollectionUri)
             JF_GIT_BASE_BRANCH: $(System.PullRequest.TargetBranch)
             JF_GIT_OWNER: $(System.TeamProject)
             JF_GIT_PROVIDER: 'azureRepos'

          inputs:
             script: |
                curl -fLg "https://releases.jfrog.io/artifactory/frogbot/v2/[RELEASE]/getFrogbot.sh" | sh
                ./frogbot spr
```

#### frogbot-scan-and-fix.yml:

```yaml
# Select on which branches to trigger the pipeline
trigger:
   branches:
      include:
         - master
         - dev
         - main

pr: none

pool:
   vmImage: ubuntu-latest

jobs:
   - job:
     displayName: "Frogbot Scan and Fix"
     condition: and(succeeded(), eq(variables['Build.Reason'], 'IndividualCI'))
     steps:
        - task: CmdLine@2
          displayName: 'Download and Run Frogbot'
          env:
             # [Mandatory]
             # Azure Repos personal access token with Code -> Read & Write permissions
             JF_GIT_TOKEN: $(USER_TOKEN)

             # [Mandatory only for projects which use npm, yarn 2, NuGet and .NET to download their dependencies]
             # The command that installs the project dependencies (e.g "npm i", "nuget restore" or "dotnet restore")
             JF_INSTALL_DEPS_CMD: ""

             # [Mandatory]
             # JFrog platform URL (This functionality requires version 3.29.0 or above of Xray)
             JF_URL: $(JF_URL)

             # [Mandatory if JF_ACCESS_TOKEN is not provided]
             # JFrog user and password with 'read' permissions for Xray
             JF_USER: $(JF_USER)
             JF_PASSWORD: $(JF_PASSWORD)

             # [Mandatory if JF_USER and JF_PASSWORD are not provided]
             # JFrog access token with 'read' permissions for Xray
             # JF_ACCESS_TOKEN: $(JF_ACCESS_TOKEN)

             # [Optional, default: "."]
             # Relative path to the project in the git repository
             # JF_WORKING_DIR: path/to/project/dir

             # [Optional]
             # Xray Watches. Learn more about them here: https://www.jfrog.com/confluence/display/JFROG/Configuring+Xray+Watches
             # JF_WATCHES: <watch-1>,<watch-2>...<watch-n>

             # [Optional]
             # JFrog project. Learn more about it here: https://www.jfrog.com/confluence/display/JFROG/Projects
             # JF_PROJECT: <project-key>

             # [Optional, default: "FALSE"]
             # Displays all existing vulnerabilities, including the ones that were added by the pull request.
             # JF_INCLUDE_ALL_VULNERABILITIES: "TRUE"

             # [Optional, default: "TRUE"]
             # Fails the Frogbot task if any security issue is found.
             # JF_FAIL: "FALSE"

             # Predefined Azure Pipelines variables. There's no need to set them.
             JF_GIT_PROJECT: $(System.TeamProject)
             JF_GIT_REPO: $(Build.Repository.Name)
             JF_GIT_API_ENDPOINT: $(System.CollectionUri)
             JF_GIT_BASE_BRANCH: $(Build.SourceBranchName)
             JF_GIT_OWNER: $(System.TeamProject)
             JF_GIT_PROVIDER: 'azureRepos'

          inputs:
             script: |
                curl -fLg "https://releases.jfrog.io/artifactory/frogbot/v2/[RELEASE]/getFrogbot.sh" | sh
                ./frogbot cfpr
```
