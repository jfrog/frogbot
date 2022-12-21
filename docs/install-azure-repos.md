[Go back to the main documentation page](../README.md)

# Installing Frogbot on Azure Repos repositories

To install Frogbot on Azure Repos repositories:

1. Go to your Azure Pipelines project, and add a new pipeline:

   ![azure-new-pipeline.png](../images/azure-new-pipeline.png)


2. Set `Azure Repos Git` as your code source:

   ![azure-set-code-source.png.png](../images/azure-set-code-source.png)


3. Select the repository you'd like Frogbot to scan.

   ![azure-select-repo-to-test.png](../images/azure-select-repo-to-test.png)


4. Select `Starter Pipeline` and name it `frogbot-scan-pr.yml`. Use the content of the below yaml for the pipeline.

<details>
  <summary>Template for frogbot-scan-pr.yml</summary>

```yml
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

</details>

5. Select `Starter Pipeline` and name it `frogbot-scan-and-fix.yml`. Use the content of the below yaml for the pipeline.

<details>
  <summary>Template for frogbot-scan-and-fix.yml</summary>

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

</details>

6. Make sure you have the connection details of your JFrog environment. In the pipeline page save the JFrog connection details as variables with the following names - JF_URL, JF_USER, and JF_PASSWORD.

   To set variables in the pipeline edit page, click on `Variables` button:

   ![variables_button.png](../images/azure-variables-button.png)

   Set `New variable`:

   ![img_1.png](../images/azure-new-variable.png)

> **_NOTE:_** You can also use **JF_XRAY_URL** and **JF_ARTIFACTORY_URL** instead of **JF_URL**, and **JF_ACCESS_TOKEN**
> instead of **JF_USER** and **JF_PASSWORD**.

7. Set the other mandatory `Variables` according to the chosen pipeline template.
