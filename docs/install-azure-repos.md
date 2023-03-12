[Go back to the main documentation page](https://github.com/jfrog/frogbot)

# Installing Frogbot on Azure Repos repositories

| Important: Using Frogbot with Azure DevOps isn't recommended for open source projects. Read more about it in the [Security note for pull requests scanning](../README.md#-security-note-for-pull-requests-scanning) section. |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |

To install Frogbot on Azure Repos repositories, follow these steps.

1. Make sure you have the connection details of your JFrog environment.

2. Decide which repository branches you'd like to scan.

3. Go to your Azure Pipelines project, and add a new pipeline.

   ![azure-new-pipeline.png](../images/azure-new-pipeline.png)

4. Set `Azure Repos Git` as your code source.

   ![azure-set-code-source.png.png](../images/azure-set-code-source.png)

5. Select your `Frogbot Management Repository`.

   ![azure-select-repo-to-test.png](../images/azure-select-repo-to-test.png)

6. Select `Starter Pipeline` and name it `frogbot`.

   ![azure-starter-pipeline.png](../images/azure-starter-pipeline.png)

   7. Use the content of the below template for the pipeline. Edit the remaining mandatory `Variables`.

      <details>
        <summary>Template</summary>

      ```yml
       schedules:
            # Every 5 minutes
            - cron: "*/5 * * * *"
              branches: 
                include: 
                  - "*"
       pool:
            vmImage: ubuntu-latest
       jobs:
          - job:
            displayName: "Frogbot Scan Pull Requests"
            steps:
            - task: CmdLine@2
              displayName: 'Download and Run Frogbot'
              env:
                 # Predefined Azure Pipelines variables. There's no need to modify them.
                 JF_GIT_PROJECT: $(System.TeamProject)
                 JF_GIT_API_ENDPOINT: $(System.CollectionUri)
                 JF_GIT_PROVIDER: 'azureRepos'
      
                 # [Mandatory]
                 # Azure Repos personal access token with Code -> Read & Write permissions
                 JF_GIT_TOKEN: $(FROGBOT_GIT_TOKEN)
   
                 # [Mandatory]
                 # JFrog platform URL (This functionality requires version 3.29.0 or above of Xray)
                 JF_URL: $(JF_URL)
   
                 # [Mandatory if JF_USER and JF_PASSWORD are not provided]
                 # JFrog access token with 'read' permissions for Xray
                 JF_ACCESS_TOKEN: $(JF_ACCESS_TOKEN)
   
                 # [Mandatory if JF_ACCESS_TOKEN is not provided]
                 # JFrog user and password with 'read' permissions for Xray
                 # JF_USER: $(JF_USER)
                 # JF_PASSWORD: $(JF_PASSWORD)
   
                 # [Mandatory]
                 # The name of the organization that owns this project
                 JF_GIT_OWNER: ""
   
                 # [Optional]
                 # If the machine that runs Frogbot has no access to the internat, set the name of a remote repository 
                 # in Artifactory, which proxies https://releases.jfrog.io/artifactory
                 # The 'frogbot' executable and other tools it needs will be downloaded through this repository.
                 # JF_RELEASES_REPO: ""
   
   
   
   
                 ##########################################################################
                 ##   If your project uses a 'frogbot-config.yml' file, you can define   ##
                 ##   the following variables inside the file, instead of here.          ##
                 ##########################################################################

                 # [Mandatory if the two conditions below are met]
                 # 1. The project uses npm, yarn 2, NuGet or .NET to download its dependencies
                 # 2. The `installCommand` variable isn't set in your frogbot-config.yml file.
                 #
                 # The command that installs the project dependencies (e.g "npm i", "nuget restore" or "dotnet restore")
                 JF_INSTALL_DEPS_CMD: ""

                 # [Optional, default: "."]
                 # Relative path to the root of the project in the Git repository
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

                 # [Optional]
                 # Frogbot will download the project dependencies if they're not cached locally. To download the
                 # dependencies from a virtual repository in Artifactory, set the name of of the repository. There's no
                 # need to set this value, if it is set in the frogbot-config.yml file.
                 # JF_DEPS_REPO: ""   
              inputs:
                script: |
                  curl -fLg "https://releases.jfrog.io/artifactory/frogbot/v2/[RELEASE]/getFrogbot.sh" | sh
                  ./frogbot scan-pull-requests
                  ./frogbot scan-and-fix-repos
      ```

      </details>

8. For the pipeline you created, save the JFrog connection details as variables with the following names - JF_URL, JF_USER, and JF_PASSWORD.

   > **_NOTE:_** You can also use **JF_XRAY_URL** and **JF_ARTIFACTORY_URL** instead of **JF_URL**, and **JF_ACCESS_TOKEN**
   > instead of **JF_USER** and **JF_PASSWORD**.

   To set the `Variables` in the pipeline edit page, click on the `Variables` button and set the `Variables`.

   ![variables_button.png](../images/azure-variables-button.png)

   ![img_1.png](../images/azure-new-variable.png)
