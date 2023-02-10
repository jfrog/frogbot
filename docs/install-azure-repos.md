[Go back to the main documentation page](../README.md)

# Installing Frogbot on Azure Repos repositories

| Important: Using Frogbot with Azure DevOps isn't recommended for open source projects. Read more about it in the [Security note for pull requests scanning](../README.md#-security-note-for-pull-requests-scanning) section. |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |

To install Frogbot on Azure Repos repositories, follow these steps.

1. Frogbot uses a [frogbot-config.yml](templates/.frogbot/frogbot-config.yml) file to run. [This](frogbot-config.md) article will guide you through the process of creating this file.

2. Make sure you have the connection details of your JFrog environment.

3. Decide which repository branches you'd like to scan.

4. Go to your Azure Pipelines project, and add a new pipeline.

   ![azure-new-pipeline.png](../images/azure-new-pipeline.png)

5. Set `Azure Repos Git` as your code source.

   ![azure-set-code-source.png.png](../images/azure-set-code-source.png)

6. Select your `Frogbot Management Repository`.

   ![azure-select-repo-to-test.png](../images/azure-select-repo-to-test.png)

7. Select `Starter Pipeline` and name it `frogbot`.

   ![azure-starter-pipeline.png](../images/azure-starter-pipeline.png)

8. Use the content of the below template for the pipeline. Edit the remaining mandatory `Variables`.

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
   
                    # Predefined Azure Pipelines variables. There's no need to set them.
                    JF_GIT_PROJECT: $(System.TeamProject)
                    JF_GIT_API_ENDPOINT: $(System.CollectionUri)
                    JF_GIT_PROVIDER: 'azureRepos'
    
                 inputs:
                   script: |
                     curl -fLg "https://releases.jfrog.io/artifactory/frogbot/v2/[RELEASE]/getFrogbot.sh" | sh
                     ./frogbot scan-pull-requests
                     ./frogbot scan-and-fix-repos
    ```

</details>

9. For the pipeline you created, save the JFrog connection details as variables with the following names - JF_URL, JF_USER, and JF_PASSWORD.

   > **_NOTE:_** You can also use **JF_XRAY_URL** and **JF_ARTIFACTORY_URL** instead of **JF_URL**, and **JF_ACCESS_TOKEN**
   > instead of **JF_USER** and **JF_PASSWORD**.

   To set the `Variables` in the pipeline edit page, click on the `Variables` button and set the `Variables`.

   ![variables_button.png](../images/azure-variables-button.png)

   ![img_1.png](../images/azure-new-variable.png)
