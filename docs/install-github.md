[Go back to the main documentation page](../README.md)

# Frogbot Configuration file

Frogbot requires a [frogbot-config](templates/.jfrog/frogbot/frogbot-config.yml) file to run it's tasks. This file resides inside a `Frogbot Management` repository that is also need to be set. Please read the [frogbot configuration file documentation](./frogbot-config.md) if you haven't configured your `Frogbot Management` repository yet.

# Installing Frogbot on GitHub repositories

## Installation Options

<details>
   <summary>Install Frogbot Using GitHub Actions</summary>

### Run Frogbot on existing repository

To install Frogbot on GitHub repositories using GitHub Actions on existing repository:

1. Set up the `Frogbot Management` for existing code repository as described in [frogbot configuration file documentation](./frogbot-config.md).
2. Make sure you have the connection details of your JFrog environment.
3. Go to your GitHub repository settings page and save the JFrog connection details as repository secrets with the following names - **JF_URL**, **JF_USER**, and **JF_PASSWORD**

> **_NOTE:_** You can also use **JF_XRAY_URL** and **JF_ARTIFACTORY_URL** instead of **JF_URL**, and **JF_ACCESS_TOKEN**
> instead of **JF_USER** and **JF_PASSWORD**

![](../images/github-repository-secrets.png)

4. Check the Allow GitHub Actions to create and approve pull requests check box.

   ![](../images/github-pr-permissions.png)

5. Create a new [GitHub environment](https://docs.github.com/en/actions/deployment/targeting-different-environments/using-environments-for-deployment#creating-an-environment)
   called **frogbot** and add people or public teams as reviewers. The chosen reviewers can trigger Frogbot scans on pull requests.

   ![](../images/github-environment.png)

6. Use our [GitHub Actions templates](templates/github-actions/README.md#frogbot-gitHub-actions-templates) to add Frogbot workflows to your project.
7. Push the workflow files to the **.github/workflows** directory in the root of your GitHub repository.

### Run Frogbot on a Central Frogbot Management repository

To install Frogbot on GitHub repositories using GitHub Actions on a Central Frogbot Management repository:

1. Set up the central `Frogbot Management` repository described in [frogbot configuration file documentation](./frogbot-config.md).
2. Make sure you have the connection details of your JFrog environment.
3. Go to your GitHub repository settings page and save the JFrog connection details as repository secrets with the following names - **JF_URL**, **JF_USER**, and **JF_PASSWORD**

> **_NOTE:_** You can also use **JF_XRAY_URL** and **JF_ARTIFACTORY_URL** instead of **JF_URL**, and **JF_ACCESS_TOKEN**
> instead of **JF_USER** and **JF_PASSWORD**

![](../images/github-repository-secrets.png)

3. Create a GitHub Personal Access Token with read and write permissions to actions, code scanning alerts, commit statuses, pull requests, security events, and workflows. For more information please refer to [GitHub Documentation](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/creating-a-personal-access-token).
4. Set the GitHub Personal Access Token name to `GH_PAT`. This access token will be used as the git token with our workflows.
5. Use our [GitHub Actions templates](templates/github-actions/README.md#frogbot-gitHub-actions-templates) to add Frogbot workflows to your project.
6. Push the workflow files to the **.github/workflows** directory in the root of the `JFrog` repository.

</details>

<details>
   <summary>Install Frogbot Using JFrog Pipelines</summary>

### Run Frogbot on existing repository

1. Set up the `Frogbot Management` for existing code repository as described in [frogbot configuration file documentation](./frogbot-config.md).
2. Make sure you have the connection details of your JFrog environment.
3. Save the JFrog connection details as a [JFrog Platform Access Token Integration](https://www.jfrog.com/confluence/display/JFROG/JFrog+Platform+Access+Token+Integration)
   named **jfrogPlatform**.
4. Save your GitHub access token as a [Generic Integration](https://www.jfrog.com/confluence/display/JFROG/Generic+Integration) named **github** with the token as the key and the GitHub access token as the value.
5. Set the `.jfrog-pipelines` directory in the root of your GitHub repository.
6. Create a Pipelines job with the below pipelines.yml content.
   <details>
    <summary>Template for scan-pull-requests</summary>

   ```yml
   resources:
     - name: cron_trigger
       type: CronTrigger
       configuration:
         interval: '*/5 * * * *'     # Every 5 minutes
   pipelines:
     - name: Frogbot
       steps:
         - name: Frogbot_Scan
           type: Bash # For Windows runner: PowerShell
           configuration:
             integrations:
               - name: jfrogPlatform
               - name: github
             inputResources:
               - name: cron_trigger
             environmentVariables:
               # [Mandatory]
               # JFrog platform URL
               JF_URL: $int_jfrogPlatform_url
               # [Mandatory if JF_USER and JF_PASSWORD are not provided]
               # JFrog access token with 'read' permissions for Xray
               JF_ACCESS_TOKEN: $int_jfrogPlatform_accessToken
               # [Mandatory]
               # GitHub accesses token with the following permissions:
               # Read and Write access to code, pull requests, security events, and workflows
               JF_GIT_TOKEN: $int_github_token
               JF_GIT_PROVIDER: "github"
               # [Mandatory]
               # API endpoint to GitHub Enterprise server
               JF_GIT_API_ENDPOINT: $int_github_url
               # [Mandatory]
               # GitHub organization namespace
               JF_GIT_OWNER: ""
           execution:
             onExecute:
               - curl -fLg "https://releases.jfrog.io/artifactory/frogbot/v2/[RELEASE]/getFrogbot.sh" | sh
               - ./frogbot scan-pull-requests
               # For Windows runner:
               # - iwr https://releases.jfrog.io/artifactory/frogbot/v2/[RELEASE]/frogbot-windows-amd64/frogbot.exe -OutFile .\frogbot.exe
               # - .\frogbot.exe scan-pull-requests
   ```

   </details>

7. In the **pipelines.yml**, make sure to set values for all the mandatory variables.
8. In the **pipelines.yml**, if you're using a Windows agent, modify the code inside the onExecute sections as described on the yaml comments.

### Run Frogbot on Central Frogbot Management repository

1. Set up the `Frogbot Management` for `Central Management Repository` as described in [frogbot configuration file documentation](./frogbot-config.md).
2. Make sure you have the connection details of your JFrog environment.
3. Save the JFrog connection details as a [JFrog Platform Access Token Integration](https://www.jfrog.com/confluence/display/JFROG/JFrog+Platform+Access+Token+Integration)
   named **jfrogPlatform**.
4. Save your GitHub access token as a [Generic Integration](https://www.jfrog.com/confluence/display/JFROG/Generic+Integration) named **github** with the token as the key and the GitHub access token as the value.
5. Set the `.jfrog-pipelines` directory in the root of your `JFrog` management repository.
6. Create a Pipelines job with the below pipelines.yml content.
   <details>
    <summary>Template for scan-pull-requests</summary>

   ```yml
   resources:
     - name: cron_trigger
       type: CronTrigger
       configuration:
         interval: '*/5 * * * *'     # Every 5 minutes
   pipelines:
     - name: Frogbot
       steps:
         - name: Frogbot_Scan
           type: Bash # For Windows runner: PowerShell
           configuration:
             integrations:
               - name: jfrogPlatform
               - name: github
             inputResources:
               - name: cron_trigger
             environmentVariables:
               # [Mandatory]
               # JFrog platform URL
               JF_URL: $int_jfrogPlatform_url
               # [Mandatory if JF_USER and JF_PASSWORD are not provided]
               # JFrog access token with 'read' permissions for Xray
               JF_ACCESS_TOKEN: $int_jfrogPlatform_accessToken
               # [Mandatory]
               # GitHub accesses token with the following permissions:
               # Read and Write access to code, pull requests, security events, and workflows
               JF_GIT_TOKEN: $int_github_token
               JF_GIT_PROVIDER: "github"
               # [Mandatory]
               # API endpoint to GitHub Enterprise server
               JF_GIT_API_ENDPOINT: $int_github_url
               # [Mandatory]
               # GitHub organization namespace
               JF_GIT_OWNER: ""
           execution:
             onExecute:
               - curl -fLg "https://releases.jfrog.io/artifactory/frogbot/v2/[RELEASE]/getFrogbot.sh" | sh
               - ./frogbot scan-pull-requests
               # For Windows runner:
               # - iwr https://releases.jfrog.io/artifactory/frogbot/v2/[RELEASE]/frogbot-windows-amd64/frogbot.exe -OutFile .\frogbot.exe
               # - .\frogbot.exe scan-pull-requests
   ```

   </details>

7. In the **pipelines.yml**, make sure to set values for all the mandatory variables.
8. In the **pipelines.yml**, if you're using a Windows agent, modify the code inside the onExecute sections as described on the yaml comments.

**Important**

- For npm, yarn 2, NuGet or .NET: Make sure to set inside the frogbot-config.yml the command in a way that it downloads your project dependencies as the value of the **installCommandName** and **installCommandArgs** variables. For example, `npm i`
  or `nuget restore`
- Make sure that all necessary build tool that are used to build the scanned project are installed on the Pipelines agent.

</details>

<details>
   <summary>Install Frogbot Using Jenkins</summary>

### Run Frogbot on existing repository

1. Set up the `Frogbot Management` for existing code repository as described in [frogbot configuration file documentation](./frogbot-config.md).
2. Make sure you have the connection details of your JFrog environment.
3. Save the JFrog connection details as Credentials in Jenkins with the following Credential IDs: **JF_URL**,
   **JF_USER** and **JF_PASSWORD** (You can also use **JF_XRAY_URL** and **JF_ARTIFACTORY_URL** instead of **JF_URL**
   and **JF_ACCESS_TOKEN** instead of **JF_USER** and **JF_PASSWORD**).
4. Save your GitHub access token as a Credential in Jenkins with the GITHUB_TOKEN Credential ID.
5. Create a Jenkinsfile with the below content under the root of your GitHub repository.
   <details>
      <summary>Template for scan-pull-requests</summary>

      ```groovy
      // Run the job every 5 minutes 
      CRON_SETTINGS = '''*/5 * * * *'''
      pipeline {
          agent any
          triggers {
              cron(CRON_SETTINGS)
          }
          environment {
              // [Mandatory only for projects which use npm, yarn 2, NuGet and .NET to download their dependencies]
              // The command that installs the project dependencies (e.g "npm i", "nuget restore" or "dotnet restore")
              JF_INSTALL_DEPS_CMD = ""
              // [Mandatory]
              // JFrog platform URL (This functionality requires version 3.29.0 or above of Xray)
              JF_URL = credentials("JF_URL")
              // [Mandatory if JF_ACCESS_TOKEN is not provided]
              // JFrog user and password with 'read' permissions for Xray
              JF_USER = credentials("JF_USER")
              JF_PASSWORD = credentials("JF_PASSWORD")
              // [Mandatory]
              // GitHub enterprise server accesses token with the following permissions:
              // Read and Write access to code, pull requests, security events, and workflows
              JF_GIT_TOKEN = credentials("GITHUB_TOKEN")
              JF_GIT_PROVIDER = "github"
              // [Mandatory]
              // GitHub enterprise server organization namespace
              JF_GIT_OWNER = ""
              // [Mandatory]
              // API endpoint to GitHub enterprise server
              JF_GIT_API_ENDPOINT = ""
              // Uncomment the below options if you'd like to use them.
              // [Mandatory if JF_USER and JF_PASSWORD are not provided]
              // JFrog access token with 'read' permissions for Xray
              // JF_ACCESS_TOKEN= credentials("JF_ACCESS_TOKEN")
          }
          stages {
              stage('Download Frogbot') {
                  steps {
                      // For Linux / MacOS runner:
                      sh """ curl -fLg "https://releases.jfrog.io/artifactory/frogbot/v2/[RELEASE]/getFrogbot.sh" | sh"""
                      // For Windows runner:
                      // powershell """iwr https://releases.jfrog.io/artifactory/frogbot/v2/[RELEASE]/frogbot-windows-amd64/frogbot.exe -OutFile .\frogbot.exe"""
                  }
              }
              stage('Scan Pull Requests') {
                  steps {
                      sh "./frogbot scan-pull-requests"
                      // For Windows runner:
                      // powershell """.\frogbot.exe scan-pull-requests"""
                  }
              }
          }
      }
      ```
   </details>
6. In the Jenkinsfile, set the values of all the mandatory variables.
7. In the Jenkinsfile, modify the code inside the `Download Frogbot` and `Scan Pull Requests` according to the Jenkins agent operating system.
8. Create a job in Jenkins pointing to the Jenkinsfile in your GitHub repository.

### Run Frogbot on a Central Frogbot Management repository

1. Set up the `Frogbot Management` for `Central Management Repository` as described in [frogbot configuration file documentation](./frogbot-config.md).
2. Make sure you have the connection details of your JFrog environment.
3. Save the JFrog connection details as Credentials in Jenkins with the following Credential IDs: **JF_URL**,
   **JF_USER** and **JF_PASSWORD** (You can also use **JF_XRAY_URL** and **JF_ARTIFACTORY_URL** instead of **JF_URL**
   and **JF_ACCESS_TOKEN** instead of **JF_USER** and **JF_PASSWORD**).
4. Save your GitHub access token as a Credential in Jenkins with the GITHUB_TOKEN Credential ID.
5. Create a Jenkinsfile with the below content under the root of your `JFrog` management repository.

   <details>
      <summary>Template for scan-pull-requests</summary>

      ```groovy
      // Run the job every 5 minutes 
      CRON_SETTINGS = '''*/5 * * * *'''
      pipeline {
          agent any
          triggers {
              cron(CRON_SETTINGS)
          }
          environment {
              // [Mandatory only for projects which use npm, yarn 2, NuGet and .NET to download their dependencies]
              // The command that installs the project dependencies (e.g "npm i", "nuget restore" or "dotnet restore")
              JF_INSTALL_DEPS_CMD = ""
              // [Mandatory]
              // JFrog platform URL (This functionality requires version 3.29.0 or above of Xray)
              JF_URL = credentials("JF_URL")
              // [Mandatory if JF_ACCESS_TOKEN is not provided]
              // JFrog user and password with 'read' permissions for Xray
              JF_USER = credentials("JF_USER")
              JF_PASSWORD = credentials("JF_PASSWORD")
              // [Mandatory]
              // GitHub enterprise server accesses token with the following permissions:
              // Read and Write access to code, pull requests, security events, and workflows
              JF_GIT_TOKEN = credentials("GITHUB_TOKEN")
              JF_GIT_PROVIDER = "github"
              // [Mandatory]
              // GitHub enterprise server organization namespace
              JF_GIT_OWNER = ""
              // [Mandatory]
              // API endpoint to GitHub enterprise server
              JF_GIT_API_ENDPOINT = ""
              // Uncomment the below options if you'd like to use them.
              // [Mandatory if JF_USER and JF_PASSWORD are not provided]
              // JFrog access token with 'read' permissions for Xray
              // JF_ACCESS_TOKEN= credentials("JF_ACCESS_TOKEN")
          }
          stages {
              stage('Download Frogbot') {
                  steps {
                      // For Linux / MacOS runner:
                      sh """ curl -fLg "https://releases.jfrog.io/artifactory/frogbot/v2/[RELEASE]/getFrogbot.sh" | sh"""
                      // For Windows runner:
                      // powershell """iwr https://releases.jfrog.io/artifactory/frogbot/v2/[RELEASE]/frogbot-windows-amd64/frogbot.exe -OutFile .\frogbot.exe"""
                  }
              }
              stage('Scan Pull Requests') {
                  steps {
                      sh "./frogbot scan-pull-requests"
                      // For Windows runner:
                      // powershell """.\frogbot.exe scan-pull-requests"""
                  }
              }
          }
      }
      ```
   </details>
6. In the Jenkinsfile, set the values of all the mandatory variables.
7. In the Jenkinsfile, modify the code inside the `Download Frogbot` and `Scan Pull Requests` according to the Jenkins agent operating system.
8. Create a job in Jenkins pointing to the Jenkinsfile in your `JFrog` management repository.

**Important**

- For npm, yarn 2, NuGet or .NET: Make sure to set inside the frogbot-config.yml the command in a way that it downloads your project dependencies as the value of the **installCommandName** and **installCommandArgs** variables. For example, `npm i`
  or `nuget restore`
- Make sure that either **JF_USER** and **JF_PASSWORD** or **JF_ACCESS_TOKEN** are set in the Jenkinsfile, but not both.
- Make sure that all necessary build tool that are used to build the scanned project are installed on the Jenkins agent.

</details>

