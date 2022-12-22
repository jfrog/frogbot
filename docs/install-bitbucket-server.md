[Go back to the main documentation page](../README.md)

# Frogbot Configuration file

Frogbot requires a [frogbot-config](templates/.jfrog/frogbot/frogbot-config.yml) file to run it's tasks. This file resides inside a `Frogbot Management` repository that is also need to be set. Please read the [frogbot configuration file documentation](./frogbot-config.md) if you haven't configured your `Frogbot Management` repository yet.

# Installing Frogbot on Bitbucket Server repositories

Frogbot is installed on Bitbucket Server repositories using JFrog Pipelines or Jenkins.

## Using JFrog Pipelines

### Run Frogbot on existing repository

To install Frogbot using JFrog Pipelines:

1. Set up the `Frogbot Management` for existing code repository as described in [frogbot configuration file documentation](./frogbot-config.md).
2. Make sure you have the connection details of your JFrog environment.
3. Save the JFrog connection details as a [JFrog Platform Access Token Integration](https://www.jfrog.com/confluence/display/JFROG/JFrog+Platform+Access+Token+Integration)
   named **jfrogPlatform**.
4. Save your Bitbucket access token as a [Generic Integration](https://www.jfrog.com/confluence/display/JFROG/Generic+Integration) named **bitbucket** with the token as the key and the Bitbucket access token as the value.
5. Set the `.jfrog-pipelines` directory in the root of your BitBucket server repository.
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
                - name: bitbucket
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
                # Bitbucket accesses token with the following permissions 
                JF_GIT_TOKEN: $int_bitbucket_token
                JF_GIT_PROVIDER: "bitbucketServer"
    
                # [Mandatory]
                # API endpoint to Bitbucket server
                JF_GIT_API_ENDPOINT: $int_bitbucket_url
    
                # [Mandatory]
                # Bitbucket project namespace
                JF_GIT_OWNER: ""
    
                # [Mandatory]
                # Bitbucket repository name
                JF_GIT_REPO: ""
    
                # Uncomment the below options if you'd like to use them.
                # NOTE: The below options are irrelevant if you are using a config file, and should be configured there.
    
                # [Mandatory only for projects which use npm, yarn 2, NuGet and .NET to download their dependencies]
                # The command that installs the project dependencies (e.g "npm i", "nuget restore" or "dotnet restore")
                # JF_INSTALL_DEPS_CMD: ""
    
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
    
                # [Optional, default: "TRUE"]
                # Use Gradle Wrapper (gradlew/gradlew.bat) to run Gradle
                # JF_USE_WRAPPER: "TRUE"
                
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
4. Save your Bitbucket access token as a [Generic Integration](https://www.jfrog.com/confluence/display/JFROG/Generic+Integration) named **bitbucket** with the token as the key and the Bitbucket access token as the value.
5. Set the `.jfrog-pipelines` directory in the root of your `Frogbot Management` repository.
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
                - name: bitbucket
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
                # Bitbucket accesses token with the following permissions 
                JF_GIT_TOKEN: $int_bitbucket_token
                JF_GIT_PROVIDER: "bitbucketServer"
    
                # [Mandatory]
                # API endpoint to Bitbucket server
                JF_GIT_API_ENDPOINT: $int_bitbucket_url
    
                # [Mandatory]
                # Bitbucket project namespace
                JF_GIT_OWNER: ""
    
                # [Mandatory]
                # Bitbucket repository name
                JF_GIT_REPO: ""
    
                # Uncomment the below options if you'd like to use them.
                # NOTE: The below options are irrelevant if you are using a config file, and should be configured there.
    
                # [Mandatory only for projects which use npm, yarn 2, NuGet and .NET to download their dependencies]
                # The command that installs the project dependencies (e.g "npm i", "nuget restore" or "dotnet restore")
                # JF_INSTALL_DEPS_CMD: ""
    
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
    
                # [Optional, default: "TRUE"]
                # Use Gradle Wrapper (gradlew/gradlew.bat) to run Gradle
                # JF_USE_WRAPPER: "TRUE"
                
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

## Using Jenkins

### Run Frogbot on existing repository

1. Set up the `Frogbot Management` for existing code repository as described in [frogbot configuration file documentation](./frogbot-config.md).
2. Make sure you have the connection details of your JFrog environment.
3. Save the JFrog connection details as Credentials in Jenkins with the following Credential IDs: **JF_URL**, **
   JF_USER** and **JF_PASSWORD** (You can also use **JF_XRAY_URL** and **JF_ARTIFACTORY_URL** instead of  **JF_URL**
   and **JF_ACCESS_TOKEN** instead of **JF_USER** and **JF_PASSWORD**).
4. Save your Bitbucket access token as a Credential in Jenkins with the BITBUCKET_TOKEN Credential ID.
5. Create a Jenkinsfile with the below content under the root of your BitBucket server repository.

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
            
            // [Mandatory]
            // JFrog platform URL (This functionality requires version 3.29.0 or above of Xray)
            JF_URL= credentials("JF_URL")
    
            // [Mandatory if JF_ACCESS_TOKEN is not provided]
            // JFrog user and password with 'read' permissions for Xray
            JF_USER= credentials("JF_USER")
            JF_PASSWORD= credentials("JF_PASSWORD")
    
            // [Mandatory]
            // Bitbucket accesses token with the following permissions 
            JF_GIT_TOKEN= credentials("BITBUCKET_TOKEN")
            JF_GIT_PROVIDER= "bitbucketServer"
    
            // [Mandatory]
            // Bitbucket project namespace
            JF_GIT_OWNER= ""
    
            // [Mandatory]
            // Bitbucket repository name
            JF_GIT_REPO= ""
    
            // [Mandatory]
            // API endpoint to Bitbucket server
            JF_GIT_API_ENDPOINT= ""
    
            // Uncomment the below options if you'd like to use them.
            // NOTE: The below options are irrelevant if you are using a config file, and should be configured there.
    
            // [Mandatory only for projects which use npm, yarn 2, NuGet and .NET to download their dependencies]
            // The command that installs the project dependencies (e.g "npm i", "nuget restore" or "dotnet restore")
            // JF_INSTALL_DEPS_CMD= ""
            
            // [Mandatory if JF_USER and JF_PASSWORD are not provided]
            // JFrog access token with 'read' permissions for Xray
            // JF_ACCESS_TOKEN= credentials("JF_ACCESS_TOKEN")
    
            // [Optional, default: "."]
            // Relative path to the project in the git repository
            // JF_WORKING_DIR= path/to/project/dir
    
            // [Optional]
            // Xray Watches. Learn more about them here: https://www.jfrog.com/confluence/display/JFROG/Configuring+Xray+Watches
            // JF_WATCHES= <watch-1>,<watch-2>...<watch-n>
    
            // [Optional]
            // JFrog project. Learn more about it here: https://www.jfrog.com/confluence/display/JFROG/Projects
            // JF_PROJECT= <project-key>
    
            // [Optional, default: "FALSE"]
            // Displays all existing vulnerabilities, including the ones that were added by the pull request.
            // JF_INCLUDE_ALL_VULNERABILITIES= "TRUE"
    
            // [Optional, default: "TRUE"]
            // Fails the Frogbot task if any security issue is found.
            // JF_FAIL= "FALSE"
    
            // [Optional, default: "TRUE"]
            // Use Gradle Wrapper (gradlew/gradlew.bat) to run Gradle
            // JF_USE_WRAPPER: "TRUE"
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
8. Create a Pipeline job in Jenkins pointing to the Jenkinsfile in the BitBucket server repository.

### Run Frogbot on a Central Frogbot Management repository

1. Set up the `Frogbot Management` for `Central Management Repository` as described in [frogbot configuration file documentation](./frogbot-config.md).
2. Make sure you have the connection details of your JFrog environment.
3. Save the JFrog connection details as Credentials in Jenkins with the following Credential IDs: **JF_URL**, **
   JF_USER** and **JF_PASSWORD** (You can also use **JF_XRAY_URL** and **JF_ARTIFACTORY_URL** instead of  **JF_URL**
   and **JF_ACCESS_TOKEN** instead of **JF_USER** and **JF_PASSWORD**).
4. Save your Bitbucket access token as a Credential in Jenkins with the BITBUCKET_TOKEN Credential ID.
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
            
            // [Mandatory]
            // JFrog platform URL (This functionality requires version 3.29.0 or above of Xray)
            JF_URL= credentials("JF_URL")
    
            // [Mandatory if JF_ACCESS_TOKEN is not provided]
            // JFrog user and password with 'read' permissions for Xray
            JF_USER= credentials("JF_USER")
            JF_PASSWORD= credentials("JF_PASSWORD")
    
            // [Mandatory]
            // Bitbucket accesses token with the following permissions 
            JF_GIT_TOKEN= credentials("BITBUCKET_TOKEN")
            JF_GIT_PROVIDER= "bitbucketServer"
    
            // [Mandatory]
            // Bitbucket project namespace
            JF_GIT_OWNER= ""
    
            // [Mandatory]
            // Bitbucket repository name
            JF_GIT_REPO= ""
    
            // [Mandatory]
            // API endpoint to Bitbucket server
            JF_GIT_API_ENDPOINT= ""
    
            // Uncomment the below options if you'd like to use them.
            // NOTE: The below options are irrelevant if you are using a config file, and should be configured there.
    
            // [Mandatory only for projects which use npm, yarn 2, NuGet and .NET to download their dependencies]
            // The command that installs the project dependencies (e.g "npm i", "nuget restore" or "dotnet restore")
            // JF_INSTALL_DEPS_CMD= ""
            
            // [Mandatory if JF_USER and JF_PASSWORD are not provided]
            // JFrog access token with 'read' permissions for Xray
            // JF_ACCESS_TOKEN= credentials("JF_ACCESS_TOKEN")
    
            // [Optional, default: "."]
            // Relative path to the project in the git repository
            // JF_WORKING_DIR= path/to/project/dir
    
            // [Optional]
            // Xray Watches. Learn more about them here: https://www.jfrog.com/confluence/display/JFROG/Configuring+Xray+Watches
            // JF_WATCHES= <watch-1>,<watch-2>...<watch-n>
    
            // [Optional]
            // JFrog project. Learn more about it here: https://www.jfrog.com/confluence/display/JFROG/Projects
            // JF_PROJECT= <project-key>
    
            // [Optional, default: "FALSE"]
            // Displays all existing vulnerabilities, including the ones that were added by the pull request.
            // JF_INCLUDE_ALL_VULNERABILITIES= "TRUE"
    
            // [Optional, default: "TRUE"]
            // Fails the Frogbot task if any security issue is found.
            // JF_FAIL= "FALSE"
    
            // [Optional, default: "TRUE"]
            // Use Gradle Wrapper (gradlew/gradlew.bat) to run Gradle
            // JF_USE_WRAPPER: "TRUE"
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
8. Create a Pipeline job in Jenkins pointing to the Jenkinsfile in the `JFrog` mangement repository.

**Important**

- For npm, yarn 2, NuGet or .NET: Make sure to set inside the frogbot-config.yml the command in a way that it downloads your project dependencies as the value of the **installCommandName** and **installCommandArgs** variables. For example, `npm i`
  or `nuget restore`
- Make sure that either **JF_USER** and **JF_PASSWORD** or **JF_ACCESS_TOKEN** are set in the Jenkinsfile, but not both.
- Make sure that all necessary build tool that are used to build the scanned project are installed on the Jenkins agent.

