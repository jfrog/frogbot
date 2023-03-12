[Go back to the main documentation page](https://github.com/jfrog/frogbot)

# Installing Frogbot on Bitbucket Server repositories

| Important: Using Frogbot on Bitbucket Server using JFrog Pipelines or Jenkins isn't recommended for open source projects. Read more about it in the [Security note for pull requests scanning](../README.md#-security-note-for-pull-requests-scanning) section. |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |

   <details>
      <summary>Install Frogbot Using JFrog Pipelines</summary>

   * Make sure you have the connection details of your JFrog environment. 
   * Save the JFrog connection details as a [JFrog Platform Access Token Integration](https://www.jfrog.com/confluence/display/JFROG/JFrog+Platform+Access+Token+Integration)
      named **jfrogPlatform**. 
   * Save your Bitbucket access token in a [Bitbucket Server Integration](https://www.jfrog.com/confluence/display/JFROG/Bitbucket+Server+Integration) named
      **gitIntegration**. 
   * Create a **pipelines.yml** file using one of the available [templates](templates/jfrog-pipelines) and push the file to your Frogbot Management Git repository under a directory named `.jfrog-pipelines`. 
   * In the **pipelines.yml**, make sure to set values for all the mandatory variables. 
   * In the **pipelines.yml**, if you're using a Windows agent, modify the code inside the onExecute sections as described in the template comments.

      **Important**
      - Make sure all the build tools that are used to build the project are installed on the build agent.
      </details>
      <details>
         <summary>Install Frogbot Using Jenkins</summary>
     
   - Make sure you have the connection details of your JFrog environment. 
   - Save the JFrog connection details as Credentials in Jenkins with the following Credential IDs: **JF_URL**,
      **JF_USER** and **JF_PASSWORD** (You can also use **JF_XRAY_URL** and **JF_ARTIFACTORY_URL** instead of  **JF_URL**
      and **JF_ACCESS_TOKEN** instead of **JF_USER** and **JF_PASSWORD**). 
   - Save your Bitbucket access token as a Credential in Jenkins with the `FROGBOT_GIT_TOKEN` Credential ID. 
   - Create a Jenkinsfile with the below content under the root of your **Frogbot Management Repository**.
   - In the Jenkinsfile, set the values of all the mandatory variables.
   - In the Jenkinsfile, modify the code inside the `Download Frogbot` and `Scan Pull Requests` according to the Jenkins agent operating system.
   - Create a Pipeline job in Jenkins pointing to the Jenkinsfile in your **Frogbot Management Repository**.

      ```groovy
      // Run the job every 5 minutes 
      CRON_SETTINGS = '''*/5 * * * *'''
   
      pipeline {
          agent any
   
          triggers {
              cron(CRON_SETTINGS)
          }
   
          environment {
              // [Mandatory if the two conditions below are met]
              // 1. The project uses npm, yarn 2, NuGet or .NET to download its dependencies
              // 2. The `installCommand` variable isn't set in your frogbot-config.yml file.
              // The command that installs the project dependencies (e.g "npm i", "nuget restore" or "dotnet restore")
              JF_INSTALL_DEPS_CMD= ""
   
              // [Mandatory]
              // JFrog platform URL (This functionality requires version 3.29.0 or above of Xray)
              JF_URL= credentials("JF_URL")
   
              // [Mandatory if JF_USER and JF_PASSWORD are not provided]
              // JFrog access token with 'read' permissions for Xray
              JF_ACCESS_TOKEN= credentials("JF_ACCESS_TOKEN")
   
              // [Mandatory]
              // Bitbucket access token with the write repository permissions 
              JF_GIT_TOKEN= credentials("FROGBOT_GIT_TOKEN")
              JF_GIT_PROVIDER= "bitbucketServer"
   
              // [Mandatory]
              // Username of the Bitbucket account
              JF_GIT_USERNAME= ""
   
              // [Mandatory]
              // Bitbucket project namespace
              JF_GIT_OWNER= ""
   
              // [Mandatory]
              // Bitbucket repository name
              JF_GIT_REPO= ""
     
              // [Mandatory]
              // Repository branch to scan
              JF_GIT_BASE_BRANCH= ""
     
              // [Mandatory]
              // API endpoint to Bitbucket server
              JF_GIT_API_ENDPOINT= ""
   
              // [Mandatory if JF_ACCESS_TOKEN is not provided]
              // JFrog user and password with 'read' permissions for Xray
              // JF_USER= credentials("JF_USER")
              // JF_PASSWORD= credentials("JF_PASSWORD")
     
              // [Optional]
              // If the machine that runs Frogbot has no access to the internet, set the name of a remote repository 
              // in Artifactory, which proxies https://releases.jfrog.io/artifactory
              // The 'frogbot' executable and other tools it needs will be downloaded through this repository.
              // JF_RELEASES_REPO= ""

              // [Optional]
              // Frogbot will download the project dependencies if they're not cached locally. To download the
              // dependencies from a virtual repository in Artifactory, set the name of the repository. There's no
              // need to set this value, if it is set in the frogbot-config.yml file.
              // JF_DEPS_REPO= ""
     
              // [Optional, default: "."]
              // Relative path to the project in the git repository
              // JF_WORKING_DIR= "path/to/project/dir"
    
              // [Optional]
              // Xray Watches. Learn more about them here: https://www.jfrog.com/confluence/display/JFROG/Configuring+Xray+Watches
              // JF_WATCHES= "<watch-1>,<watch-2>...<watch-n>"
   
              // [Optional, default: "FALSE"]
              // Displays all existing vulnerabilities, including the ones that were added by the pull request.
              // JF_INCLUDE_ALL_VULNERABILITIES= "TRUE"

              // [Optional, default: "TRUE"]
              // Fails the Frogbot task if any security issue is found.
              // JF_FAIL= "FALSE"
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
      
                  stage('Scan and Fix Repos') {
                     steps {
                         sh "./frogbot scan-and-fix-repos"
      
                         // For Windows runner:
                         // powershell """.\frogbot.exe scan-and-fix-repos"""
                     }
                 }
             }
         }
      ```
     
      **Important**

      - Make sure that either **JF_USER** and **JF_PASSWORD** or **JF_ACCESS_TOKEN** are set in the Jenkinsfile, but not both.
      - Make sure that all the build tools that are used to build the project are installed on the Jenkins agent.

      </details>

  </details>


