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
   * Create a **pipelines.yml** file using one of the available [templates](templates/jfrog-pipelines) and push the file into one of your Git repositories, under a directory named `.jfrog-pipelines`. 
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
   - Create a Jenkinsfile with the below template content, and push it to root of one of your Git repositories.
   - In the Jenkinsfile, set the values of all the mandatory variables.
   - In the Jenkinsfile, modify the code inside the `Download Frogbot` and `Scan Pull Requests` according to the Jenkins agent operating system.
   - Create a Pipeline job in Jenkins pointing to the Jenkinsfile in your Git repository.

      <details>
            <summary>Template</summary>

      ```groovy
      // Run the job once an hour 
      CRON_SETTINGS = '''* */1 * * *'''
      
      pipeline {
         agent any
      
         triggers {
            cron(CRON_SETTINGS)
         }
      
         environment {   
               // [Mandatory]
               // JFrog platform URL (This functionality requires version 3.29.0 or above of Xray)
               JF_URL= credentials("JF_URL")
               
               // [Mandatory if JF_USER and JF_PASSWORD are not provided]
               // JFrog access token with 'read' permissions for Xray
               JF_ACCESS_TOKEN= credentials("JF_ACCESS_TOKEN")
               
               // [Mandatory if JF_ACCESS_TOKEN is not provided]
               // JFrog user and password with 'read' permissions for Xray
               // JF_USER= credentials("JF_USER")
               // JF_PASSWORD= credentials("JF_PASSWORD")
               
               // [Mandatory]
               // Bitbucket access token with the write repository permissions 
               JF_GIT_TOKEN= credentials("FROGBOT_GIT_TOKEN")
               JF_GIT_PROVIDER= "bitbucketServer"
               
               // [Mandatory]
               // Username of the account associated with the token
               JF_GIT_USERNAME= ""
               
               // [Mandatory]
               // Bitbucket project namespace
               // Private projects should start with the prefix: "~"
               JF_GIT_OWNER= ""
               
               // [Mandatory]
               // API endpoint to Bitbucket server
               JF_GIT_API_ENDPOINT= ""
               
               // [Optional]
               // If the machine that runs Frogbot has no access to the internet, set the name of a remote repository 
               // in Artifactory, which proxies https://releases.jfrog.io
               // The 'frogbot' executable and other tools it needs will be downloaded through this repository.
               // JF_RELEASES_REPO= ""
               
               ///////////////////////////////////////////////////////////////////////////
               //   If your project uses a 'frogbot-config.yml' file, you should define //
               //   the following variables inside the file, instead of here.           //
               ///////////////////////////////////////////////////////////////////////////
   
               // [Mandatory]
               // The name of the repository
               JF_GIT_REPO= ""
    
               // [Mandatory]
               // The name of the branch on which Frogbot will perform the scan
               JF_GIT_BASE_BRANCH= ""
               
               // [Mandatory if the two conditions below are met]
               // 1. The project uses yarn 2, NuGet or .NET to download its dependencies
               // 2. The `installCommand` variable isn't set in your frogbot-config.yml file.
               //
               // The command that installs the project dependencies (e.g "nuget restore")
               JF_INSTALL_DEPS_CMD= ""
               
               // [Optional, default: "."]
               // Relative path to the root of the project in the Git repository
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
               // Relative path to a Pip requirements.txt file. If not set, the python project's dependencies are determined and scanned using the project setup.py file.
               // JF_REQUIREMENTS_FILE= ""
   
               // [Optional, Default: "TRUE"]
               // Use Gradle wrapper.
               // JF_USE_WRAPPER= "FALSE"
               
               // [Optional]
               // Frogbot will download the project dependencies if they're not cached locally. To download the
               // dependencies from a virtual repository in Artifactory, set the name of of the repository. There's no
               // need to set this value, if it is set in the frogbot-config.yml file.
               // JF_DEPS_REPO= ""

               // [Optional]
               // Template for the branch name generated by Frogbot when creating pull requests with fixes.
               // The template must include ${BRANCH_NAME_HASH}, to ensure that the generated branch name is unique.
               // The template can optionally include the ${IMPACTED_PACKAGE} and ${FIX_VERSION} variables.
               // JF_BRANCH_NAME_TEMPLATE= "frogbot-${IMPACTED_PACKAGE}-${BRANCH_NAME_HASH}"

               // [Optional]
               // Template for the commit message generated by Frogbot when creating pull requests with fixes
               // The template can optionally include the ${IMPACTED_PACKAGE} and ${FIX_VERSION} variables.
               // JF_COMMIT_MESSAGE_TEMPLATE= "Upgrade ${IMPACTED_PACKAGE} to ${FIX_VERSION}"

               // [Optional]
               // Template for the pull request title generated by Frogbot when creating pull requests with fixes.
               // The template can optionally include the ${IMPACTED_PACKAGE} and ${FIX_VERSION} variables.
               // JF_PULL_REQUEST_TITLE_TEMPLATE= "[🐸 Frogbot] Upgrade ${IMPACTED_PACKAGE} to ${FIX_VERSION}"

               // [Optional, Default: "FALSE"]
               // If TRUE, Frogbot creates a single pull request with all the fixes.
               // If FALSE, Frogbot creates a separate pull request for each fix.
               // JF_GIT_AGGREGATE_FIXES= "FALSE"

               // [Optional, Default: "FALSE"]
               // Handle vulnerabilities with fix versions only
               // JF_FIXABLE_ONLY= "TRUE"
      
               // [Optional]
               // Set the minimum severity for vulnerabilities that should be fixed and commented on in pull requests
               // The following values are accepted: Low, Medium, High or Critical
               // JF_MIN_SEVERITY= ""
     
               // [Optional, Default: eco-system+frogbot@jfrog.com]
               // Set the email of the commit author
               // JF_GIT_EMAIL_AUTHOR: ""
         }
         
         stages {
               stage('Download Frogbot') {
                  steps {
                        if (env.JF_RELEASES_REPO == "") {
                         // For Linux / MacOS runner:
                         sh """ curl -fLg "https://releases.jfrog.io/artifactory/frogbot/v2/[RELEASE]/getFrogbot.sh" | sh"""
                         // For Windows runner:
                         // powershell """iwr https://releases.jfrog.io/artifactory/frogbot/v2/[RELEASE]/frogbot-windows-amd64/frogbot.exe -OutFile .\frogbot.exe"""  
                     } else {
                         // For Linux / MacOS air gapped environments:
                         sh """ curl -fLg "${env.JF_URL}/artifactory/${env.JF_RELEASES_REPO}/artifactory/frogbot/v2/[RELEASE]/getFrogbot.sh" | sh"""
                         // For Windows air gapped environments:
                         // powershell """iwr ${env.JF_URL}/artifactory/${env.JF_RELEASES_REPO}/artifactory/frogbot/v2/[RELEASE]/frogbot-windows-amd64/frogbot.exe -OutFile .\frogbot.exe"""
                     }
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
   </details>
</details>

**Important**
- Make sure that either **JF_USER** and **JF_PASSWORD** or **JF_ACCESS_TOKEN** are set in the Jenkinsfile, but not both.
- Make sure that all the build tools that are used to build the project are installed on the Jenkins agent.

