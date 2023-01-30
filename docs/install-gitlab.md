[Go back to the main documentation page](../README.md)
# Installing Frogbot on GitLab repositories
To install Frogbot on GitLab repositories using GitLab CI:

1. Make sure you have the connection details of your JFrog environment.
2. Go to your GitLab repository settings page and save the JFrog connection details as repository secrets with the following names - **JF_URL**, **JF_USER**, and **JF_PASSWORD** 
> **_NOTE:_** You can also use **JF_XRAY_URL** and **JF_ARTIFACTORY_URL** instead of **JF_URL**, and **JF_ACCESS_TOKEN** instead of **JF_USER** and **JF_PASSWORD**
3. Add a job named **frogbot-scan** to your **.gitlab-ci.yml** file in your GitLab repository using the code block below.

**Important**
- For npm, yarn 2, NuGet or .NET: Make sure to set the command in a way that it downloads your project dependencies as
  the value of the **JF_INSTALL_DEPS_CMD** variable. For example, `npm i` or `nuget restore`
- Make sure that either **JF_USER** and **JF_PASSWORD** or **JF_ACCESS_TOKEN** are set, **but not both**.

```yml
frogbot-scan:
  rules:
    - if: $CI_PIPELINE_SOURCE == 'merge_request_event'
      when: manual
      variables:
        FROGBOT_CMD: "scan-pull-request"
        JF_GIT_BASE_BRANCH: $CI_MERGE_REQUEST_TARGET_BRANCH_NAME
      # Creating fix pull requests will be triggered by any push to the default branch.
      # You can change it to any other branch you want, for example:
      # if: $CI_COMMIT_BRANCH == "dev"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
      variables:
        FROGBOT_CMD: "create-fix-pull-requests"
        JF_GIT_BASE_BRANCH: $CI_COMMIT_BRANCH
  variables:
    # [Mandatory only for projects which use npm, yarn 2, NuGet and .NET to download their dependencies]
    # The command that installs the project dependencies (e.g "npm i", "nuget restore" or "dotnet restore")
    JF_INSTALL_DEPS_CMD: ""

    # [Mandatory]
    # JFrog platform URL (This functionality requires version 3.29.0 or above of Xray)
    JF_URL: $JF_URL

    # [Mandatory if JF_USER and JF_PASSWORD are not provided]
    # JFrog access token with 'read' permissions for Xray
    JF_ACCESS_TOKEN: $JF_ACCESS_TOKEN

    # [Mandatory]
    # GitLab accesses token with the following permissions scopes: api, read_api, read_user, read_repository
    JF_GIT_TOKEN: $USER_TOKEN

    # Predefined GitLab variables. There's no need to set them.
    JF_GIT_PROVIDER: gitlab
    JF_GIT_OWNER: $CI_PROJECT_NAMESPACE
    JF_GIT_REPO: $CI_PROJECT_NAME
    JF_GIT_PULL_REQUEST_ID: $CI_MERGE_REQUEST_IID

    # Uncomment the below options if you'd like to use them.

    # [Mandatory if JF_ACCESS_TOKEN is not provided]
    # JFrog user and password with 'read' permissions for Xray
    # JF_USER: $JF_USER
    # JF_PASSWORD: $JF_PASSWORD

    # [Optional, default: https://gitlab.com]
    # API endpoint to GitLab
    # JF_GIT_API_ENDPOINT: https://gitlab.example.com

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
  script:
    # For Linux / MacOS runner:
    - curl -fLg "https://releases.jfrog.io/artifactory/frogbot/v2/[RELEASE]/getFrogbot.sh" | sh
    - ./frogbot ${FROGBOT_CMD}

    # For Windows runner:
    # iwr https://releases.jfrog.io/artifactory/frogbot/v2/[RELEASE]/frogbot-windows-amd64/frogbot.exe -OutFile .\frogbot.exe
    # .\frogbot.exe ${FROGBOT_CMD}
```