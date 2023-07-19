[Go back to the main documentation page](https://github.com/jfrog/frogbot)
# Installing Frogbot on GitLab repositories
To install Frogbot on GitLab repositories using GitLab CI:

1. Make sure you have the connection details of your JFrog environment.
2. Go to your GitLab repository settings page and save the JFrog connection details as repository secrets with the following names - **JF_URL**, **JF_USER**, and **JF_PASSWORD** 
> **_NOTE:_** You can also use **JF_XRAY_URL** and **JF_ARTIFACTORY_URL** instead of **JF_URL**, and **JF_ACCESS_TOKEN** instead of **JF_USER** and **JF_PASSWORD**
3. Add a job named **frogbot-scan** to your **.gitlab-ci.yml** file in your GitLab repository using the code block below.

**Important**
- Set the **JF_INSTALL_DEPS_CMD** variable below, or the **installCommand** property in your frogbot-config.yml file, if the project uses yarn 2, NuGet or .NET to download its dependencies
- Make sure that either **JF_USER** and **JF_PASSWORD** or **JF_ACCESS_TOKEN** are set, **but not both**.

```yml
frogbot-scan:
  rules:
    - if: $CI_PIPELINE_SOURCE == 'merge_request_event'
      when: manual
      variables:
        FROGBOT_CMD: "scan-pull-request"
        JF_GIT_BASE_BRANCH: $CI_MERGE_REQUEST_TARGET_BRANCH_NAME
      # Repository scanning is triggered by any push to the default branch.
      # If you'd like a different branch to be scanned, replace $CI_DEFAULT_BRANCH in the line below with the name of branch, wrapped with quotes (").
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH || $CI_PIPELINE_SOURCE == "schedule"
      variables:
        FROGBOT_CMD: "create-fix-pull-requests"
        JF_GIT_BASE_BRANCH: $CI_COMMIT_BRANCH
  variables:
    # [Mandatory]
    # JFrog platform URL (This functionality requires version 3.29.0 or above of Xray)
    JF_URL: $JF_URL

    # [Mandatory if JF_USER and JF_PASSWORD are not provided]
    # JFrog access token with 'read' permissions for Xray
    JF_ACCESS_TOKEN: $JF_ACCESS_TOKEN

    # [Mandatory if JF_ACCESS_TOKEN is not provided]
    # JFrog user and password with 'read' permissions for Xray
    # JF_USER: $JF_USER
    # JF_PASSWORD: $JF_PASSWORD

    # [Mandatory]
    # GitLab access token with the following permissions scopes: api, read_api, read_user, read_repository
    JF_GIT_TOKEN: $USER_TOKEN

    # Predefined GitLab variables. There's no need to set them.
    JF_GIT_PROVIDER: gitlab
    JF_GIT_OWNER: $CI_PROJECT_NAMESPACE
    JF_GIT_REPO: $CI_PROJECT_NAME
    JF_GIT_PULL_REQUEST_ID: $CI_MERGE_REQUEST_IID

    # [Optional, default: https://gitlab.com]
    # API endpoint to GitLab
    # JF_GIT_API_ENDPOINT: https://gitlab.example.com

    # [Optional]
    # If the machine that runs Frogbot has no access to the internet, set the name of a remote repository 
    # in Artifactory, which proxies https://releases.jfrog.io
    # The 'frogbot' executable and other tools it needs will be downloaded through this repository.
    # JF_RELEASES_REPO: ""

    ###########################################################################
    ##   If your project uses a 'frogbot-config.yml' file, you should define ##
    ##   the following variables inside the file, instead of here.           ##
    ###########################################################################

    # [Mandatory if the two conditions below are met]
    # 1. The project uses yarn 2, NuGet or .NET to download its dependencies
    # 2. The `installCommand` variable isn't set in your frogbot-config.yml file.
    #
    # The command that installs the project dependencies (e.g "nuget restore")
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
    # Relative path to a Pip requirements.txt file. If not set, the python project's dependencies are determined and scanned using the project setup.py file.
    # JF_REQUIREMENTS_FILE: ""

    # [Optional, Default: "TRUE"]
    # Use Gradle wrapper.
    # JF_USE_WRAPPER: "FALSE"

    # [Optional]
    # Frogbot will download the project dependencies if they're not cached locally. To download the
    # dependencies from a virtual repository in Artifactory, set the name of the repository. There's no
    # need to set this value, if it is set in the frogbot-config.yml file.
    # JF_DEPS_REPO: ""

    # [Optional]
    # Template for the branch name generated by Frogbot when creating pull requests with fixes.
    # The template must include ${BRANCH_NAME_HASH}, to ensure that the generated branch name is unique.
    # The template can optionally include the ${IMPACTED_PACKAGE} and ${FIX_VERSION} variables.
    # JF_BRANCH_NAME_TEMPLATE: "frogbot-${IMPACTED_PACKAGE}-${BRANCH_NAME_HASH}"

    # [Optional]
    # Template for the commit message generated by Frogbot when creating pull requests with fixes
    # The template can optionally include the ${IMPACTED_PACKAGE} and ${FIX_VERSION} variables.
    # JF_COMMIT_MESSAGE_TEMPLATE: "Upgrade ${IMPACTED_PACKAGE} to ${FIX_VERSION}"

    # [Optional]
    # Template for the pull request title generated by Frogbot when creating pull requests with fixes.
    # The template can optionally include the ${IMPACTED_PACKAGE} and ${FIX_VERSION} variables.
    # JF_PULL_REQUEST_TITLE_TEMPLATE: "[🐸 Frogbot] Upgrade ${IMPACTED_PACKAGE} to ${FIX_VERSION}"

    # [Optional, Default: "FALSE"]
    # If TRUE, Frogbot creates a single pull request with all the fixes.
    # If FALSE, Frogbot creates a separate pull request for each fix.
    # JF_GIT_AGGREGATE_FIXES: "FALSE"

    # [Optional, Default: "FALSE"]
    # Handle vulnerabilities with fix versions only
    # JF_FIXABLE_ONLY: "TRUE"

    # [Optional]
    # Set the minimum severity for vulnerabilities that should be fixed and commented on in pull requests
    # The following values are accepted: Low, Medium, High or Critical
    # JF_MIN_SEVERITY: ""

    # [Optional, Default: eco-system+frogbot@jfrog.com]
    # Set the email of the commit author
    # JF_GIT_EMAIL_AUTHOR: ""
  script:
    # For Linux / MacOS runner:
    - |
      getFrogbotScriptPath=$(if [ -z "$JF_RELEASES_REPO" ]; then echo "https://releases.jfrog.io"; else echo "${JF_URL}/artifactory/${JF_RELEASES_REPO}"; fi)
      curl -fLg "$getFrogbotScriptPath/artifactory/frogbot/v2/[RELEASE]/getFrogbot.sh" | sh
      ./frogbot ${FROGBOT_CMD}

    # For Windows runner:
    # 
    # - $getFrogbotScriptPath = $(if ([string]::IsNullOrEmpty($env:JF_RELEASES_REPO)) { "https://releases.jfrog.io" } else { "$($env:JF_URL)/artifactory/$($env:JF_RELEASES_REPO)" })
    # - Invoke-WebRequest -Uri "$getFrogbotScriptPath/artifactory/frogbot/v2/[RELEASE]/getFrogbot.sh" -UseBasicParsing | ForEach-Object { & $_.Content }
    # - .\frogbot ${FROGBOT_CMD}
```
