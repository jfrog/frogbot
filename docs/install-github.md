[Go back to the main documentation page](https://github.com/jfrog/frogbot)

# Setting Frogbot on GitHub repositories

## Github Prerequisites

   - Go to your repository's **settings** tab and save the JFrog connection details as repository secrets with the following names:
      - **JF_URL** (JFrog Platform URL - Example: `https://acme.jfrog.io`)
      - **JF_ACCESS_TOKEN** (JFrog access token)

   > You can also use **JF_XRAY_URL** and **JF_ARTIFACTORY_URL** instead of **JF_URL**,
   > and **JF_USER** + **JF_PASSWORD** instead of **JF_ACCESS_TOKEN**

   <img src="../images/github-repository-secrets.png" width="600">

   - Under **Actions** > **General**, check the **Allow GitHub Actions to create and approve pull requests** check box.

   <img src="../images/github-pr-permissions.png" width="600">

   - For open-source projects: Create a new [GitHub environment](https://docs.github.com/en/actions/deployment/targeting-different-environments/using-environments-for-deployment#creating-an-environment)
   called **frogbot** and add people or public teams as reviewers. The chosen reviewers can trigger Frogbot scans on pull requests.

   <img src="../images/github-environment.png" width="600">

## Frogbot GitHub Action Templates

Use these templates to install [Frogbot](https://github.com/jfrog/frogbot/blob/master/README.md#frogbot) on your GitHub repository.
Push the workflow files to the `.github/workflows` directory at the root of your GitHub repository.

> **IMPORTANT**: The workflow files must be pushed to the target branch before Frogbot is triggered. This means that if, for example, a pull request includes the workflow files and the target branch doesn't, Frogbot will fail to run.

### 🔎 Scan pull requests

Create a file named `frogbot-scan-pull-request.yml` with the content of the following template.
This will allow Frogbot to scan pull requests for security issues when the pull requests are open, and before they are merged.

<details>
  <summary>Show Template</summary>

```yaml
name: "Frogbot Scan Pull Request"
on:
  pull_request_target:
    types: [opened, synchronize]
permissions:
  pull-requests: write
  contents: read
jobs:
  scan-pull-request:
    runs-on: ubuntu-latest
    # A pull request needs to be approved before Frogbot scans it. Any GitHub user who is associated with the
    # "frogbot" GitHub environment can approve the pull request to be scanned.
    environment: frogbot
    steps:
      - uses: jfrog/frogbot@v2
        env:
          # [Mandatory]
          # JFrog platform URL
          JF_URL: ${{ secrets.JF_URL }}

          # [Mandatory if JF_USER and JF_PASSWORD are not provided]
          # JFrog access token with 'read' permissions on Xray service
          JF_ACCESS_TOKEN: ${{ secrets.JF_ACCESS_TOKEN }}

          # [Mandatory if JF_ACCESS_TOKEN is not provided]
          # JFrog username with 'read' permissions for Xray. Must be provided with JF_PASSWORD
          # JF_USER: ${{ secrets.JF_USER }}

          # [Mandatory if JF_ACCESS_TOKEN is not provided]
          # JFrog password. Must be provided with JF_USER
          # JF_PASSWORD: ${{ secrets.JF_PASSWORD }}

          # [Mandatory]
          # The GitHub token is automatically generated for the job
          JF_GIT_TOKEN: ${{ secrets.GITHUB_TOKEN }}

          # [Optional, default: https://api.github.com]
          # API endpoint to GitHub
          # JF_GIT_API_ENDPOINT: https://github.example.com

          # [Optional]
          # By default, the Frogbot workflows download the Frogbot executable as well as other tools
          # needed from https://releases.jfrog.io
          # If the machine that runs Frogbot has no access to the internet, follow these steps to allow the
          # executable to be downloaded from an Artifactory instance, which the machine has access to:
          #
          # 1. Login to the Artifactory UI, with a user who has admin credentials.
          # 2. Create a Remote Repository with the following properties set.
          #    Under the 'Basic' tab:
          #       Package Type: Generic
          #       URL: https://releases.jfrog.io
          #    Under the 'Advanced' tab:
          #       Uncheck the 'Store Artifacts Locally' option
          # 3. Set the value of the 'JF_RELEASES_REPO' variable with the Repository Key you created.
          # JF_RELEASES_REPO: ""
          
          # [Optional]
          # Configure the SMTP server to enable Frogbot to send emails with detected secrets in pull request scans.
          # SMTP server URL including should the relevant port: (Example: smtp.server.com:8080)
          # JF_SMTP_SERVER: ""

          # [Mandatory if JF_SMTP_SERVER is set]
          # The username required for authenticating with the SMTP server.
          # JF_SMTP_USER: ""

          # [Mandatory if JF_SMTP_SERVER is set]
          # The password associated with the username required for authentication with the SMTP server.
          # JF_SMTP_PASSWORD: ""

          ##########################################################################
          ##   If your project uses a 'frogbot-config.yml' file, you can define   ##
          ##   the following variables inside the file, instead of here.          ##
          ##########################################################################

          # [Mandatory if the two conditions below are met]
          # 1. The project uses yarn 2, NuGet or .NET Core to download its dependencies
          # 2. The `installCommand` variable isn't set in your frogbot-config.yml file.
          #
          # The command that installs the project dependencies (e.g "nuget restore")
          # JF_INSTALL_DEPS_CMD: ""

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
          # dependencies from a virtual repository in Artifactory, set the name of the repository. There's no
          # need to set this value, if it is set in the frogbot-config.yml file.
          # JF_DEPS_REPO: ""

          # [Optional, Default: "FALSE"]
          # If TRUE, Frogbot creates a single pull request with all the fixes.
          # If false, Frogbot creates a separate pull request for each fix.
          # JF_GIT_AGGREGATE_FIXES: "FALSE"

          # [Optional, Default: "FALSE"]
          # Handle vulnerabilities with fix versions only
          # JF_FIXABLE_ONLY: "TRUE"

          # [Optional]
          # Set the minimum severity for vulnerabilities that should be fixed and commented on in pull requests
          # The following values are accepted: Low, Medium, High or Critical
          # JF_MIN_SEVERITY: ""
          
          # [Optional]
          # List of comma-separated email addresses to receive email notifications about secrets
          # detected during pull request scanning. The notification is also sent to the email set
          # in the committer git profile regardless of whether this variable is set or not.
          # JF_EMAIL_RECEIVERS: ""
          
```

</details>

### 🛠️ Scanning repository branches and fixing issues

Create a file named `frogbot-scan-and-fix.yml` with the content of the following template.
This will make Frogbot open pull requests with fixes for security vulnerabilities found in the GitHub repository.
> Please notice that the template is configured to scan "dev" branch but it can be changed to any existing branch/branches on your repository.

<details>
  <summary>Show Template</summary>

```yaml
name: "Frogbot Scan Repository"
on:
  workflow_dispatch:
  schedule:
    # The repository will be scanned once a day at 00:00 GMT.
    - cron: "0 0 * * *"
permissions:
  contents: write
  pull-requests: write
  security-events: write
jobs:
  scan-repository:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        # The repository scanning will be triggered periodically on the following branches.
        branch: [ "dev" ]
    steps:
      - uses: actions/checkout@v3
        with:
          ref: ${{ matrix.branch }}

      - uses: jfrog/frogbot@v2
        env:
          # [Mandatory]
          # JFrog platform URL
          JF_URL: ${{ secrets.JF_URL }}

          # [Mandatory if JF_USER and JF_PASSWORD are not provided]
          # JFrog access token with 'read' permissions on Xray service
          JF_ACCESS_TOKEN: ${{ secrets.JF_ACCESS_TOKEN }}

          # [Mandatory if JF_ACCESS_TOKEN is not provided]
          # JFrog username with 'read' permissions for Xray. Must be provided with JF_PASSWORD
          # JF_USER: ${{ secrets.JF_USER }}

          # [Mandatory if JF_ACCESS_TOKEN is not provided]
          # JFrog password. Must be provided with JF_USER
          # JF_PASSWORD: ${{ secrets.JF_PASSWORD }}

          # [Mandatory]
          # The GitHub token is automatically generated for the job
          JF_GIT_TOKEN: ${{ secrets.GITHUB_TOKEN }}

          # [Optional, default: https://api.github.com]
          # API endpoint to GitHub
          # JF_GIT_API_ENDPOINT: https://github.example.com

          # [Optional]
          # By default, the Frogbot workflows download the Frogbot executable as well as other tools
          # needed from https://releases.jfrog.io
          # If the machine that runs Frogbot has no access to the internet, follow these steps to allow the
          # executable to be downloaded from an Artifactory instance, which the machine has access to:
          #
          # 1. Login to the Artifactory UI, with a user who has admin credentials.
          # 2. Create a Remote Repository with the following properties set.
          #    Under the 'Basic' tab:
          #       Package Type: Generic
          #       URL: https://releases.jfrog.io
          #    Under the 'Advanced' tab:
          #       Uncheck the 'Store Artifacts Locally' option
          # 3. Set the value of the 'JF_RELEASES_REPO' variable with the Repository Key you created.
          # JF_RELEASES_REPO: ""

          ##########################################################################
          ##   If your project uses a 'frogbot-config.yml' file, you can define   ##
          ##   the following variables inside the file, instead of here.          ##
          ##########################################################################

          # [Optional, default: "."]
          # Relative path to the root of the project in the Git repository
          # JF_WORKING_DIR: path/to/project/dir

          # [Optional]
          # Xray Watches. Learn more about them here: https://www.jfrog.com/confluence/display/JFROG/Configuring+Xray+Watches
          # JF_WATCHES: <watch-1>,<watch-2>...<watch-n>

          # [Optional]
          # JFrog project. Learn more about it here: https://www.jfrog.com/confluence/display/JFROG/Projects
          # JF_PROJECT: <project-key>

          # [Optional, default: "TRUE"]
          # Fails the Frogbot task if any security issue is found.
          # JF_FAIL: "FALSE"

          # [Optional]
          # Frogbot will download the project dependencies, if they're not cached locally. To download the
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

```
</details>
