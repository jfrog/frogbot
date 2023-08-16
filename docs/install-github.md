[Go back to the main documentation page](https://github.com/jfrog/frogbot)

# Setting Frogbot on GitHub repositories

## Github Prerequisites

   - Go to your **Frogbot Management Repository** settings page and save the JFrog connection details as repository secrets with the following names - **JF_URL**, **JF_ACCESS_TOKEN**

   > **_NOTE:_** You can also use **JF_XRAY_URL** and **JF_ARTIFACTORY_URL** instead of **JF_URL**,
   > and **JF_USER** + **JF_PASSWORD** instead of **JF_ACCESS_TOKEN**

   <img src="../images/github-repository-secrets.png" width="600">

   - Check the Allow GitHub Actions to create and approve pull requests check box.

   <img src="../images/github-pr-permissions.png" width="600">

   - For open-source projects: Create a new [GitHub environment](https://docs.github.com/en/actions/deployment/targeting-different-environments/using-environments-for-deployment#creating-an-environment)
   called **frogbot** and add people or public teams as reviewers. The chosen reviewers can trigger Frogbot scans on pull requests.

   <img src="../images/github-environment.png" width="600">

## Frogbot GitHub Action Templates

Use these templates to install [Frogbot](https://github.com/jfrog/frogbot/blob/master/README.md#frogbot) on your GitHub repository.
Push the workflow files to the `.github/workflows` directory at the root of your GitHub repository.

> **IMPORTANT**: The workflow files must be pushed to the target branch before Frogbot is triggered. This means that if, for example, a pull request includes the workflow files and the target branch doesn't, Frogbot will fail to run.

### 🔎 Scan pull requests

Create a file named `frogbot-scan-pull-request.yml` with the content of [this](templates/github-actions/frogbot-scan-pull-request.yml) template.
This will allow Frogbot to scan pull requests for security issues when the pull requests are open, and before they are merged.


### 🛠️ Scanning repository branches and fixing issues

Create a file named `frogbot-scan-repository.yml` with the content of [this](templates/github-actions/frogbot-scan-repository.yml) template.
This will make Frogbot open pull requests with fixes for security vulnerabilities found in the GitHub repository.
