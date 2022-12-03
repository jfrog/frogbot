# Setting up Frogbot on GitHub repositories

To install Frogbot on GitHub repositories using GitHub Actions: 

1. Make sure you have the connection details of your JFrog environment.
2. Go to your GitHub repository settings page and save the JFrog connection details as repository secrets with the following names - **JF_URL**, **JF_USER**, and **JF_PASSWORD** 

> **_NOTE:_** You can also use **JF_XRAY_URL** and **JF_ARTIFACTORY_URL** instead of **JF_URL**, and **JF_ACCESS_TOKEN** instead of **JF_USER** and **JF_PASSWORD**
   
   ![](../../images/github-repository-secrets.png)

3. Check the Allow GitHub Actions to create and approve pull requests check box. 

   ![](../../images/github-pr-permissions.png)

4. Create a new [GitHub environment](https://docs.github.com/en/actions/deployment/targeting-different-environments/using-environments-for-deployment#creating-an-environment) called **frogbot** and add people or public teams as reviewers. The chosen reviewers can trigger Frogbot scans on pull requests.

   ![](../../images/github-environment.png)

5. Use our [GitHub Actions templates](../templates/github-actions/README.md#frogbot-gitHub-actions-templates) to add Frogbot workflows to your project.
6. Push the workflow files to the **.github/workflows** directory in the root of your GitHub repository.
