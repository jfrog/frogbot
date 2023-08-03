[Go back to the main documentation page](https://github.com/jfrog/frogbot)

# Installing Frogbot on JFrog Pipelines

| Important: Using Frogbot on JFrog Pipelines isn't recommended for open source projects. Read more about it in the [Security note for pull requests scanning](../README.md#-security-note-for-pull-requests-scanning) section. |
|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|


* Make sure you have the connection details of your JFrog environment.
* Save the JFrog connection details as
  a [JFrog Platform Access Token Integration](https://www.jfrog.com/confluence/display/JFROG/JFrog+Platform+Access+Token+Integration)
  named **jfrogPlatform**.
* Save your Git access token in
  a [Git Server Integration](https://jfrog.com/help/r/jfrog-pipelines-documentation/pipelines-integrations) named
  **gitIntegration**.
* Create a **pipelines.yml** file using one of the available [templates](templates/jfrog-pipelines) and push the file
  into one of your Git repositories, under a directory named `.jfrog-pipelines`.
* In the **pipelines.yml**, make sure to set values for all the mandatory variables.
* In the **pipelines.yml**, if you're using a Windows agent, modify the code inside the onExecute sections as described
  in the template comments.

  **Important**
    - Make sure all the build tools that are used to build the project are installed on the build agent.
