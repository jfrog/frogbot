# Adding new testdata case with git folder

Frogbot integration tests require `JF_URL` and `JF_ACCESS_TOKEN` to operate, and also require the test data to include `git` folders, mimicking the repositories we operate on.

When creating a new test case that involves git operations, follow these steps:

1. CD into the testdata directory.
2. Run `git init` to initialize a new Git repository.
3. Prepare the necessary test case data:
    - For example, create a main branch with a vulnerability in a `package.json` file and a PR branch containing a new vulnerability to test the `scan-pull-request` command.
4. Change the name of the git directory  `mv git .git`. (this will make it non-operational)
5. If not needed, delete the `hooks` folder to remove redundant files.
6. Add the prepared git folder to the repository by running `git add . && git commit -m 'add testdata git folder'`.
7. During tests,we search for a folder named `git` and rename it to `.git` to make it operational.

By following these steps, you can add new test data cases with git folders to your project's test suite for Frogbot integration testing.
