package commands

import (
	"github.com/jfrog/frogbot/commands/utils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/sassoftware/go-rpmutils"
	"github.com/stretchr/testify/assert"
	clitool "github.com/urfave/cli/v2"
	"path/filepath"
	"testing"
)

func TestCreateFixPullRequests(t *testing.T) {
	testCreateFixPullRequests(t, "", "go-proj")
}

func testCreateFixPullRequests(t *testing.T, workingDirectory, projectName string) {
	restoreEnv := verifyEnv(t)
	defer restoreEnv()

	cleanUp := prepareScanCommitTestEnvironment(t, projectName)
	defer cleanUp()

	// // Set required environment variables
	// utils.SetEnvAndAssert(t, map[string]string{
	// 	utils.GitProvider:         string(utils.GitHub),
	// 	utils.GitRepoOwnerEnv:     "sverdlov93",
	// 	utils.GitRepoEnv:          "frogbot",
	// 	utils.GitBaseBranchEnv:    "create-fix-prs",
	// 	utils.GitPullRequestIDEnv: "1",
	// 	utils.WorkingDirectoryEnv: workingDirectory,
	// })
	// add vulnerable code
	rpmutils.Vercmp("", "")
	// // Run "frogbot spr"
	app := clitool.App{Commands: GetCommands()}
	assert.NoError(t, app.Run([]string{"frogbot", "create-fix-pull-requests"}))
	utils.AssertSanitizedEnv(t)
}

// Prepare test environment for the integration tests
// projectName - 'test-proj' or 'test-proj-subdir'
// Return a cleanup function
func prepareScanCommitTestEnvironment(t *testing.T, projectName string) func() {
	// Copy project to a temporary directory
	tmpDir, err := fileutils.CreateTempDir()
	assert.NoError(t, err)
	err = fileutils.CopyDir(filepath.Join(".."), tmpDir, true, []string{})
	assert.NoError(t, err)

	restoreDir, err := utils.Chdir(filepath.Join(tmpDir))
	assert.NoError(t, err)
	return func() {
		assert.NoError(t, restoreDir())
		assert.NoError(t, fileutils.RemoveTempDir(tmpDir))
	}
}
