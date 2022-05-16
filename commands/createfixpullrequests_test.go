package commands

import (
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	clitool "github.com/urfave/cli/v2"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/jfrog/frogbot/commands/utils"
	"github.com/stretchr/testify/assert"
)

func TestMic(t *testing.T) {
	// Get params and VCS client
	params, client, err := utils.GetParamsAndClient()
	// Do scan commit
	scanResults, err := scanCommit(params)
	if assert.NoError(t, err) {
		// Fix and create PRs
		err = fixImpactedPackagesAndCreatePRs(params, client, scanResults)
		assert.NoError(t, err)
	}
}

func TestScanCommitCreateFixPRs(t *testing.T) {
	testScanCommitCreateFixPRs(t, "", "go-proj")
}

func testScanCommitCreateFixPRs(t *testing.T, workingDirectory, projectName string) {
	restoreEnv := verifyEnv(t)
	defer restoreEnv()

	cleanUp := prepareScanCommitTestEnvironment(t, projectName)
	defer cleanUp()

	// Create mock GitLab server
	server := httptest.NewServer(createGitLabHandler(t, projectName))
	defer server.Close()

	// Set required environment variables
	utils.SetEnvAndAssert(t, map[string]string{
		utils.GitProvider:         string(utils.GitHub),
		utils.GitApiEndpointEnv:   server.URL,
		utils.GitRepoOwnerEnv:     "jfrog",
		utils.GitRepoEnv:          projectName,
		utils.GitTokenEnv:         "123456",
		utils.GitBaseBranchEnv:    "master",
		utils.GitPullRequestIDEnv: "1",
		//utils.InstallCommandEnv:   "npm i",
		utils.WorkingDirectoryEnv: workingDirectory,
	})
	// Run "frogbot spr"
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
	err = fileutils.CopyDir(filepath.Join("testdata", "scancommitcreatefixprs"), tmpDir, true, []string{})
	assert.NoError(t, err)

	restoreDir, err := utils.Chdir(filepath.Join(tmpDir, projectName))
	assert.NoError(t, err)
	return func() {
		assert.NoError(t, restoreDir())
		assert.NoError(t, fileutils.RemoveTempDir(tmpDir))
	}
}
