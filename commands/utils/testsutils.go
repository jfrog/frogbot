package utils

import (
	"fmt"
	"github.com/golang/mock/gomock"
	"github.com/jfrog/frogbot/commands/testdata"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Receive an environment variables key-values map, set and assert the environment variables.
// Return a callback that sets the previous values.
func SetEnvAndAssert(t *testing.T, env map[string]string) {
	for key, val := range env {
		setEnvAndAssert(t, key, val)
	}
}

// Make sure the environment variables does not contain any Frogbot variables
func AssertSanitizedEnv(t *testing.T) {
	for _, env := range os.Environ() {
		assert.False(t, strings.HasPrefix(env, "JF_"))
	}
}

func setEnvAndAssert(t *testing.T, key, value string) {
	assert.NoError(t, os.Setenv(key, value))
}

// Prepare test environment for the integration tests
// projectName - the directory name under testDir
// Return a cleanup function and the temp dir path
func PrepareTestEnvironment(t *testing.T, projectName, testDir string) (string, func()) {
	// Copy project to a temporary directory
	tmpDir, err := fileutils.CreateTempDir()
	assert.NoError(t, err)
	err = fileutils.CopyDir(filepath.Join("..", "testdata", testDir), tmpDir, true, []string{})
	assert.NoError(t, err)

	// Renames test git folder to .git
	currentDir := filepath.Join(tmpDir, projectName)
	testGitFolderPath := filepath.Join(currentDir, "git")
	exists, err := fileutils.IsDirExists(testGitFolderPath, false)
	assert.NoError(t, err)
	if exists {
		err = fileutils.CopyDir(testGitFolderPath, filepath.Join(currentDir, ".git"), true, []string{})
		assert.NoError(t, err)
		err = fileutils.RemoveTempDir(testGitFolderPath)
		assert.NoError(t, err)
	}
	restoreDir, err := Chdir(currentDir)
	assert.NoError(t, err)
	return tmpDir, func() {
		assert.NoError(t, restoreDir())
		assert.NoError(t, fileutils.RemoveTempDir(tmpDir))
	}
}

// Check connection details with JFrog instance.
// Return a callback method that restores the credentials after the test is done.
func VerifyEnv(t *testing.T) (server config.ServerDetails, restoreFunc func()) {
	url := strings.TrimSuffix(os.Getenv(JFrogUrlEnv), "/")
	username := os.Getenv(JFrogUserEnv)
	password := os.Getenv(JFrogPasswordEnv)
	token := os.Getenv(JFrogTokenEnv)
	if url == "" {
		assert.FailNow(t, fmt.Sprintf("'%s' is not set", JFrogUrlEnv))
	}
	if token == "" && (username == "" || password == "") {
		assert.FailNow(t, fmt.Sprintf("'%s' or '%s' and '%s' are not set", JFrogTokenEnv, JFrogUserEnv, JFrogPasswordEnv))
	}
	server.Url = url
	server.XrayUrl = url + "/xray/"
	server.ArtifactoryUrl = url + "/artifactory/"
	server.User = username
	server.Password = password
	server.AccessToken = token
	restoreFunc = func() {
		SetEnvAndAssert(t, map[string]string{
			JFrogUrlEnv:          url,
			JFrogTokenEnv:        token,
			JFrogUserEnv:         username,
			JFrogPasswordEnv:     password,
			GitAggregateFixesEnv: "FALSE",
		})
	}
	return
}

func CreateMockVcsClient(t *testing.T) *testdata.MockVcsClient {
	mockCtrl := gomock.NewController(t)
	return testdata.NewMockVcsClient(mockCtrl)
}
