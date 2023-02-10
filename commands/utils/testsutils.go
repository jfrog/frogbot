package utils

import (
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
	tmpDir, err := CreateFrogbotTempDir()
	assert.NoError(t, err)
	err = fileutils.CopyDir(filepath.Join("testdata", testDir), tmpDir, true, []string{})
	assert.NoError(t, err)

	restoreDir, err := Chdir(filepath.Join(tmpDir, projectName))
	assert.NoError(t, err)
	return tmpDir, func() {
		assert.NoError(t, restoreDir())
		assert.NoError(t, fileutils.RemoveTempDir(tmpDir))
	}
}
