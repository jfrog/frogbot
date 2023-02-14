package utils

import (
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/stretchr/testify/assert"
	"path/filepath"
	"testing"
)

func TestResolveNpmDependencies(t *testing.T) {
	params, restoreEnv := verifyEnv(t)
	defer restoreEnv()
	tmpDir, err := fileutils.CreateTempDir()
	assert.NoError(t, err)
	sourceDir := filepath.Join("..", "testdata", "projects", "npm")
	assert.NoError(t, fileutils.CopyDir(sourceDir, tmpDir, false, nil))
	restoreDir, err := Chdir(tmpDir)
	assert.NoError(t, err)
	defer func() {
		assert.NoError(t, restoreDir())
	}()
	scanSetup := &ScanSetup{
		ServerDetails: &params,
		Project: Project{
			DepsResolutionRepo: "frogbot-npm-remote-tests",
			InstallCommandName: "npm",
			InstallCommandArgs: []string{"install"},
		},
	}
	_, err = resolveNpmDependencies(scanSetup)
	assert.NoError(t, err)
}
