package utils

import (
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/stretchr/testify/assert"
	"path/filepath"
	"testing"
)

func setTestEnvironment(t *testing.T, project string) func() {
	tmpDir, err := fileutils.CreateTempDir()
	assert.NoError(t, err)
	sourceDir := filepath.Join("..", "testdata", "projects", project)
	assert.NoError(t, fileutils.CopyDir(sourceDir, tmpDir, true, nil))
	restoreDir, err := Chdir(tmpDir)
	assert.NoError(t, err)
	return func() {
		assert.NoError(t, restoreDir())
		assert.NoError(t, fileutils.RemoveTempDir(tmpDir))
	}
}

func TestResolveDependencies(t *testing.T) {
	params, restoreEnv := verifyEnv(t)
	defer restoreEnv()
	testCases := []struct {
		name        string
		tech        string
		scanSetup   *ScanSetup
		resolveFunc func(scanSetup *ScanSetup) ([]byte, error)
	}{
		{
			name: "Resolve NPM dependencies",
			tech: "npm",
			scanSetup: &ScanSetup{
				ServerDetails: &params,
				Project: Project{
					DepsResolutionRepo: "frogbot-npm-remote-tests",
					InstallCommandName: "npm",
					InstallCommandArgs: []string{"install"},
				}},
			resolveFunc: resolveNpmDependencies,
		},
		{
			name: "Resolve Yarn dependencies",
			tech: "yarn",
			scanSetup: &ScanSetup{
				ServerDetails: &params,
				Project: Project{
					DepsResolutionRepo: "frogbot-npm-remote-tests",
					InstallCommandName: "yarn",
					InstallCommandArgs: []string{"install"},
				}},
			resolveFunc: resolveYarnDependencies,
		},
		{
			name: "Resolve .NET dependencies",
			tech: "dotnet",
			scanSetup: &ScanSetup{
				ServerDetails: &params,
				Project: Project{
					DepsResolutionRepo: "frogbot-nuget-remote-tests",
					InstallCommandName: "dotnet",
					InstallCommandArgs: []string{"restore"},
				}},
			resolveFunc: resolveDotnetDependencies,
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			restoreFunc := setTestEnvironment(t, test.tech)
			defer restoreFunc()
			_, err := test.resolveFunc(test.scanSetup)
			assert.NoError(t, err)
		})
	}
}
