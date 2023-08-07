package utils

import (
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/stretchr/testify/assert"
	"path/filepath"
	"testing"
)

func TestCreateXrayScanParams(t *testing.T) {
	// Project
	scanDetails := &ScanDetails{}
	scanDetails.SetXrayGraphScanParams(nil, "")
	assert.Empty(t, scanDetails.Watches)
	assert.Equal(t, "", scanDetails.ProjectKey)
	assert.True(t, scanDetails.IncludeVulnerabilities)
	assert.False(t, scanDetails.IncludeLicenses)

	// Watches
	scanDetails.SetXrayGraphScanParams([]string{"watch-1", "watch-2"}, "")
	assert.Equal(t, []string{"watch-1", "watch-2"}, scanDetails.Watches)
	assert.Equal(t, "", scanDetails.ProjectKey)
	assert.False(t, scanDetails.IncludeVulnerabilities)
	assert.False(t, scanDetails.IncludeLicenses)

	// Project
	scanDetails.SetXrayGraphScanParams(nil, "project")
	assert.Empty(t, scanDetails.Watches)
	assert.Equal(t, "project", scanDetails.ProjectKey)
	assert.False(t, scanDetails.IncludeVulnerabilities)
	assert.False(t, scanDetails.IncludeLicenses)
}

func TestRunInstallIfNeeded(t *testing.T) {
	scanSetup := ScanDetails{
		Project: &Project{},
	}
	scanSetup.SetFailOnInstallationErrors(true)
	assert.NoError(t, scanSetup.runInstallIfNeeded(""))
	tmpDir, err := fileutils.CreateTempDir()
	assert.NoError(t, err)
	defer func() {
		err = fileutils.RemoveTempDir(tmpDir)
		assert.NoError(t, err)
	}()
	params := &Project{
		InstallCommandName: "echo",
		InstallCommandArgs: []string{"Hello"},
	}
	scanSetup.Project = params
	assert.NoError(t, scanSetup.runInstallIfNeeded(tmpDir))

	scanSetup.InstallCommandName = "not-exist"
	scanSetup.InstallCommandArgs = []string{"1", "2"}
	scanSetup.SetFailOnInstallationErrors(false)
	assert.NoError(t, scanSetup.runInstallIfNeeded(tmpDir))

	params = &Project{
		InstallCommandName: "not-existed",
		InstallCommandArgs: []string{"1", "2"},
	}
	scanSetup.Project = params
	scanSetup.SetFailOnInstallationErrors(true)
	assert.Error(t, scanSetup.runInstallIfNeeded(tmpDir))
}

func TestGetFullPathWorkingDirs(t *testing.T) {
	sampleProject := Project{
		WorkingDirs: []string{filepath.Join("a", "b"), filepath.Join("a", "b", "c"), ".", filepath.Join("c", "d", "e", "f")},
	}
	baseWd := "tempDir"
	fullPathWds := GetFullPathWorkingDirs(sampleProject.WorkingDirs, baseWd)
	expectedWds := []string{filepath.Join("tempDir", "a", "b"), filepath.Join("tempDir", "a", "b", "c"), "tempDir", filepath.Join("tempDir", "c", "d", "e", "f")}
	for _, expectedWd := range expectedWds {
		assert.Contains(t, fullPathWds, expectedWd)
	}
}
