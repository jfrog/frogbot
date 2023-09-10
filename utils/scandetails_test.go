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
	assert.Empty(t, scanDetails.xrayGraphScanParams.Watches)
	assert.Equal(t, "", scanDetails.xrayGraphScanParams.ProjectKey)
	assert.True(t, scanDetails.xrayGraphScanParams.IncludeVulnerabilities)
	assert.False(t, scanDetails.xrayGraphScanParams.IncludeLicenses)

	// Watches
	scanDetails.SetXrayGraphScanParams([]string{"watch-1", "watch-2"}, "")
	assert.Equal(t, []string{"watch-1", "watch-2"}, scanDetails.xrayGraphScanParams.Watches)
	assert.Equal(t, "", scanDetails.xrayGraphScanParams.ProjectKey)
	assert.False(t, scanDetails.xrayGraphScanParams.IncludeVulnerabilities)
	assert.False(t, scanDetails.xrayGraphScanParams.IncludeLicenses)

	// Project
	scanDetails.SetXrayGraphScanParams(nil, "project")
	assert.Empty(t, scanDetails.xrayGraphScanParams.Watches)
	assert.Equal(t, "project", scanDetails.xrayGraphScanParams.ProjectKey)
	assert.False(t, scanDetails.xrayGraphScanParams.IncludeVulnerabilities)
	assert.False(t, scanDetails.xrayGraphScanParams.IncludeLicenses)
}

func TestRunInstallIfNeeded(t *testing.T) {
	scanSetup := ScanDetails{
		project: Project{},
	}
	scanSetup.SetFailOnSecurityIssues(true)
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
	scanSetup.SetProject(params)
	assert.NoError(t, scanSetup.runInstallIfNeeded(tmpDir))

	scanSetup.project.InstallCommandName = "not-exist"
	scanSetup.project.InstallCommandArgs = []string{"1", "2"}
	scanSetup.SetFailOnSecurityIssues(false)
	assert.NoError(t, scanSetup.runInstallIfNeeded(tmpDir))

	params = &Project{
		InstallCommandName: "not-existed",
		InstallCommandArgs: []string{"1", "2"},
	}
	scanSetup.SetProject(params)
	scanSetup.SetFailOnSecurityIssues(true)
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
