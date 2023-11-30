package utils

import (
	"github.com/stretchr/testify/assert"
	"path/filepath"
	"testing"
)

func TestCreateXrayScanParams(t *testing.T) {
	// Project
	scanDetails := &ScanDetails{}
	scanDetails.SetXrayGraphScanParams(nil, "", false)
	assert.Empty(t, scanDetails.Watches)
	assert.Equal(t, "", scanDetails.ProjectKey)
	assert.True(t, scanDetails.IncludeVulnerabilities)
	assert.False(t, scanDetails.IncludeLicenses)

	// Watches
	scanDetails.SetXrayGraphScanParams([]string{"watch-1", "watch-2"}, "", false)
	assert.Equal(t, []string{"watch-1", "watch-2"}, scanDetails.Watches)
	assert.Equal(t, "", scanDetails.ProjectKey)
	assert.False(t, scanDetails.IncludeVulnerabilities)
	assert.False(t, scanDetails.IncludeLicenses)

	// Project
	scanDetails.SetXrayGraphScanParams(nil, "project", true)
	assert.Empty(t, scanDetails.Watches)
	assert.Equal(t, "project", scanDetails.ProjectKey)
	assert.False(t, scanDetails.IncludeVulnerabilities)
	assert.True(t, scanDetails.IncludeLicenses)
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
