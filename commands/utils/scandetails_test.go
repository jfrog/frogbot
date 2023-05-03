package utils

import (
	"github.com/stretchr/testify/assert"
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
