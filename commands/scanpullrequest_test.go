package commands

import (
	"testing"

	"github.com/jfrog/jfrog-client-go/xray/services"
	"github.com/stretchr/testify/assert"
)

func TestCreateXrayScanParams(t *testing.T) {
	// Project
	params := createXrayScanParams("", "")
	assert.Empty(t, params.Watches)
	assert.Equal(t, "", params.ProjectKey)
	assert.True(t, params.IncludeVulnerabilities)
	assert.False(t, params.IncludeLicenses)

	// Watches
	params = createXrayScanParams("watch-1,watch-2", "")
	assert.Equal(t, []string{"watch-1", "watch-2"}, params.Watches)
	assert.Equal(t, "", params.ProjectKey)
	assert.False(t, params.IncludeVulnerabilities)
	assert.False(t, params.IncludeLicenses)

	// Project
	params = createXrayScanParams("", "project")
	assert.Empty(t, params.Watches)
	assert.Equal(t, "project", params.ProjectKey)
	assert.False(t, params.IncludeVulnerabilities)
	assert.False(t, params.IncludeLicenses)
}

func TestGetNewViolations(t *testing.T) {
	// Previous scan with only one violation - XRAY-1
	previousScan := services.ScanResponse{
		Violations: []services.Violation{{
			IssueId:       "XRAY-1",
			Summary:       "summary-1",
			Severity:      "high",
			ViolationType: "security",
			Components:    map[string]services.Component{"component-A": {}, "component-B": {}},
		}},
	}

	// Current scan with 2 violations - XRAY-1 and XRAY-2
	currentScan := services.ScanResponse{
		Violations: []services.Violation{
			{
				IssueId:       "XRAY-1",
				Summary:       "summary-1",
				Severity:      "high",
				ViolationType: "security",
				Components:    map[string]services.Component{"component-A": {}, "component-B": {}},
			},
			{
				IssueId:       "XRAY-2",
				Summary:       "summary-2",
				ViolationType: "security",
				Severity:      "low",
				Components:    map[string]services.Component{"component-C": {}, "component-D": {}},
			},
		},
	}

	// Run getNewViolations and make sure that only the XRAY-2 violation exists in the results
	newViolations := getNewViolations(previousScan, currentScan)
	assert.Len(t, newViolations, 2)
	assert.Equal(t, "XRAY-2", newViolations[0].IssueId)
	assert.Equal(t, "low", newViolations[0].Severity)
	assert.Equal(t, "XRAY-2", newViolations[1].IssueId)
	assert.Equal(t, "low", newViolations[1].Severity)

	impactedPackageOne := newViolations[0].ImpactedPackageName
	impactedPackageTwo := newViolations[1].ImpactedPackageName
	assert.ElementsMatch(t, []string{"component-C", "component-D"}, []string{impactedPackageOne, impactedPackageTwo})
}

func TestGetNewVulnerabilities(t *testing.T) {
	// Previous scan with only one vulnerability - XRAY-1
	previousScan := services.ScanResponse{
		Vulnerabilities: []services.Vulnerability{{
			IssueId:    "XRAY-1",
			Summary:    "summary-1",
			Severity:   "high",
			Components: map[string]services.Component{"component-A": {}, "component-B": {}},
		}},
	}

	// Current scan with 2 vulnerabilities - XRAY-1 and XRAY-2
	currentScan := services.ScanResponse{
		Vulnerabilities: []services.Vulnerability{
			{
				IssueId:    "XRAY-1",
				Summary:    "summary-1",
				Severity:   "high",
				Components: map[string]services.Component{"component-A": {}, "component-B": {}},
			},
			{
				IssueId:    "XRAY-2",
				Summary:    "summary-2",
				Severity:   "low",
				Components: map[string]services.Component{"component-C": {}, "component-D": {}},
			},
		},
	}

	// Run getNewVulnerabilities and make sure that only the XRAY-2 vulnerability exists in the results
	newViolations := getNewVulnerabilities(previousScan, currentScan)
	assert.Len(t, newViolations, 2)
	assert.Equal(t, "XRAY-2", newViolations[0].IssueId)
	assert.Equal(t, "low", newViolations[0].Severity)
	assert.Equal(t, "XRAY-2", newViolations[1].IssueId)
	assert.Equal(t, "low", newViolations[1].Severity)

	impactedPackageOne := newViolations[0].ImpactedPackageName
	impactedPackageTwo := newViolations[1].ImpactedPackageName
	assert.ElementsMatch(t, []string{"component-C", "component-D"}, []string{impactedPackageOne, impactedPackageTwo})
}
