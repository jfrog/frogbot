package utils

import (
	"testing"

	"github.com/owenrumney/go-sarif/v2/sarif"
	"github.com/stretchr/testify/assert"

	"github.com/jfrog/jfrog-cli-security/formats"
	xrayutils "github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-client-go/xray/services"
)

func TestConvertResultsToCollection(t *testing.T) {
	allowedLicenses := []string{"MIT"}
	auditResults := &xrayutils.Results{
		ScaResults: []xrayutils.ScaScanResult{{
			XrayResults: []services.ScanResponse{{
				Vulnerabilities: []services.Vulnerability{
					{Cves: []services.Cve{{Id: "CVE-2022-2122"}}, Severity: "High", Components: map[string]services.Component{"Dep-1": {FixedVersions: []string{"1.2.3"}}}},
					{Cves: []services.Cve{{Id: "CVE-2023-3122"}}, Severity: "Low", Components: map[string]services.Component{"Dep-2": {FixedVersions: []string{"1.2.2"}}}},
				},
				Licenses: []services.License{{Key: "Apache-2.0", Components: map[string]services.Component{"Dep-1": {FixedVersions: []string{"1.2.3"}}}}},
			}},
		}},
		ExtendedScanResults: &xrayutils.ExtendedScanResults{
			ApplicabilityScanResults: []*sarif.Run{
				xrayutils.CreateRunWithDummyResults(
					xrayutils.CreateDummyPassingResult("applic_CVE-2023-3122"),
					xrayutils.CreateResultWithOneLocation("file1", 1, 10, 2, 11, "snippet", "applic_CVE-2022-2122", ""),
				),
			},
			IacScanResults: []*sarif.Run{
				xrayutils.CreateRunWithDummyResults(
					xrayutils.CreateResultWithLocations("Missing auto upgrade was detected", "rule", xrayutils.ConvertToSarifLevel("high"),
						xrayutils.CreateLocation("file1", 1, 10, 2, 11, "aws-violation"),
					),
				),
			},
			SecretsScanResults: []*sarif.Run{
				xrayutils.CreateRunWithDummyResults(
					xrayutils.CreateResultWithLocations("Secret", "rule", xrayutils.ConvertToSarifLevel("high"),
						xrayutils.CreateLocation("index.js", 5, 6, 7, 8, "access token exposed"),
					),
				),
			},
			SastScanResults: []*sarif.Run{
				xrayutils.CreateRunWithDummyResults(
					xrayutils.CreateResultWithLocations("XSS Vulnerability", "rule", xrayutils.ConvertToSarifLevel("high"),
						xrayutils.CreateLocation("file1", 1, 10, 2, 11, "snippet"),
					),
				),
			},
			EntitledForJas: true,
		},
	}
	expectedOutput := &IssuesCollection{
		Vulnerabilities: []formats.VulnerabilityOrViolationRow{
			{
				Applicable:    "Applicable",
				FixedVersions: []string{"1.2.3"},
				ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
					SeverityDetails:        formats.SeverityDetails{Severity: "High", SeverityNumValue: 13},
					ImpactedDependencyName: "Dep-1",
				},
				Cves: []formats.CveRow{{Id: "CVE-2022-2122", Applicability: &formats.Applicability{Status: "Applicable", Evidence: []formats.Evidence{{Location: formats.Location{File: "file1", StartLine: 1, StartColumn: 10, EndLine: 2, EndColumn: 11, Snippet: "snippet"}}}}}},
			},
			{
				Applicable:    "Not Applicable",
				FixedVersions: []string{"1.2.2"},
				ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
					SeverityDetails:        formats.SeverityDetails{Severity: "Low", SeverityNumValue: 2},
					ImpactedDependencyName: "Dep-2",
				},
				Cves: []formats.CveRow{{Id: "CVE-2023-3122", Applicability: &formats.Applicability{Status: "Not Applicable"}}},
			},
		},
		Iacs: []formats.SourceCodeRow{
			{
				SeverityDetails: formats.SeverityDetails{
					Severity:         "High",
					SeverityNumValue: 13,
				},
				Finding: "Missing auto upgrade was detected",
				Location: formats.Location{
					File:        "file1",
					StartLine:   1,
					StartColumn: 10,
					EndLine:     2,
					EndColumn:   11,
					Snippet:     "aws-violation",
				},
			},
		},
		Secrets: []formats.SourceCodeRow{
			{
				SeverityDetails: formats.SeverityDetails{
					Severity:         "High",
					SeverityNumValue: 13,
				},
				Finding: "Secret",
				Location: formats.Location{
					File:        "index.js",
					StartLine:   5,
					StartColumn: 6,
					EndLine:     7,
					EndColumn:   8,
					Snippet:     "access token exposed",
				},
			},
		},
		Sast: []formats.SourceCodeRow{
			{
				SeverityDetails: formats.SeverityDetails{
					Severity:         "High",
					SeverityNumValue: 13,
				},
				Finding: "XSS Vulnerability",
				Location: formats.Location{
					File:        "file1",
					StartLine:   1,
					StartColumn: 10,
					EndLine:     2,
					EndColumn:   11,
					Snippet:     "snippet",
				},
			},
		},
		Licenses: []formats.LicenseRow{
			{
				LicenseKey: "Apache-2.0",
				ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
					ImpactedDependencyName: "Dep-1",
				},
			},
		},
	}

	issuesRows, err := ConvertResultsToCollection(auditResults, allowedLicenses)

	if assert.NoError(t, err) {
		assert.ElementsMatch(t, expectedOutput.Vulnerabilities, issuesRows.Vulnerabilities)
		assert.ElementsMatch(t, expectedOutput.Iacs, issuesRows.Iacs)
		assert.ElementsMatch(t, expectedOutput.Secrets, issuesRows.Secrets)
		assert.ElementsMatch(t, expectedOutput.Sast, issuesRows.Sast)
		assert.ElementsMatch(t, expectedOutput.Licenses, issuesRows.Licenses)
	}
}
