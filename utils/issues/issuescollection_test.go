package issues

import (
	"testing"

	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/severityutils"
	"github.com/stretchr/testify/assert"
)

func getTestData() ScansIssuesCollection {
	issuesCollection := ScansIssuesCollection{
		ScaVulnerabilities: []formats.VulnerabilityOrViolationRow{
			{
				ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
					ImpactedDependencyName:    "impacted-name",
					ImpactedDependencyVersion: "1.0.0",
					SeverityDetails:           formats.SeverityDetails{Severity: "High"},
					Components: []formats.ComponentRow{
						{
							Name:    "vuln-pack-name1",
							Version: "1.0.0",
						},
						{
							Name:    "vuln-pack-name1",
							Version: "1.2.3",
						},
						{
							Name:    "vuln-pack-name2",
							Version: "1.2.3",
						},
					},
				},
				Cves: []formats.CveRow{{
					Id: "CVE-2021-1234",
					Applicability: &formats.Applicability{
						Status:             "Applicable",
						ScannerDescription: "scanner",
						Evidence: []formats.Evidence{
							{Reason: "reason", Location: formats.Location{File: "file1", StartLine: 1, StartColumn: 2, EndLine: 3, EndColumn: 4, Snippet: "snippet1"}},
							{Reason: "other reason", Location: formats.Location{File: "file2", StartLine: 5, StartColumn: 6, EndLine: 7, EndColumn: 8, Snippet: "snippet2"}},
						},
					},
				}},
				JfrogResearchInformation: &formats.JfrogResearchInformation{
					Remediation: "remediation",
				},
				Summary:    "summary",
				Applicable: "Applicable",
				IssueId:    "Xray-Id",
			},
			{
				ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
					ImpactedDependencyName:    "impacted-name2",
					ImpactedDependencyVersion: "1.0.0",
					SeverityDetails:           formats.SeverityDetails{Severity: "Low"},
					Components: []formats.ComponentRow{
						{
							Name:    "vuln-pack-name3",
							Version: "1.0.0",
						},
					},
				},
				Cves: []formats.CveRow{{
					Id:            "CVE-1111-2222",
					Applicability: &formats.Applicability{Status: "Not Applicable"},
				}},
				Summary:    "other summary",
				Applicable: "Not Applicable",
				IssueId:    "Xray-Id2",
			},
		},

		ScaViolations: []formats.VulnerabilityOrViolationRow{
			{
				ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
					ImpactedDependencyName:    "impacted-name",
					ImpactedDependencyVersion: "1.0.0",
					SeverityDetails:           formats.SeverityDetails{Severity: "Critical"},
					Components: []formats.ComponentRow{
						{
							Name:    "vuln-pack-name1",
							Version: "1.0.0",
						},
					},
				},
				Cves: []formats.CveRow{{
					Id: "CVE-2021-1234",
					Applicability: &formats.Applicability{
						Status:             "Applicable",
						ScannerDescription: "scanner",
						Evidence: []formats.Evidence{
							{Reason: "reason", Location: formats.Location{File: "file1", StartLine: 1, StartColumn: 2, EndLine: 3, EndColumn: 4, Snippet: "snippet1"}},
						},
					},
				}},
				JfrogResearchInformation: &formats.JfrogResearchInformation{
					Remediation: "remediation",
				},
				Summary:    "summary",
				Applicable: "Applicable",
				IssueId:    "Xray-Id",
				ViolationContext: formats.ViolationContext{
					Watch:    "watch",
					Policies: []string{"policy1", "policy2"},
				},
			},
		},

		LicensesViolations: []formats.LicenseViolationRow{{
			LicenseRow: formats.LicenseRow{
				LicenseKey:  "license1",
				LicenseName: "license-name1",
				ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
					SeverityDetails: formats.SeverityDetails{Severity: "Medium"},
					Components: []formats.ComponentRow{
						{
							Name:    "vuln-pack-name3",
							Version: "1.0.0",
						},
					},
				},
			},
			ViolationContext: formats.ViolationContext{
				Watch:    "lic-watch",
				Policies: []string{"policy3"},
			},
		}},

		IacVulnerabilities:     []formats.SourceCodeRow{{SeverityDetails: formats.SeverityDetails{Severity: "Low"}}},
		SecretsVulnerabilities: []formats.SourceCodeRow{{SeverityDetails: formats.SeverityDetails{Severity: "High"}}},
		SecretsViolations: []formats.SourceCodeRow{{
			SeverityDetails: formats.SeverityDetails{Severity: "High"},
			ViolationContext: formats.ViolationContext{
				IssueId: "secret-violation-id",
				Watch:   "watch",
			},
		}},
		SastVulnerabilities: []formats.SourceCodeRow{
			{
				SeverityDetails: formats.SeverityDetails{Severity: "Unknown"},
			},
			{
				SeverityDetails: formats.SeverityDetails{Severity: "High"},
			},
		},
	}
	return issuesCollection
}

func TestCountIssuesCollectionFindings(t *testing.T) {
	testCases := []struct {
		name             string
		includeSecrets   bool
		expectedFindings int
	}{
		{
			name:             "With Secrets",
			includeSecrets:   true,
			expectedFindings: 9,
		},
		{
			name:             "No Secrets",
			includeSecrets:   false,
			expectedFindings: 7,
		},
	}
	issuesCollection := getTestData()
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			findingsAmount := issuesCollection.GetAllIssuesCount(tc.includeSecrets)
			assert.Equal(t, tc.expectedFindings, findingsAmount)
		})
	}
}

func TestGetTotalVulnerabilities(t *testing.T) {
	testCases := []struct {
		name             string
		includeSecrets   bool
		expectedFindings int
	}{
		{
			name:             "With Secrets",
			includeSecrets:   true,
			expectedFindings: 6,
		},
		{
			name:             "No Secrets",
			includeSecrets:   false,
			expectedFindings: 5,
		},
	}
	issuesCollection := getTestData()
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			findingsAmount := issuesCollection.GetTotalVulnerabilities(tc.includeSecrets)
			assert.Equal(t, tc.expectedFindings, findingsAmount)
		})
	}
}

func TestGetTotalViolations(t *testing.T) {
	testCases := []struct {
		name             string
		includeSecrets   bool
		expectedFindings int
	}{
		{
			name:             "With Secrets",
			includeSecrets:   true,
			expectedFindings: 3,
		},
		{
			name:             "No Secrets",
			includeSecrets:   false,
			expectedFindings: 2,
		},
	}
	issuesCollection := getTestData()
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			findingsAmount := issuesCollection.GetTotalViolations(tc.includeSecrets)
			assert.Equal(t, tc.expectedFindings, findingsAmount)
		})
	}
}

func TestGetScanIssuesSeverityCount(t *testing.T) {
	testCases := []struct {
		name                  string
		scanType              utils.SubScanType
		violation             bool
		vulnerabilities       bool
		expectedSeverityCount map[string]int
	}{
		{
			name:                  "Sca Vulnerabilities",
			scanType:              utils.ScaScan,
			vulnerabilities:       true,
			expectedSeverityCount: map[string]int{"High": 1, "Low": 1},
		},
		{
			name:                  "Sca Violations",
			scanType:              utils.ScaScan,
			violation:             true,
			expectedSeverityCount: map[string]int{"Critical": 1, "Medium": 1},
		},
		{
			name:                  "Sca Vulnerabilities and Violations",
			scanType:              utils.ScaScan,
			vulnerabilities:       true,
			violation:             true,
			expectedSeverityCount: map[string]int{"High": 1, "Low": 1, "Critical": 1, "Medium": 1},
		},
		{
			name:                  "Iac Vulnerabilities",
			scanType:              utils.IacScan,
			vulnerabilities:       true,
			expectedSeverityCount: map[string]int{"Low": 1},
		},
		{
			name:                  "Iac Violations",
			scanType:              utils.IacScan,
			violation:             true,
			expectedSeverityCount: map[string]int{},
		},
		{
			name:                  "Iac Vulnerabilities and Violations",
			scanType:              utils.IacScan,
			vulnerabilities:       true,
			violation:             true,
			expectedSeverityCount: map[string]int{"Low": 1},
		},
		{
			name:                  "Secrets Vulnerabilities",
			scanType:              utils.SecretsScan,
			vulnerabilities:       true,
			expectedSeverityCount: map[string]int{"High": 1},
		},
		{
			name:                  "Secrets Violations",
			scanType:              utils.SecretsScan,
			violation:             true,
			expectedSeverityCount: map[string]int{"High": 1},
		},
		{
			name:                  "Secrets Vulnerabilities and Violations",
			scanType:              utils.SecretsScan,
			vulnerabilities:       true,
			violation:             true,
			expectedSeverityCount: map[string]int{"High": 2},
		},
		{
			name:                  "Sast Vulnerabilities",
			scanType:              utils.SastScan,
			vulnerabilities:       true,
			expectedSeverityCount: map[string]int{"High": 1, "Unknown": 1},
		},
		{
			name:                  "Sast Violations",
			scanType:              utils.SastScan,
			violation:             true,
			expectedSeverityCount: map[string]int{},
		},
		{
			name:                  "Sast Vulnerabilities and Violations",
			scanType:              utils.SastScan,
			vulnerabilities:       true,
			violation:             true,
			expectedSeverityCount: map[string]int{"High": 1, "Unknown": 1},
		},
	}
	issuesCollection := getTestData()
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			severityCount := issuesCollection.GetScanIssuesSeverityCount(tc.scanType, tc.vulnerabilities, tc.violation)
			assert.Len(t, severityCount, len(tc.expectedSeverityCount))
			for severity, count := range tc.expectedSeverityCount {
				actualCount, ok := severityCount[severityutils.GetSeverity(severity)]
				assert.True(t, ok)
				assert.Equal(t, count, actualCount)
			}
		})
	}
}

func TestGetApplicableEvidences(t *testing.T) {
	testCases := []struct {
		name              string
		issues            ScansIssuesCollection
		expectedEvidences []ApplicableEvidences
	}{
		{
			name: "No Issues",
		},
		{
			name:   "With Issues",
			issues: getTestData(),
			expectedEvidences: []ApplicableEvidences{
				{
					Evidence: formats.Evidence{Reason: "reason", Location: formats.Location{File: "file1", StartLine: 1, StartColumn: 2, EndLine: 3, EndColumn: 4, Snippet: "snippet1"}},
					Severity: "Critical", ScannerDescription: "scanner", IssueId: "CVE-2021-1234", CveSummary: "summary", ImpactedDependency: "impacted-name:1.0.0", Remediation: "remediation",
				},
				{
					Evidence: formats.Evidence{Reason: "other reason", Location: formats.Location{File: "file2", StartLine: 5, StartColumn: 6, EndLine: 7, EndColumn: 8, Snippet: "snippet2"}},
					Severity: "High", ScannerDescription: "scanner", IssueId: "CVE-2021-1234", CveSummary: "summary", ImpactedDependency: "impacted-name:1.0.0", Remediation: "remediation",
				},
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.ElementsMatch(t, tc.expectedEvidences, tc.issues.GetApplicableEvidences())
		})
	}
}

func TestIssuesExists(t *testing.T) {
	testCases := []struct {
		name           string
		issues         ScansIssuesCollection
		includeSecrets bool
		expected       bool
	}{
		{
			name: "No Issues",
		},
		{
			name:     "With Issues",
			issues:   getTestData(),
			expected: true,
		},
		{
			name:           "With Secrets",
			issues:         getTestData(),
			includeSecrets: true,
			expected:       true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.issues.IssuesExists(tc.includeSecrets))
		})
	}
}

func TestHasErrors(t *testing.T) {
	testCases := []struct {
		name     string
		status   formats.ScanStatus
		expected bool
	}{
		{
			name: "Some Not Scanned",
			status: formats.ScanStatus{
				ScaStatusCode:     utils.NewIntPtr(0),
				SastStatusCode:    utils.NewIntPtr(0),
				SecretsStatusCode: utils.NewIntPtr(0),
			},
		},
		{
			name: "All Completed",
			status: formats.ScanStatus{
				ScaStatusCode:           utils.NewIntPtr(0),
				SastStatusCode:          utils.NewIntPtr(0),
				SecretsStatusCode:       utils.NewIntPtr(0),
				IacStatusCode:           utils.NewIntPtr(0),
				ApplicabilityStatusCode: utils.NewIntPtr(0),
			},
		},
		{
			name: "With Errors",
			status: formats.ScanStatus{
				ScaStatusCode:           utils.NewIntPtr(-1),
				SastStatusCode:          utils.NewIntPtr(0),
				SecretsStatusCode:       utils.NewIntPtr(33),
				IacStatusCode:           utils.NewIntPtr(0),
				ApplicabilityStatusCode: utils.NewIntPtr(0),
			},
			expected: true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			issues := ScansIssuesCollection{ScanStatus: tc.status}
			assert.Equal(t, tc.expected, issues.HasErrors())
		})
	}
}

func TestIsScanNotCompleted(t *testing.T) {
	issues := ScansIssuesCollection{ScanStatus: formats.ScanStatus{
		ScaStatusCode:     utils.NewIntPtr(-1),
		SastStatusCode:    utils.NewIntPtr(0),
		SecretsStatusCode: utils.NewIntPtr(33),
	}}
	testCases := []struct {
		name     string
		scan     utils.SubScanType
		expected bool
	}{
		{
			name: "Scanned and Passed",
			scan: utils.SastScan,
		},
		{
			name:     "Scanned and unknown Failed",
			scan:     utils.ScaScan,
			expected: true,
		},
		{
			name:     "Scanned and Failed",
			scan:     utils.SecretsScan,
			expected: true,
		},
		{
			name:     "Not Scanned",
			scan:     utils.IacScan,
			expected: true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, issues.IsScanNotCompleted(tc.scan))
		})
	}
}

func TestAppendStatus(t *testing.T) {
	oldStatus := formats.ScanStatus{
		ScaStatusCode:  utils.NewIntPtr(-1),
		SastStatusCode: utils.NewIntPtr(0),
	}
	newStatus := formats.ScanStatus{
		ScaStatusCode:           utils.NewIntPtr(0),
		SastStatusCode:          utils.NewIntPtr(33),
		ApplicabilityStatusCode: utils.NewIntPtr(0),
		SecretsStatusCode:       utils.NewIntPtr(51),
	}
	expectedStatus := formats.ScanStatus{
		ScaStatusCode:           utils.NewIntPtr(-1),
		SastStatusCode:          utils.NewIntPtr(33),
		ApplicabilityStatusCode: utils.NewIntPtr(0),
		SecretsStatusCode:       utils.NewIntPtr(51),
	}
	issues := ScansIssuesCollection{ScanStatus: oldStatus}
	issues.AppendStatus(newStatus)
	assert.Equal(t, expectedStatus, issues.ScanStatus)
}
