package outputwriter

import (
	"path/filepath"
	"testing"

	"github.com/jfrog/froggit-go/vcsutils"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/severityutils"
	xrayApi "github.com/jfrog/jfrog-client-go/xray/services/utils"
	"github.com/stretchr/testify/assert"

	"github.com/jfrog/frogbot/v2/utils/issues"
)

func TestGetMainCommentContent(t *testing.T) {
	testCases := []struct {
		name         string
		cases        []OutputTestCase
		issuesExists bool
		isComment    bool
	}{
		{
			name:         "Main comment No issues found",
			issuesExists: false,
			isComment:    true,
			cases: []OutputTestCase{
				{
					name:               "Pull Request entitled (Standard output)",
					writer:             &StandardOutput{MarkdownOutput{hasInternetConnection: true, entitledForJas: true}},
					expectedOutputPath: []string{filepath.Join(testSummaryCommentDir, "structure", "summary_comment_no_issues_pr_entitled.md")},
				},
				{
					name:               "Merge Request entitled (Standard output)",
					writer:             &StandardOutput{MarkdownOutput{hasInternetConnection: true, vcsProvider: vcsutils.GitLab, entitledForJas: true}},
					expectedOutputPath: []string{filepath.Join(testSummaryCommentDir, "structure", "summary_comment_no_issues_mr_entitled.md")},
				},
				{
					name:               "Simplified output entitled",
					writer:             &SimplifiedOutput{MarkdownOutput{hasInternetConnection: true, entitledForJas: true}},
					expectedOutputPath: []string{filepath.Join(testSummaryCommentDir, "structure", "summary_comment_no_issues_simplified_entitled.md")},
				},
				{
					name:               "Pull Request not entitled custom title (Standard output)",
					writer:             &StandardOutput{MarkdownOutput{hasInternetConnection: true, pullRequestCommentTitle: "Custom title"}},
					expectedOutputPath: []string{filepath.Join(testSummaryCommentDir, "structure", "summary_comment_no_issues_pr_entitled_with_title.md")},
				},
				{
					name:               "Merge Request not entitled (Standard output)",
					writer:             &StandardOutput{MarkdownOutput{hasInternetConnection: true, vcsProvider: vcsutils.GitLab}},
					expectedOutputPath: []string{filepath.Join(testSummaryCommentDir, "structure", "summary_comment_no_issues_mr_entitled.md")},
				},
			},
		},
		{
			name:         "Main comment Found issues",
			issuesExists: true,
			isComment:    true,
			cases: []OutputTestCase{
				{
					name:               "Pull Request entitled (Standard output)",
					writer:             &StandardOutput{MarkdownOutput{hasInternetConnection: true, entitledForJas: true}},
					expectedOutputPath: []string{filepath.Join(testSummaryCommentDir, "structure", "summary_comment_issues_pr_entitled.md")},
				},
				{
					name:               "Merge Request entitled (Standard output)",
					writer:             &StandardOutput{MarkdownOutput{hasInternetConnection: true, vcsProvider: vcsutils.GitLab, entitledForJas: true}},
					expectedOutputPath: []string{filepath.Join(testSummaryCommentDir, "structure", "summary_comment_issues_mr_entitled.md")},
				},
				{
					name:               "Pull Request not entitled (Standard output)",
					writer:             &StandardOutput{MarkdownOutput{hasInternetConnection: true}},
					expectedOutputPath: []string{filepath.Join(testSummaryCommentDir, "structure", "summary_comment_issues_pr_entitled.md")},
				},
				{
					name:               "Simplified output not entitled",
					writer:             &SimplifiedOutput{MarkdownOutput{hasInternetConnection: true}},
					expectedOutputPath: []string{filepath.Join(testSummaryCommentDir, "structure", "summary_comment_issues_simplified_entitled.md")},
				},
				{
					name:               "Simplified output entitled",
					writer:             &SimplifiedOutput{MarkdownOutput{hasInternetConnection: true, entitledForJas: true}},
					expectedOutputPath: []string{filepath.Join(testSummaryCommentDir, "structure", "summary_comment_issues_simplified_entitled.md")},
				},
				{
					name:               "Merge Request entitled custom title (Standard output)",
					writer:             &StandardOutput{MarkdownOutput{hasInternetConnection: true, vcsProvider: vcsutils.GitLab, entitledForJas: true, pullRequestCommentTitle: "Custom title"}},
					expectedOutputPath: []string{filepath.Join(testSummaryCommentDir, "structure", "summary_comment_issues_mr_entitled_with_title.md")},
				},
				{
					name:               "Pull request entitled custom title (Simplified output)",
					writer:             &SimplifiedOutput{MarkdownOutput{hasInternetConnection: true, entitledForJas: true, pullRequestCommentTitle: "Custom title"}},
					expectedOutputPath: []string{filepath.Join(testSummaryCommentDir, "structure", "summary_comment_issues_simplified_entitled_with_title.md")},
				},
			},
		},
		{
			name:         "Frogbot Fix issues details content",
			issuesExists: true,
			isComment:    false,
			cases: []OutputTestCase{
				{
					name:               "Pull Request entitled (Standard output)",
					writer:             &StandardOutput{MarkdownOutput{hasInternetConnection: true, entitledForJas: true}},
					expectedOutputPath: []string{filepath.Join(testSummaryCommentDir, "structure", "fix_pr_entitled.md")},
				},
				{
					name:               "Merge Request entitled (Standard output)",
					writer:             &StandardOutput{MarkdownOutput{hasInternetConnection: true, vcsProvider: vcsutils.GitLab, entitledForJas: true}},
					expectedOutputPath: []string{filepath.Join(testSummaryCommentDir, "structure", "fix_mr_entitled.md")},
				},
				{
					name:               "Simplified output entitled",
					writer:             &SimplifiedOutput{MarkdownOutput{hasInternetConnection: true}},
					expectedOutputPath: []string{filepath.Join(testSummaryCommentDir, "structure", "fix_simplified_entitled.md")},
				},
			},
		},
	}

	for _, tc := range testCases {
		for _, test := range tc.cases {
			t.Run(tc.name+"_"+test.name, func(t *testing.T) {
				expectedOutput := GetExpectedTestOutput(t, test)
				output := GetMainCommentContent([]string{MarkAsCodeSnippet("some content")}, tc.issuesExists, tc.isComment, test.writer)
				assert.Len(t, output, 1)
				assert.Equal(t, expectedOutput, output[0])
			})
		}
	}
}

func TestScanSummaryContent(t *testing.T) {
	testScanStatus := formats.ScanStatus{
		ScaStatusCode:           utils.NewIntPtr(0),
		ApplicabilityStatusCode: utils.NewIntPtr(0),
		SastStatusCode:          utils.NewIntPtr(0),
		SecretsStatusCode:       utils.NewIntPtr(0),
	}
	testIssues := issues.ScansIssuesCollection{
		ScaVulnerabilities: []formats.VulnerabilityOrViolationRow{
			{ImpactedDependencyDetails: formats.ImpactedDependencyDetails{SeverityDetails: formats.SeverityDetails{Severity: "Critical"}}},
			{ImpactedDependencyDetails: formats.ImpactedDependencyDetails{SeverityDetails: formats.SeverityDetails{Severity: "High"}}},
			{ImpactedDependencyDetails: formats.ImpactedDependencyDetails{SeverityDetails: formats.SeverityDetails{Severity: "High"}}},
			{ImpactedDependencyDetails: formats.ImpactedDependencyDetails{SeverityDetails: formats.SeverityDetails{Severity: "Medium"}}},
			{ImpactedDependencyDetails: formats.ImpactedDependencyDetails{SeverityDetails: formats.SeverityDetails{Severity: "Low"}}},
			{ImpactedDependencyDetails: formats.ImpactedDependencyDetails{SeverityDetails: formats.SeverityDetails{Severity: "Unknown"}}},
		},
		ScaViolations: []formats.VulnerabilityOrViolationRow{
			{ImpactedDependencyDetails: formats.ImpactedDependencyDetails{SeverityDetails: formats.SeverityDetails{Severity: "Critical"}}},
		},
		LicensesViolations: []formats.LicenseViolationRow{
			{LicenseRow: formats.LicenseRow{ImpactedDependencyDetails: formats.ImpactedDependencyDetails{SeverityDetails: formats.SeverityDetails{Severity: "High"}}}},
			{LicenseRow: formats.LicenseRow{ImpactedDependencyDetails: formats.ImpactedDependencyDetails{SeverityDetails: formats.SeverityDetails{Severity: "Medium"}}}},
		},
		SecretsVulnerabilities: []formats.SourceCodeRow{
			{SeverityDetails: formats.SeverityDetails{Severity: "High"}},
			{SeverityDetails: formats.SeverityDetails{Severity: "High"}},
		},
		SastVulnerabilities: []formats.SourceCodeRow{
			{SeverityDetails: formats.SeverityDetails{Severity: "High"}},
			{SeverityDetails: formats.SeverityDetails{Severity: "High"}},
			{SeverityDetails: formats.SeverityDetails{Severity: "Low"}},
		},
		SastViolations: []formats.SourceCodeRow{{SeverityDetails: formats.SeverityDetails{Severity: "High"}}},
	}

	testCases := []struct {
		name           string
		includeSecrets bool
		scanStatus     formats.ScanStatus
		context        results.ResultContext
		issues         issues.ScansIssuesCollection
		cases          []OutputTestCase
	}{
		{
			name:       "No issues",
			issues:     issues.ScansIssuesCollection{},
			scanStatus: testScanStatus,
			cases: []OutputTestCase{
				{
					name:           "Standard output",
					writer:         &StandardOutput{},
					expectedOutput: []string{""},
				},
				{
					name:           "Simplified output",
					writer:         &SimplifiedOutput{},
					expectedOutput: []string{""},
				},
			},
		},
		{
			name:       "Vulnerabilities",
			issues:     testIssues,
			scanStatus: testScanStatus,
			context:    results.ResultContext{IncludeVulnerabilities: true},
			cases: []OutputTestCase{
				{
					name:               "Standard output",
					writer:             &StandardOutput{MarkdownOutput{hasInternetConnection: true}},
					expectedOutputPath: []string{filepath.Join(testSummaryCommentDir, "summary", "summary_standard.md")},
				},
				{
					name:               "Simplified output",
					writer:             &SimplifiedOutput{MarkdownOutput{hasInternetConnection: true}},
					expectedOutputPath: []string{filepath.Join(testSummaryCommentDir, "summary", "summary_simplified.md")},
				},
			},
		},
		{
			name:       "Violations",
			issues:     testIssues,
			scanStatus: testScanStatus,
			context:    results.ResultContext{Watches: []string{"watch"}},
			cases: []OutputTestCase{
				{
					name:               "Standard output",
					writer:             &StandardOutput{MarkdownOutput{hasInternetConnection: true}},
					expectedOutputPath: []string{filepath.Join(testSummaryCommentDir, "summary", "summary_violation_standard.md")},
				},
				{
					name:               "Simplified output",
					writer:             &SimplifiedOutput{MarkdownOutput{hasInternetConnection: true}},
					expectedOutputPath: []string{filepath.Join(testSummaryCommentDir, "summary", "summary_violation_simplified.md")},
				},
			},
		},
		{
			name:       "Violations and Vulnerabilities",
			issues:     testIssues,
			scanStatus: testScanStatus,
			context:    results.ResultContext{GitRepoHttpsCloneUrl: "url", PlatformWatches: &xrayApi.ResourcesWatchesBody{GitRepositoryWatches: []string{"watch"}}, IncludeVulnerabilities: true},
			cases: []OutputTestCase{
				{
					name:               "Standard output",
					writer:             &StandardOutput{MarkdownOutput{hasInternetConnection: true}},
					expectedOutputPath: []string{filepath.Join(testSummaryCommentDir, "summary", "summary_both_standard.md")},
				},
				{
					name:               "Simplified output",
					writer:             &SimplifiedOutput{MarkdownOutput{hasInternetConnection: true}},
					expectedOutputPath: []string{filepath.Join(testSummaryCommentDir, "summary", "summary_both_simplified.md")},
				},
			},
		},
		{
			name:   "with errors",
			issues: issues.ScansIssuesCollection{},
			scanStatus: formats.ScanStatus{
				IacStatusCode: utils.NewIntPtr(33),
			},
			context: results.ResultContext{GitRepoHttpsCloneUrl: "url", PlatformWatches: &xrayApi.ResourcesWatchesBody{GitRepositoryWatches: []string{"watch"}}},
			cases: []OutputTestCase{
				{
					name:               "Standard output",
					writer:             &StandardOutput{MarkdownOutput{hasInternetConnection: true}},
					expectedOutputPath: []string{filepath.Join(testSummaryCommentDir, "summary", "summary_error_standard.md")},
				},
				{
					name:               "Simplified output",
					writer:             &SimplifiedOutput{MarkdownOutput{hasInternetConnection: true}},
					expectedOutputPath: []string{filepath.Join(testSummaryCommentDir, "summary", "summary_error_simplified.md")},
				},
			},
		},
	}

	for _, tc := range testCases {
		for _, test := range tc.cases {
			t.Run(tc.name+"_"+test.name, func(t *testing.T) {
				expectedOutput := GetExpectedTestOutput(t, test)
				tc.issues.ScanStatus = tc.scanStatus
				output := ScanSummaryContent(tc.issues, tc.context, tc.includeSecrets, test.writer)
				assert.Equal(t, expectedOutput, output)
			})
		}
	}
}

func TestVulnerabilitiesContent(t *testing.T) {
	testCases := []struct {
		name            string
		vulnerabilities []formats.VulnerabilityOrViolationRow
		cases           []OutputTestCase
	}{
		{
			name:            "No vulnerabilities",
			vulnerabilities: []formats.VulnerabilityOrViolationRow{},
			cases: []OutputTestCase{
				{
					name:           "Standard output",
					writer:         &StandardOutput{},
					expectedOutput: []string{},
				},
				{
					name:           "Simplified output",
					writer:         &SimplifiedOutput{},
					expectedOutput: []string{},
				},
			},
		},
		{
			name: "One vulnerability",
			vulnerabilities: []formats.VulnerabilityOrViolationRow{
				{
					Summary: "Summary CVE-2022-26652",
					ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
						SeverityDetails:           formats.SeverityDetails{Severity: "Medium"},
						ImpactedDependencyName:    "github.com/nats-io/nats-streaming-server",
						ImpactedDependencyVersion: "v0.21.0",
						Components: []formats.ComponentRow{
							{
								Name:    "github.com/nats-io/nats-streaming-server",
								Version: "v0.21.0",
							},
						},
					},
					Applicable:    "Undetermined",
					FixedVersions: []string{"[0.24.3]"},
					ImpactPaths: [][]formats.ComponentRow{
						{
							{Name: "root", Version: "1.0.0"},
							{Name: "github.com/nats-io/nats-streaming-server", Version: "v0.21.0"},
						},
					},
					JfrogResearchInformation: &formats.JfrogResearchInformation{
						Details:     "Research CVE-2022-26652 details",
						Remediation: "some remediation",
					},
					Cves: []formats.CveRow{{Id: "CVE-2022-26652"}},
				},
			},
			cases: []OutputTestCase{
				{
					name:               "Standard output",
					writer:             &StandardOutput{},
					expectedOutputPath: []string{filepath.Join(testSummaryCommentDir, "vulnerabilities", "one_vulnerability_standard.md")},
				},
				{
					name:               "Simplified output",
					writer:             &SimplifiedOutput{},
					expectedOutputPath: []string{filepath.Join(testSummaryCommentDir, "vulnerabilities", "one_vulnerability_simplified.md")},
				},
			},
		},
		{
			name: "One vulnerability, no Details",
			vulnerabilities: []formats.VulnerabilityOrViolationRow{
				{
					ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
						SeverityDetails:           formats.SeverityDetails{Severity: "Medium"},
						ImpactedDependencyName:    "github.com/nats-io/nats-streaming-server",
						ImpactedDependencyVersion: "v0.21.0",
						Components: []formats.ComponentRow{
							{
								Name:    "github.com/nats-io/nats-streaming-server",
								Version: "v0.21.0",
							},
						},
					},
					Applicable:    "Undetermined",
					FixedVersions: []string{"[0.24.3]"},
					ImpactPaths: [][]formats.ComponentRow{
						{
							{Name: "root", Version: "1.0.0"},
							{Name: "github.com/nats-io/nats-streaming-server", Version: "v0.21.0"},
						},
					},
					Cves: []formats.CveRow{{Id: "CVE-2022-26652"}},
				},
			},
			cases: []OutputTestCase{
				{
					name:               "Standard output",
					writer:             &StandardOutput{},
					expectedOutputPath: []string{filepath.Join(testSummaryCommentDir, "vulnerabilities", "one_vulnerability_no_details_standard.md")},
				},
				{
					name:               "Simplified output",
					writer:             &SimplifiedOutput{},
					expectedOutputPath: []string{filepath.Join(testSummaryCommentDir, "vulnerabilities", "one_vulnerability_no_details_simplified.md")},
				},
			},
		},
		{
			name:            "multiple Vulnerabilities with Contextual Analysis",
			vulnerabilities: getTestScaIssues(false),
			cases: []OutputTestCase{
				{
					name:               "Standard output",
					writer:             &StandardOutput{MarkdownOutput{showCaColumn: true, hasInternetConnection: true}},
					expectedOutputPath: []string{filepath.Join(testSummaryCommentDir, "vulnerabilities", "vulnerabilities_standard.md")},
				},
				{
					name:               "Simplified output",
					writer:             &SimplifiedOutput{MarkdownOutput{showCaColumn: true, hasInternetConnection: true}},
					expectedOutputPath: []string{filepath.Join(testSummaryCommentDir, "vulnerabilities", "vulnerabilities_simplified.md")},
				},
				{
					name:   "Split Standard output",
					writer: &StandardOutput{MarkdownOutput{showCaColumn: true, hasInternetConnection: true, descriptionSizeLimit: 1720, commentSizeLimit: 1720}},
					expectedOutputPath: []string{
						filepath.Join(testSummaryCommentDir, "vulnerabilities", "vulnerabilities_standard_split1.md"),
						filepath.Join(testSummaryCommentDir, "vulnerabilities", "vulnerabilities_standard_split2.md"),
					},
				},
				{
					name:   "Split Simplified output",
					writer: &SimplifiedOutput{MarkdownOutput{showCaColumn: true, hasInternetConnection: true, descriptionSizeLimit: 1000, commentSizeLimit: 2000}},
					expectedOutputPath: []string{
						filepath.Join(testSummaryCommentDir, "vulnerabilities", "vulnerabilities_simplified_split1.md"),
						filepath.Join(testSummaryCommentDir, "vulnerabilities", "vulnerabilities_simplified_split2.md"),
					},
				},
			},
		},
	}
	for _, tc := range testCases {
		for _, test := range tc.cases {
			t.Run(tc.name+"_"+test.name, func(t *testing.T) {
				expectedOutput := GetExpectedTestCaseOutput(t, test)
				output := ConvertContentToComments(GetVulnerabilitiesContent(tc.vulnerabilities, test.writer), test.writer)
				assert.Len(t, output, len(expectedOutput))
				assert.ElementsMatch(t, expectedOutput, output)
			})
		}
	}
}

func TestSecurityViolationsContent(t *testing.T) {
	testCases := []struct {
		name   string
		issues issues.ScansIssuesCollection
		cases  []OutputTestCase
	}{
		{
			name:   "No security violations",
			issues: issues.ScansIssuesCollection{},
			cases: []OutputTestCase{
				{
					name:           "Standard output",
					writer:         &StandardOutput{},
					expectedOutput: []string{},
				},
				{
					name:           "Simplified output",
					writer:         &SimplifiedOutput{},
					expectedOutput: []string{},
				},
			},
		},
		{
			name:   "Security violations",
			issues: issues.ScansIssuesCollection{ScaViolations: getTestScaIssues(true)},
			cases: []OutputTestCase{
				{
					name:               "Standard output",
					writer:             &StandardOutput{MarkdownOutput{showCaColumn: true, hasInternetConnection: true}},
					expectedOutputPath: []string{filepath.Join(testSummaryCommentDir, "violations", "security", "security_violation_standard.md")},
				},
				{
					name:               "Simplified output",
					writer:             &SimplifiedOutput{MarkdownOutput{showCaColumn: true, hasInternetConnection: true}},
					expectedOutputPath: []string{filepath.Join(testSummaryCommentDir, "violations", "security", "security_violation_simplified.md")},
				},
			},
		},
	}
	for _, tc := range testCases {
		for _, test := range tc.cases {
			t.Run(tc.name+"_"+test.name, func(t *testing.T) {
				expectedOutput := GetExpectedTestCaseOutput(t, test)
				output := ConvertContentToComments(getSecurityViolationsContent(tc.issues, test.writer), test.writer)
				assert.Len(t, output, len(expectedOutput))
				assert.ElementsMatch(t, expectedOutput, output)
			})
		}
	}
}

func getTestScaIssues(violations bool) []formats.VulnerabilityOrViolationRow {
	issues := []formats.VulnerabilityOrViolationRow{
		{
			ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
				SeverityDetails:           severityutils.GetAsDetails(severityutils.Critical, jasutils.NotApplicable, false),
				ImpactedDependencyName:    "impacted",
				ImpactedDependencyVersion: "3.0.0",
				Components: []formats.ComponentRow{
					{Name: "dep1", Version: "1.0.0"},
					{Name: "dep2", Version: "2.0.0"},
				},
			},
			Applicable:    "Not Applicable",
			FixedVersions: []string{"4.0.0", "5.0.0"},
			ImpactPaths: [][]formats.ComponentRow{
				{
					{Name: "root", Version: "1.0.0"},
					{Name: "dep1", Version: "1.0.0"},
					{Name: "impacted", Version: "3.0.0"},
				},
				{
					{Name: "root", Version: "1.0.0"},
					{Name: "dep2", Version: "2.0.0"},
					{Name: "impacted", Version: "3.0.0"},
				},
			},
			Cves: []formats.CveRow{{Id: "CVE-1111-11111", Applicability: &formats.Applicability{Status: "Not Applicable"}}},
		},
		{
			Summary: "Summary XRAY-122345",
			ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
				SeverityDetails:           severityutils.GetAsDetails(severityutils.High, jasutils.ApplicabilityUndetermined, false),
				ImpactedDependencyName:    "github.com/nats-io/nats-streaming-server",
				ImpactedDependencyVersion: "v0.21.0",
				Components: []formats.ComponentRow{
					{
						Name:    "github.com/nats-io/nats-streaming-server",
						Version: "v0.21.0",
					},
				},
			},
			Applicable:    "Undetermined",
			FixedVersions: []string{"[0.24.1]"},
			ImpactPaths: [][]formats.ComponentRow{
				{
					{Name: "root", Version: "1.0.0"},
					{Name: "github.com/nats-io/nats-streaming-server", Version: "v0.21.0"},
				},
			},
			IssueId: "XRAY-122345",
			JfrogResearchInformation: &formats.JfrogResearchInformation{
				Remediation: "some remediation",
			},
			Cves: []formats.CveRow{},
		},
		{
			ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
				SeverityDetails:           severityutils.GetAsDetails(severityutils.Medium, jasutils.Applicable, false),
				ImpactedDependencyName:    "component-D",
				ImpactedDependencyVersion: "v0.21.0",
				Components: []formats.ComponentRow{
					{
						Name:    "component-D",
						Version: "v0.21.0",
					},
				},
			},
			Applicable:    "Applicable",
			FixedVersions: []string{"[0.24.3]"},
			ImpactPaths: [][]formats.ComponentRow{
				{
					{Name: "root", Version: "1.0.0"},
					{Name: "component-D", Version: "v0.21.0"},
				},
			},
			JfrogResearchInformation: &formats.JfrogResearchInformation{
				Remediation: "some remediation",
			},
			Cves: []formats.CveRow{
				{Id: "CVE-2022-26652"},
				{Id: "CVE-2023-4321", Applicability: &formats.Applicability{Status: "Applicable"}},
			},
		},
		{
			Summary: "Summary",
			ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
				SeverityDetails:           severityutils.GetAsDetails(severityutils.Low, jasutils.ApplicabilityUndetermined, false),
				ImpactedDependencyName:    "github.com/mholt/archiver/v3",
				ImpactedDependencyVersion: "v3.5.1",
				Components: []formats.ComponentRow{
					{
						Name:    "github.com/mholt/archiver/v3",
						Version: "v3.5.1",
					},
				},
			},
			Applicable: "Undetermined",
			ImpactPaths: [][]formats.ComponentRow{
				{
					{Name: "root", Version: "1.0.0"},
					{Name: "github.com/mholt/archiver/v3", Version: "v3.5.1"},
				},
			},
			Cves: []formats.CveRow{},
		},
	}
	if violations {
		for _, issue := range issues {
			issue.ViolationContext = formats.ViolationContext{
				Watch:    "watch",
				Policies: []string{"policy1", "policy2"},
			}
		}
	}
	return issues
}

func TestLicensesContent(t *testing.T) {
	testCases := []struct {
		name     string
		licenses []formats.LicenseViolationRow
		cases    []OutputTestCase
	}{
		{
			name:     "No license violations",
			licenses: []formats.LicenseViolationRow{},
			cases: []OutputTestCase{
				{
					name:           "Standard output",
					writer:         &StandardOutput{},
					expectedOutput: []string{},
				},
				{
					name:           "Simplified output",
					writer:         &SimplifiedOutput{},
					expectedOutput: []string{},
				},
			},
		},
		{
			name: "License violations",
			licenses: []formats.LicenseViolationRow{
				{
					LicenseRow: formats.LicenseRow{
						LicenseKey:  "License1",
						LicenseName: "License1 full name",
						ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
							Components:                []formats.ComponentRow{{Name: "Comp1", Version: "1.0"}},
							ImpactedDependencyName:    "Dep1",
							ImpactedDependencyVersion: "2.0",
							SeverityDetails: formats.SeverityDetails{
								Severity: "High",
							},
						},
					},
					ViolationContext: formats.ViolationContext{
						Watch:    "watch",
						Policies: []string{"policy1", "policy2"},
					},
				},
				{
					LicenseRow: formats.LicenseRow{
						LicenseKey: "License2",
						ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
							Components: []formats.ComponentRow{
								{
									Name:    "root",
									Version: "1.0.0",
								},
								{
									Name:    "minimatch",
									Version: "1.2.3",
								},
							},
							ImpactedDependencyName:    "Dep2",
							ImpactedDependencyVersion: "3.0",
							SeverityDetails: formats.SeverityDetails{
								Severity: "High",
							},
						},
					},
					ViolationContext: formats.ViolationContext{
						Watch:    "watch2",
						Policies: []string{"policy3"},
					},
				},
			},
			cases: []OutputTestCase{
				{
					name:               "Standard output",
					writer:             &StandardOutput{MarkdownOutput{hasInternetConnection: true}},
					expectedOutputPath: []string{filepath.Join(testSummaryCommentDir, "violations", "license", "license_violation_standard.md")},
				},
				{
					name:               "Simplified output",
					writer:             &SimplifiedOutput{MarkdownOutput{hasInternetConnection: true}},
					expectedOutputPath: []string{filepath.Join(testSummaryCommentDir, "violations", "license", "license_violation_simplified.md")},
				},
			},
		},
	}
	for _, tc := range testCases {
		for _, test := range tc.cases {
			t.Run(tc.name+"_"+test.name, func(t *testing.T) {
				expectedOutput := GetExpectedTestCaseOutput(t, test)
				assert.Equal(t, expectedOutput, PolicyViolationsContent(issues.ScansIssuesCollection{LicensesViolations: tc.licenses}, test.writer))
			})
		}
	}
}

func TestIsFrogbotReviewComment(t *testing.T) {
	testCases := []struct {
		name           string
		content        string
		expectedOutput bool
	}{
		{
			name:           "Not frogbot comments",
			content:        "This comment is unrelated to Frogbot",
			expectedOutput: false,
		},
		{
			name:           "Frogbot review comment",
			content:        MarkdownComment(ReviewCommentId) + "This is a review comment",
			expectedOutput: true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expectedOutput, IsFrogbotComment(tc.content))
		})
	}
}

func TestGenerateReviewComment(t *testing.T) {
	testCases := []struct {
		name     string
		location *formats.Location
		cases    []OutputTestCase
	}{
		{
			name: "Review comment structure",
			cases: []OutputTestCase{
				{
					name:               "Standard output",
					writer:             &StandardOutput{},
					expectedOutputPath: []string{filepath.Join(testReviewCommentDir, "review_comment_standard.md")},
				},
				{
					name:               "Simplified output",
					writer:             &SimplifiedOutput{},
					expectedOutputPath: []string{filepath.Join(testReviewCommentDir, "review_comment_simplified.md")},
				},
			},
		},
		{
			name: "Fallback review comment structure",
			location: &formats.Location{
				File:        "file",
				StartLine:   11,
				StartColumn: 22,
				EndLine:     33,
				EndColumn:   44,
				Snippet:     "snippet",
			},
			cases: []OutputTestCase{
				{
					name:               "Standard output",
					writer:             &StandardOutput{},
					expectedOutputPath: []string{filepath.Join(testReviewCommentDir, "review_comment_fallback_standard.md")},
				},
				{
					name:               "Simplified output",
					writer:             &SimplifiedOutput{},
					expectedOutputPath: []string{filepath.Join(testReviewCommentDir, "review_comment_fallback_simplified.md")},
				},
			},
		},
	}

	content := "\n" + MarkAsCodeSnippet("some review content")

	for _, tc := range testCases {
		for _, test := range tc.cases {
			t.Run(tc.name+"_"+test.name, func(t *testing.T) {
				expectedOutput := GetExpectedTestOutput(t, test)
				output := GenerateReviewCommentContent(content, test.writer)
				if tc.location != nil {
					output = GetFallbackReviewCommentContent(content, *tc.location)
				}
				assert.Equal(t, expectedOutput, output)
			})
		}
	}
}

func TestApplicableReviewContent(t *testing.T) {
	testCases := []struct {
		name                                                                             string
		issue                                                                            issues.ApplicableEvidences
		severity, finding, fullDetails, cve, cveDetails, impactedDependency, remediation string
		cases                                                                            []OutputTestCase
	}{
		{
			name: "Applicable CVE review comment content",
			issue: issues.ApplicableEvidences{
				Severity:           "Critical",
				IssueId:            "CVE-2022-29361",
				ScannerDescription: "The scanner checks whether the vulnerable `Development Server` of the `werkzeug` library is used by looking for calls to `werkzeug.serving.run_simple()`.",
				CveSummary:         "cveDetails",
				ImpactedDependency: "werkzeug:1.0.1",
				Remediation:        "some remediation",
				Evidence: formats.Evidence{
					Reason: "The vulnerable function flask.Flask.run is called",
				},
			},
			cases: []OutputTestCase{
				{
					name:               "Standard output",
					writer:             &StandardOutput{MarkdownOutput{hasInternetConnection: true}},
					expectedOutputPath: []string{filepath.Join(testReviewCommentDir, "applicable", "applicable_review_content_standard.md")},
				},
				{
					name:               "Simplified output",
					writer:             &SimplifiedOutput{MarkdownOutput{hasInternetConnection: true}},
					expectedOutputPath: []string{filepath.Join(testReviewCommentDir, "applicable", "applicable_review_content_simplified.md")},
				},
			},
		},
		{
			name: "No remediation and internet connection",
			issue: issues.ApplicableEvidences{
				Severity:           "Critical",
				IssueId:            "CVE-2022-29361",
				ScannerDescription: "The scanner checks whether the vulnerable `Development Server` of the `werkzeug` library is used by looking for calls to `werkzeug.serving.run_simple()`.",
				CveSummary:         "cveDetails",
				ImpactedDependency: "werkzeug:1.0.1",
				Evidence: formats.Evidence{
					Reason: "The vulnerable function flask.Flask.run is called",
				},
			},
			cases: []OutputTestCase{
				{
					name:               "Standard output",
					writer:             &StandardOutput{},
					expectedOutputPath: []string{filepath.Join(testReviewCommentDir, "applicable", "applicable_review_content_no_remediation_standard.md")},
				},
				{
					name:               "Simplified output",
					writer:             &SimplifiedOutput{},
					expectedOutputPath: []string{filepath.Join(testReviewCommentDir, "applicable", "applicable_review_content_no_remediation_simplified.md")},
				},
			},
		},
	}

	for _, tc := range testCases {
		for _, test := range tc.cases {
			t.Run(tc.name+"_"+test.name, func(t *testing.T) {
				expectedOutput := GetExpectedTestOutput(t, test)
				assert.Equal(t, expectedOutput, ApplicableCveReviewContent(tc.issue, test.writer))
			})
		}
	}
}

func TestSecretsReviewContent(t *testing.T) {
	testCases := []struct {
		name   string
		issues []formats.SourceCodeRow
		cases  []OutputTestCase
	}{
		{
			name: "Secret review comment content",
			issues: []formats.SourceCodeRow{{
				SeverityDetails: formats.SeverityDetails{Severity: "High"},
				Finding:         "Secret keys were found",
				ScannerInfo: formats.ScannerInfo{
					RuleId:                  "rule-id",
					Cwe:                     []string{"CWE-798", "CWE-799"},
					ScannerDescription:      "Scanner Description....",
					ScannerShortDescription: "Scanner Short Description",
					Origin:                  "JFrog",
				},
			}},
			cases: []OutputTestCase{
				{
					name:               "Standard output",
					writer:             &StandardOutput{MarkdownOutput{hasInternetConnection: true}},
					expectedOutputPath: []string{filepath.Join(testReviewCommentDir, "secrets", "secret_review_content_no_ca_standard.md")},
				},
				{
					name:               "Simplified output",
					writer:             &SimplifiedOutput{MarkdownOutput{hasInternetConnection: true}},
					expectedOutputPath: []string{filepath.Join(testReviewCommentDir, "secrets", "secret_review_content_no_ca_simplified.md")},
				},
			},
		},
		{
			name: "Secret review comment content with applicability status",
			issues: []formats.SourceCodeRow{{
				SeverityDetails: formats.SeverityDetails{Severity: "High"},
				Applicability:   &formats.Applicability{Status: jasutils.Active.String()},
				Finding:         "Secret keys were found",
				ScannerInfo: formats.ScannerInfo{
					RuleId:                  "rule-id",
					Cwe:                     []string{"CWE-798", "CWE-799"},
					ScannerDescription:      "Scanner Description....",
					ScannerShortDescription: "Scanner Short Description",
					Origin:                  "JFrog",
				},
			}},
			cases: []OutputTestCase{
				{
					name:               "Standard output",
					writer:             &StandardOutput{MarkdownOutput{hasInternetConnection: true}},
					expectedOutputPath: []string{filepath.Join(testReviewCommentDir, "secrets", "secret_review_content_standard.md")},
				},
				{
					name:               "Simplified output",
					writer:             &SimplifiedOutput{MarkdownOutput{hasInternetConnection: true}},
					expectedOutputPath: []string{filepath.Join(testReviewCommentDir, "secrets", "secret_review_content_simplified.md")},
				},
			},
		},
		{
			name: "Secrets violation review comment content with applicability status",
			issues: []formats.SourceCodeRow{
				{
					SeverityDetails: formats.SeverityDetails{Severity: "High"},
					Applicability:   &formats.Applicability{Status: jasutils.Active.String()},
					Finding:         "Secret keys were found",
					ScannerInfo: formats.ScannerInfo{
						RuleId:                  "rule-id",
						Cwe:                     []string{"CWE-798", "CWE-799"},
						ScannerDescription:      "Scanner Description....",
						ScannerShortDescription: "Scanner Short Description",
						Origin:                  "JFrog",
					},
					ViolationContext: formats.ViolationContext{
						Watch:    "jas-watch",
						IssueId:  "secret-violation-id",
						Policies: []string{"policy1"},
					},
				},
				{
					SeverityDetails: formats.SeverityDetails{Severity: "Critical"},
					Applicability:   &formats.Applicability{Status: jasutils.Inactive.String()},
					Finding:         "Secret keys were found",
					ScannerInfo: formats.ScannerInfo{
						RuleId:                  "rule-id",
						Cwe:                     []string{"CWE-798", "CWE-799"},
						ScannerDescription:      "Scanner Description....",
						ScannerShortDescription: "Scanner Short Description",
						Origin:                  "JFrog",
					},
					ViolationContext: formats.ViolationContext{
						Watch:    "jas-watch2",
						IssueId:  "secret-violation-id-2",
						Policies: []string{"policy1", "policy2"},
					},
				},
			},
			cases: []OutputTestCase{
				{
					name:               "Standard output",
					writer:             &StandardOutput{MarkdownOutput{hasInternetConnection: true}},
					expectedOutputPath: []string{filepath.Join(testReviewCommentDir, "secrets", "secret_violation_review_content_standard.md")},
				},
				{
					name:               "Simplified output",
					writer:             &SimplifiedOutput{MarkdownOutput{hasInternetConnection: true}},
					expectedOutputPath: []string{filepath.Join(testReviewCommentDir, "secrets", "secret_violation_review_content_simplified.md")},
				},
			},
		},
	}

	for _, tc := range testCases {
		for _, test := range tc.cases {
			t.Run(tc.name+"_"+test.name, func(t *testing.T) {
				expectedOutput := GetExpectedTestOutput(t, test)
				violations := false
				for _, issue := range tc.issues {
					if issue.Watch != "" {
						violations = true
						break
					}
				}
				assert.Equal(t, expectedOutput, SecretReviewContent(violations, test.writer, tc.issues...))
			})
		}
	}
}

func TestIacReviewContent(t *testing.T) {
	testCases := []struct {
		name   string
		issues []formats.SourceCodeRow
		cases  []OutputTestCase
	}{
		{
			name: "Iac review comment content",
			issues: []formats.SourceCodeRow{{
				SeverityDetails: formats.SeverityDetails{Severity: "Medium"},
				Finding:         "Missing auto upgrade was detected",
				ScannerInfo: formats.ScannerInfo{
					RuleId:                  "rule-id",
					ScannerDescription:      "Scanner Description....",
					ScannerShortDescription: "Scanner Short Description",
				},
			}},
			cases: []OutputTestCase{
				{
					name:               "Standard output",
					writer:             &StandardOutput{MarkdownOutput{hasInternetConnection: true}},
					expectedOutputPath: []string{filepath.Join(testReviewCommentDir, "iac", "iac_review_content_standard.md")},
				},
				{
					name:               "Simplified output",
					writer:             &SimplifiedOutput{MarkdownOutput{hasInternetConnection: true}},
					expectedOutputPath: []string{filepath.Join(testReviewCommentDir, "iac", "iac_review_content_simplified.md")},
				},
			},
		},
		{
			name: "Iac violation review comment content",
			issues: []formats.SourceCodeRow{{
				SeverityDetails: formats.SeverityDetails{Severity: "Medium"},
				Finding:         "Missing auto upgrade was detected",
				ScannerInfo: formats.ScannerInfo{
					RuleId:                  "rule-id",
					ScannerDescription:      "Scanner Description....",
					ScannerShortDescription: "Scanner Short Description",
				},
				ViolationContext: formats.ViolationContext{
					IssueId:  "iac-violation-id",
					Watch:    "jas-watch",
					Policies: []string{"policy1", "policy2"},
				},
			}},
			cases: []OutputTestCase{
				{
					name:               "Standard output",
					writer:             &StandardOutput{MarkdownOutput{hasInternetConnection: true}},
					expectedOutputPath: []string{filepath.Join(testReviewCommentDir, "iac", "iac_violation_review_content_standard.md")},
				},
				{
					name:               "Simplified output",
					writer:             &SimplifiedOutput{MarkdownOutput{hasInternetConnection: true}},
					expectedOutputPath: []string{filepath.Join(testReviewCommentDir, "iac", "iac_violation_review_content_simplified.md")},
				},
			},
		},
	}

	for _, tc := range testCases {
		for _, test := range tc.cases {
			t.Run(tc.name+"_"+test.name, func(t *testing.T) {
				expectedOutput := GetExpectedTestOutput(t, test)
				violations := false
				for _, issue := range tc.issues {
					if issue.Watch != "" {
						violations = true
						break
					}
				}
				assert.Equal(t, expectedOutput, IacReviewContent(violations, test.writer, tc.issues...))
			})
		}
	}
}

func TestSastReviewContent(t *testing.T) {
	testCases := []struct {
		name   string
		issues []formats.SourceCodeRow
		cases  []OutputTestCase
	}{
		{
			name: "No code flows (no internet connection)",
			issues: []formats.SourceCodeRow{{
				SeverityDetails: formats.SeverityDetails{Severity: "Low"},
				Finding:         "Found a Use of Insecure Random",
				ScannerInfo: formats.ScannerInfo{
					RuleId:                  "js-insecure-random",
					Cwe:                     []string{"CWE-798", "CWE-799"},
					ScannerDescription:      "Scanner Description....",
					ScannerShortDescription: "Use of Insecure Random",
				},
			}},
			cases: []OutputTestCase{
				{
					name:               "Standard output",
					writer:             &StandardOutput{},
					expectedOutputPath: []string{filepath.Join(testReviewCommentDir, "sast", "sast_review_content_no_code_flow_standard.md")},
				},
				{
					name:               "Simplified output",
					writer:             &SimplifiedOutput{},
					expectedOutputPath: []string{filepath.Join(testReviewCommentDir, "sast", "sast_review_content_no_code_flow_simplified.md")},
				},
			},
		},
		{
			name: "Sast review comment content",
			issues: []formats.SourceCodeRow{{
				SeverityDetails: formats.SeverityDetails{Severity: "Low"},
				Finding:         "Found a Use of Insecure Random",
				ScannerInfo: formats.ScannerInfo{
					RuleId:                  "js-insecure-random",
					Cwe:                     []string{"CWE-798", "CWE-799"},
					ScannerDescription:      "Scanner Description....",
					ScannerShortDescription: "Use of Insecure Random",
				},
				CodeFlow: [][]formats.Location{
					{
						{
							File:        "file2",
							StartLine:   1,
							StartColumn: 2,
							EndLine:     3,
							EndColumn:   4,
							Snippet:     "other-snippet",
						},
						{
							File:        "file",
							StartLine:   0,
							StartColumn: 0,
							EndLine:     0,
							EndColumn:   0,
							Snippet:     "snippet",
						},
					},
					{
						{
							File:        "file",
							StartLine:   10,
							StartColumn: 20,
							EndLine:     10,
							EndColumn:   30,
							Snippet:     "a-snippet",
						},
						{
							File:        "file",
							StartLine:   0,
							StartColumn: 0,
							EndLine:     0,
							EndColumn:   0,
							Snippet:     "snippet",
						},
					},
				},
			}},
			cases: []OutputTestCase{
				{
					name:               "Standard output",
					writer:             &StandardOutput{MarkdownOutput{hasInternetConnection: true}},
					expectedOutputPath: []string{filepath.Join(testReviewCommentDir, "sast", "sast_review_content_standard.md")},
				},
				{
					name:               "Simplified output",
					writer:             &SimplifiedOutput{MarkdownOutput{hasInternetConnection: true}},
					expectedOutputPath: []string{filepath.Join(testReviewCommentDir, "sast", "sast_review_content_simplified.md")},
				},
			},
		},
		{
			name: "Sast violation review comment content",
			issues: []formats.SourceCodeRow{
				{
					SeverityDetails: formats.SeverityDetails{Severity: "Low"},
					Finding:         "Found a Use of Insecure Random",
					ScannerInfo: formats.ScannerInfo{
						RuleId:                  "js-insecure-random",
						Cwe:                     []string{"CWE-798", "CWE-799"},
						ScannerDescription:      "Scanner Description....",
						ScannerShortDescription: "Use of Insecure Random",
					},
					ViolationContext: formats.ViolationContext{
						IssueId:  "sast-violation-id",
						Watch:    "jas-watch",
						Policies: []string{"policy1", "policy2"},
					},
					CodeFlow: [][]formats.Location{
						{
							{
								File:        "file2",
								StartLine:   1,
								StartColumn: 2,
								EndLine:     3,
								EndColumn:   4,
								Snippet:     "other-snippet",
							},
							{
								File:        "file",
								StartLine:   0,
								StartColumn: 0,
								EndLine:     0,
								EndColumn:   0,
								Snippet:     "snippet",
							},
						},
						{
							{
								File:        "file",
								StartLine:   10,
								StartColumn: 20,
								EndLine:     10,
								EndColumn:   30,
								Snippet:     "a-snippet",
							},
							{
								File:        "file",
								StartLine:   0,
								StartColumn: 0,
								EndLine:     0,
								EndColumn:   0,
								Snippet:     "snippet",
							},
						},
					},
				},
				{
					SeverityDetails: formats.SeverityDetails{Severity: "High"},
					Finding:         "Found a Use of Insecure Random",
					ScannerInfo: formats.ScannerInfo{
						RuleId:                  "js-insecure-random",
						Cwe:                     []string{"CWE-798", "CWE-799"},
						ScannerDescription:      "Scanner Description....",
						ScannerShortDescription: "Use of Insecure Random",
					},
					ViolationContext: formats.ViolationContext{
						IssueId:  "sast-violation-id-2",
						Watch:    "jas-watch2",
						Policies: []string{"policy3"},
					},
				},
				{
					SeverityDetails: formats.SeverityDetails{Severity: "High"},
					Finding:         "Found An Express Not Using Helmet",
					ScannerInfo: formats.ScannerInfo{
						RuleId:                  "js-express-without-helmet",
						ScannerDescription:      "Scanner Description....",
						ScannerShortDescription: "Express Not Using Helmet",
					},
					ViolationContext: formats.ViolationContext{
						IssueId:  "sast-violation-id-3",
						Watch:    "jas-watch2",
						Policies: []string{"policy3"},
					},
				},
			},
			cases: []OutputTestCase{
				{
					name:               "Standard output",
					writer:             &StandardOutput{MarkdownOutput{hasInternetConnection: true}},
					expectedOutputPath: []string{filepath.Join(testReviewCommentDir, "sast", "sast_violation_review_content_standard.md")},
				},
				{
					name:               "Simplified output",
					writer:             &SimplifiedOutput{MarkdownOutput{hasInternetConnection: true}},
					expectedOutputPath: []string{filepath.Join(testReviewCommentDir, "sast", "sast_violation_review_content_simplified.md")},
				},
			},
		},
	}

	for _, tc := range testCases {
		for _, test := range tc.cases {
			t.Run(tc.name+"_"+test.name, func(t *testing.T) {
				expectedOutput := GetExpectedTestOutput(t, test)
				violations := false
				for _, issue := range tc.issues {
					if issue.Watch != "" {
						violations = true
						break
					}
				}
				assert.Equal(t, expectedOutput, SastReviewContent(violations, test.writer, tc.issues...))
			})
		}
	}
}
