package outputwriter

import (
	"path/filepath"
	"strconv"
	"testing"

	"github.com/jfrog/froggit-go/vcsutils"
	"github.com/jfrog/jfrog-cli-security/formats"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/stretchr/testify/assert"
)

func TestIsFrogbotSummaryComment(t *testing.T) {
	testCases := []struct {
		name    string
		comment string
		cases   []OutputTestCase
	}{
		{
			name:    "No Summary comment",
			comment: "This comment is unrelated to Frogbot",
			cases: []OutputTestCase{
				{
					name:           "Standard output (PR)",
					writer:         &StandardOutput{},
					expectedOutput: "false",
				},
				{
					name:           "Standard output (MR)",
					writer:         &StandardOutput{MarkdownOutput{vcsProvider: vcsutils.GitLab}},
					expectedOutput: "false",
				},
				{
					name:           "Simplified output",
					writer:         &SimplifiedOutput{},
					expectedOutput: "false",
				},
			},
		},
		{
			name:    "No Vulnerability PR",
			comment: "This is a comment with the " + GetBanner(NoVulnerabilityPrBannerSource) + " icon",
			cases: []OutputTestCase{
				{
					name:           "Standard output (PR)",
					writer:         &StandardOutput{},
					expectedOutput: "true",
				},
				{
					name:           "Standard output (MR)",
					writer:         &StandardOutput{MarkdownOutput{vcsProvider: vcsutils.GitLab}},
					expectedOutput: "false",
				},
				{
					name:           "Simplified output",
					writer:         &SimplifiedOutput{},
					expectedOutput: "true",
				},
			},
		},
		{
			name:    "No Vulnerability MR",
			comment: "This is a comment with the " + GetBanner(NoVulnerabilityMrBannerSource) + " icon",
			cases: []OutputTestCase{
				{
					name:           "Standard output (PR)",
					writer:         &StandardOutput{},
					expectedOutput: "false",
				},
				{
					name:           "Standard output (MR)",
					writer:         &StandardOutput{MarkdownOutput{vcsProvider: vcsutils.GitLab}},
					expectedOutput: "true",
				},
				{
					name:           "Simplified output",
					writer:         &SimplifiedOutput{},
					expectedOutput: "false",
				},
			},
		},
		{
			name:    "No Vulnerability simplified",
			comment: "This is a comment with the " + MarkAsBold(GetSimplifiedTitle(NoVulnerabilityPrBannerSource)) + " icon",
			cases: []OutputTestCase{
				{
					name:           "Standard output (PR)",
					writer:         &StandardOutput{},
					expectedOutput: "true",
				},
				{
					name:           "Standard output (MR)",
					writer:         &StandardOutput{MarkdownOutput{vcsProvider: vcsutils.GitLab}},
					expectedOutput: "false",
				},
				{
					name:           "Simplified output",
					writer:         &SimplifiedOutput{},
					expectedOutput: "true",
				},
			},
		},
		{
			name:    "Vulnerability PR",
			comment: "This is a comment with the " + GetBanner(VulnerabilitiesPrBannerSource) + " icon",
			cases: []OutputTestCase{
				{
					name:           "Standard output (PR)",
					writer:         &StandardOutput{},
					expectedOutput: "true",
				},
				{
					name:           "Standard output (MR)",
					writer:         &StandardOutput{MarkdownOutput{vcsProvider: vcsutils.GitLab}},
					expectedOutput: "false",
				},
				{
					name:           "Simplified output",
					writer:         &SimplifiedOutput{},
					expectedOutput: "true",
				},
			},
		},
		{
			name:    "Vulnerability MR",
			comment: "This is a comment with the " + GetBanner(VulnerabilitiesMrBannerSource) + " icon",
			cases: []OutputTestCase{
				{
					name:           "Standard output (PR)",
					writer:         &StandardOutput{},
					expectedOutput: "false",
				},
				{
					name:           "Standard output (MR)",
					writer:         &StandardOutput{MarkdownOutput{vcsProvider: vcsutils.GitLab}},
					expectedOutput: "true",
				},
				{
					name:           "Simplified output",
					writer:         &SimplifiedOutput{},
					expectedOutput: "false",
				},
			},
		},
		{
			name:    "Vulnerability simplified",
			comment: "This is a comment with the " + MarkAsBold(GetSimplifiedTitle(VulnerabilitiesPrBannerSource)) + " icon",
			cases: []OutputTestCase{
				{
					name:           "Standard output (PR)",
					writer:         &StandardOutput{},
					expectedOutput: "true",
				},
				{
					name:           "Standard output (MR)",
					writer:         &StandardOutput{MarkdownOutput{vcsProvider: vcsutils.GitLab}},
					expectedOutput: "false",
				},
				{
					name:           "Simplified output",
					writer:         &SimplifiedOutput{},
					expectedOutput: "true",
				},
			},
		},
	}
	for _, tc := range testCases {
		for _, test := range tc.cases {
			expected, err := strconv.ParseBool(GetExpectedTestOutput(t, test))
			assert.NoError(t, err)
			t.Run(tc.name+"_"+test.name, func(t *testing.T) {
				assert.Equal(t, expected, IsFrogbotSummaryComment(test.writer, tc.comment))
			})
		}
	}
}

func TestGetPRSummaryContent(t *testing.T) {
	testCases := []struct {
		name         string
		cases        []OutputTestCase
		issuesExists bool
		isComment    bool
	}{
		{
			name:         "Summary comment No issues found",
			issuesExists: false,
			isComment:    true,
			cases: []OutputTestCase{
				{
					name:               "Pull Request not entitled (Standard output)",
					writer:             &StandardOutput{MarkdownOutput{hasInternetConnection: true}},
					expectedOutputPath: filepath.Join(testSummaryCommentDir, "structure", "summary_comment_no_issues_pr_not_entitled.md"),
				},
				{
					name:               "Pull Request entitled (Standard output)",
					writer:             &StandardOutput{MarkdownOutput{hasInternetConnection: true, entitledForJas: true}},
					expectedOutputPath: filepath.Join(testSummaryCommentDir, "structure", "summary_comment_no_issues_pr_entitled.md"),
				},
				{
					name:               "Merge Request not entitled (Standard output)",
					writer:             &StandardOutput{MarkdownOutput{hasInternetConnection: true, vcsProvider: vcsutils.GitLab}},
					expectedOutputPath: filepath.Join(testSummaryCommentDir, "structure", "summary_comment_no_issues_mr_not_entitled.md"),
				},
				{
					name:               "Merge Request entitled (Standard output)",
					writer:             &StandardOutput{MarkdownOutput{hasInternetConnection: true, vcsProvider: vcsutils.GitLab, entitledForJas: true}},
					expectedOutputPath: filepath.Join(testSummaryCommentDir, "structure", "summary_comment_no_issues_mr_entitled.md"),
				},
				{
					name:               "Simplified output not entitled",
					writer:             &SimplifiedOutput{MarkdownOutput{hasInternetConnection: true}},
					expectedOutputPath: filepath.Join(testSummaryCommentDir, "structure", "summary_comment_no_issues_simplified_not_entitled.md"),
				},
				{
					name:               "Simplified output entitled",
					writer:             &SimplifiedOutput{MarkdownOutput{hasInternetConnection: true, entitledForJas: true}},
					expectedOutputPath: filepath.Join(testSummaryCommentDir, "structure", "summary_comment_no_issues_simplified_entitled.md"),
				},
				{
					name:               "Pull request not entitled custom title (Standard output)",
					writer:             &StandardOutput{MarkdownOutput{hasInternetConnection: true, pullRequestCommentTitle: "Custom title"}},
					expectedOutputPath: filepath.Join(testSummaryCommentDir, "structure", "summary_comment_no_issues_pr_not_entitled_with_title.md"),
				},
				{
					name:               "Pull Request not entitled custom title avoid extra messages (Standard output)",
					writer:             &StandardOutput{MarkdownOutput{hasInternetConnection: true, pullRequestCommentTitle: "Custom title", avoidExtraMessages: true}},
					expectedOutputPath: filepath.Join(testSummaryCommentDir, "structure", "summary_comment_no_issues_pr_entitled_with_title.md"),
				},
				{
					name:               "Pull request not entitled custom title (Simplified output)",
					writer:             &SimplifiedOutput{MarkdownOutput{hasInternetConnection: true, pullRequestCommentTitle: "Custom title"}},
					expectedOutputPath: filepath.Join(testSummaryCommentDir, "structure", "summary_comment_no_issues_simplified_not_entitled_with_title.md"),
				},
				{
					name:               "Merge Request not entitled avoid extra messages (Standard output)",
					writer:             &StandardOutput{MarkdownOutput{hasInternetConnection: true, vcsProvider: vcsutils.GitLab, avoidExtraMessages: true}},
					expectedOutputPath: filepath.Join(testSummaryCommentDir, "structure", "summary_comment_no_issues_mr_entitled.md"),
				},
			},
		},
		{
			name:         "Summary comment Found issues",
			issuesExists: true,
			isComment:    true,
			cases: []OutputTestCase{
				{
					name:               "Pull Request not entitled (Standard output)",
					writer:             &StandardOutput{MarkdownOutput{hasInternetConnection: true}},
					expectedOutputPath: filepath.Join(testSummaryCommentDir, "structure", "summary_comment_issues_pr_not_entitled.md"),
				},
				{
					name:               "Pull Request entitled (Standard output)",
					writer:             &StandardOutput{MarkdownOutput{hasInternetConnection: true, entitledForJas: true}},
					expectedOutputPath: filepath.Join(testSummaryCommentDir, "structure", "summary_comment_issues_pr_entitled.md"),
				},
				{
					name:               "Merge Request not entitled (Standard output)",
					writer:             &StandardOutput{MarkdownOutput{hasInternetConnection: true, vcsProvider: vcsutils.GitLab}},
					expectedOutputPath: filepath.Join(testSummaryCommentDir, "structure", "summary_comment_issues_mr_not_entitled.md"),
				},
				{
					name:               "Merge Request entitled (Standard output)",
					writer:             &StandardOutput{MarkdownOutput{hasInternetConnection: true, vcsProvider: vcsutils.GitLab, entitledForJas: true}},
					expectedOutputPath: filepath.Join(testSummaryCommentDir, "structure", "summary_comment_issues_mr_entitled.md"),
				},
				{
					name:               "Simplified output not entitled",
					writer:             &SimplifiedOutput{MarkdownOutput{hasInternetConnection: true}},
					expectedOutputPath: filepath.Join(testSummaryCommentDir, "structure", "summary_comment_issues_simplified_not_entitled.md"),
				},
				{
					name:               "Pull Request not entitled avoid extra messages (Standard output)",
					writer:             &StandardOutput{MarkdownOutput{hasInternetConnection: true, avoidExtraMessages: true}},
					expectedOutputPath: filepath.Join(testSummaryCommentDir, "structure", "summary_comment_issues_pr_entitled.md"),
				},
				{
					name:               "Simplified output not entitled avoid extra messages",
					writer:             &SimplifiedOutput{MarkdownOutput{hasInternetConnection: true, avoidExtraMessages: true}},
					expectedOutputPath: filepath.Join(testSummaryCommentDir, "structure", "summary_comment_issues_simplified_entitled.md"),
				},
				{
					name:               "Simplified output entitled",
					writer:             &SimplifiedOutput{MarkdownOutput{hasInternetConnection: true, entitledForJas: true}},
					expectedOutputPath: filepath.Join(testSummaryCommentDir, "structure", "summary_comment_issues_simplified_entitled.md"),
				},
				{
					name:               "Merge Request entitled custom title (Standard output)",
					writer:             &StandardOutput{MarkdownOutput{hasInternetConnection: true, vcsProvider: vcsutils.GitLab, entitledForJas: true, pullRequestCommentTitle: "Custom title"}},
					expectedOutputPath: filepath.Join(testSummaryCommentDir, "structure", "summary_comment_issues_mr_entitled_with_title.md"),
				},
				{
					name:               "Pull Request not entitled custom title (Standard output)",
					writer:             &StandardOutput{MarkdownOutput{hasInternetConnection: true, pullRequestCommentTitle: "Custom title"}},
					expectedOutputPath: filepath.Join(testSummaryCommentDir, "structure", "summary_comment_issues_pr_not_entitled_with_title.md"),
				},
				{
					name:               "Pull request entitled custom title (Simplified output)",
					writer:             &SimplifiedOutput{MarkdownOutput{hasInternetConnection: true, entitledForJas: true, pullRequestCommentTitle: "Custom title"}},
					expectedOutputPath: filepath.Join(testSummaryCommentDir, "structure", "summary_comment_issues_simplified_entitled_with_title.md"),
				},
			},
		},
		{
			name:         "Frogbot Fix issues details content",
			issuesExists: true,
			isComment:    false,
			cases: []OutputTestCase{
				{
					name:               "Pull Request not entitled (Standard output)",
					writer:             &StandardOutput{MarkdownOutput{hasInternetConnection: true}},
					expectedOutputPath: filepath.Join(testSummaryCommentDir, "structure", "fix_pr_not_entitled.md"),
				},
				{
					name:               "Pull Request entitled (Standard output)",
					writer:             &StandardOutput{MarkdownOutput{hasInternetConnection: true, entitledForJas: true}},
					expectedOutputPath: filepath.Join(testSummaryCommentDir, "structure", "fix_pr_entitled.md"),
				},
				{
					name:               "Merge Request not entitled (Standard output)",
					writer:             &StandardOutput{MarkdownOutput{hasInternetConnection: true, vcsProvider: vcsutils.GitLab}},
					expectedOutputPath: filepath.Join(testSummaryCommentDir, "structure", "fix_mr_not_entitled.md"),
				},
				{
					name:               "Merge Request entitled (Standard output)",
					writer:             &StandardOutput{MarkdownOutput{hasInternetConnection: true, vcsProvider: vcsutils.GitLab, entitledForJas: true}},
					expectedOutputPath: filepath.Join(testSummaryCommentDir, "structure", "fix_mr_entitled.md"),
				},
				{
					name:               "Simplified output not entitled",
					writer:             &SimplifiedOutput{MarkdownOutput{hasInternetConnection: true}},
					expectedOutputPath: filepath.Join(testSummaryCommentDir, "structure", "fix_simplified_not_entitled.md"),
				},
				{
					name:               "Simplified output not entitled ",
					writer:             &SimplifiedOutput{MarkdownOutput{hasInternetConnection: true}},
					expectedOutputPath: filepath.Join(testSummaryCommentDir, "structure", "fix_simplified_not_entitled.md"),
				},
				{
					name:               "Simplified output entitled avoid extra messages",
					writer:             &SimplifiedOutput{MarkdownOutput{hasInternetConnection: true, avoidExtraMessages: true}},
					expectedOutputPath: filepath.Join(testSummaryCommentDir, "structure", "fix_simplified_entitled.md"),
				},
			},
		},
	}

	content := "\n" + MarkAsCodeSnippet("some content")

	for _, tc := range testCases {
		for _, test := range tc.cases {
			t.Run(tc.name+"_"+test.name, func(t *testing.T) {
				expectedOutput := GetExpectedTestOutput(t, test)
				output := GetPRSummaryContent(content, tc.issuesExists, tc.isComment, test.writer)
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
					expectedOutput: "",
				},
				{
					name:           "Simplified output",
					writer:         &SimplifiedOutput{},
					expectedOutput: "",
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
					expectedOutputPath: filepath.Join(testSummaryCommentDir, "vulnerabilities", "one_vulnerability_standard.md"),
				},
				{
					name:               "Simplified output",
					writer:             &SimplifiedOutput{},
					expectedOutputPath: filepath.Join(testSummaryCommentDir, "vulnerabilities", "one_vulnerability_simplified.md"),
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
					Cves:          []formats.CveRow{{Id: "CVE-2022-26652"}},
				},
			},
			cases: []OutputTestCase{
				{
					name:               "Standard output",
					writer:             &StandardOutput{},
					expectedOutputPath: filepath.Join(testSummaryCommentDir, "vulnerabilities", "one_vulnerability_no_details_standard.md"),
				},
				{
					name:               "Simplified output",
					writer:             &SimplifiedOutput{},
					expectedOutputPath: filepath.Join(testSummaryCommentDir, "vulnerabilities", "one_vulnerability_no_details_simplified.md"),
				},
			},
		},
		{
			name: "multiple Vulnerabilities with Contextual Analysis",
			vulnerabilities: []formats.VulnerabilityOrViolationRow{
				{
					ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
						SeverityDetails:           formats.SeverityDetails{Severity: "Critical", SeverityNumValue: utils.GetSeverity("Critical", utils.NotApplicable).SeverityNumValue},
						ImpactedDependencyName:    "impacted",
						ImpactedDependencyVersion: "3.0.0",
						Components: []formats.ComponentRow{
							{Name: "dep1", Version: "1.0.0"},
							{Name: "dep2", Version: "2.0.0"},
						},
					},
					Applicable:    "Not Applicable",
					FixedVersions: []string{"4.0.0", "5.0.0"},
					Cves:          []formats.CveRow{{Id: "CVE-1111-11111", Applicability: &formats.Applicability{Status: "Not Applicable"}}},
				},
				{
					Summary: "Summary XRAY-122345",
					ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
						SeverityDetails:           formats.SeverityDetails{Severity: "High", SeverityNumValue: utils.GetSeverity("High", utils.ApplicabilityUndetermined).SeverityNumValue},
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
					IssueId:       "XRAY-122345",
					JfrogResearchInformation: &formats.JfrogResearchInformation{
						Remediation: "some remediation",
					},
					Cves: []formats.CveRow{{}},
				},
				{
					ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
						SeverityDetails:           formats.SeverityDetails{Severity: "Medium", SeverityNumValue: utils.GetSeverity("Medium", utils.Applicable).SeverityNumValue},
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
						SeverityDetails:           formats.SeverityDetails{Severity: "Low", SeverityNumValue: utils.GetSeverity("Low", utils.ApplicabilityUndetermined).SeverityNumValue},
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
					Cves:       []formats.CveRow{},
				},
			},
			cases: []OutputTestCase{
				{
					name:               "Standard output",
					writer:             &StandardOutput{MarkdownOutput{showCaColumn: true}},
					expectedOutputPath: filepath.Join(testSummaryCommentDir, "vulnerabilities", "vulnerabilities_standard.md"),
				},
				{
					name:               "Simplified output",
					writer:             &SimplifiedOutput{MarkdownOutput{showCaColumn: true}},
					expectedOutputPath: filepath.Join(testSummaryCommentDir, "vulnerabilities", "vulnerabilities_simplified.md"),
				},
			},
		},
	}
	for _, tc := range testCases {
		for _, test := range tc.cases {
			t.Run(tc.name+"_"+test.name, func(t *testing.T) {
				assert.Equal(t, GetExpectedTestOutput(t, test), VulnerabilitiesContent(tc.vulnerabilities, test.writer))
			})
		}
	}
}

func TestLicensesContent(t *testing.T) {
	testCases := []struct {
		name     string
		licenses []formats.LicenseRow
		cases    []OutputTestCase
	}{
		{
			name:     "No license violations",
			licenses: []formats.LicenseRow{},
			cases: []OutputTestCase{
				{
					name:           "Standard output",
					writer:         &StandardOutput{},
					expectedOutput: "",
				},
				{
					name:           "Simplified output",
					writer:         &SimplifiedOutput{},
					expectedOutput: "",
				},
			},
		},
		{
			name: "License violations",
			licenses: []formats.LicenseRow{
				{
					LicenseKey: "License1",
					ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
						Components:                []formats.ComponentRow{{Name: "Comp1", Version: "1.0"}},
						ImpactedDependencyName:    "Dep1",
						ImpactedDependencyVersion: "2.0",
					},
				},
				{
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
					},
				},
			},
			cases: []OutputTestCase{
				{
					name:               "Standard output",
					writer:             &StandardOutput{},
					expectedOutputPath: filepath.Join(testSummaryCommentDir, "license", "license_violation_standard.md"),
				},
				{
					name:               "Simplified output",
					writer:             &SimplifiedOutput{},
					expectedOutputPath: filepath.Join(testSummaryCommentDir, "license", "license_violation_simplified.md"),
				},
			},
		},
	}
	for _, tc := range testCases {
		for _, test := range tc.cases {
			t.Run(tc.name+"_"+test.name, func(t *testing.T) {
				assert.Equal(t, GetExpectedTestOutput(t, test), LicensesContent(tc.licenses, test.writer))
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
			assert.Equal(t, tc.expectedOutput, IsFrogbotReviewComment(tc.content))
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
					expectedOutputPath: filepath.Join(testReviewCommentDir, "review_comment_standard.md"),
				},
				{
					name:               "Simplified output",
					writer:             &SimplifiedOutput{},
					expectedOutputPath: filepath.Join(testReviewCommentDir, "review_comment_simplified.md"),
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
					expectedOutputPath: filepath.Join(testReviewCommentDir, "review_comment_fallback_standard.md"),
				},
				{
					name:               "Simplified output",
					writer:             &SimplifiedOutput{},
					expectedOutputPath: filepath.Join(testReviewCommentDir, "review_comment_fallback_simplified.md"),
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
					output = GetFallbackReviewCommentContent(content, *tc.location, test.writer)
				}
				assert.Equal(t, expectedOutput, output)
			})
		}
	}
}

func TestApplicableReviewContent(t *testing.T) {
	testCases := []struct {
		name                                                                             string
		severity, finding, fullDetails, cve, cveDetails, impactedDependency, remediation string
		cases                                                                            []OutputTestCase
	}{
		{
			name:               "Applicable CVE review comment content",
			severity:           "Critical",
			finding:            "The vulnerable function flask.Flask.run is called",
			fullDetails:        "The scanner checks whether the vulnerable `Development Server` of the `werkzeug` library is used by looking for calls to `werkzeug.serving.run_simple()`.",
			cve:                "CVE-2022-29361",
			cveDetails:         "cveDetails",
			impactedDependency: "werkzeug:1.0.1",
			remediation:        "some remediation",
			cases: []OutputTestCase{
				{
					name:               "Standard output",
					writer:             &StandardOutput{},
					expectedOutputPath: filepath.Join(testReviewCommentDir, "applicable", "applicable_review_content_standard.md"),
				},
				{
					name:               "Simplified output",
					writer:             &SimplifiedOutput{},
					expectedOutputPath: filepath.Join(testReviewCommentDir, "applicable", "applicable_review_content_simplified.md"),
				},
			},
		},
		{
			name:               "No remediation",
			severity:           "Critical",
			finding:            "The vulnerable function flask.Flask.run is called",
			fullDetails:        "The scanner checks whether the vulnerable `Development Server` of the `werkzeug` library is used by looking for calls to `werkzeug.serving.run_simple()`.",
			cve:                "CVE-2022-29361",
			cveDetails:         "cveDetails",
			impactedDependency: "werkzeug:1.0.1",
			cases: []OutputTestCase{
				{
					name:               "Standard output",
					writer:             &StandardOutput{},
					expectedOutputPath: filepath.Join(testReviewCommentDir, "applicable", "applicable_review_content_no_remediation_standard.md"),
				},
				{
					name:               "Simplified output",
					writer:             &SimplifiedOutput{},
					expectedOutputPath: filepath.Join(testReviewCommentDir, "applicable", "applicable_review_content_no_remediation_simplified.md"),
				},
			},
		},
	}

	for _, tc := range testCases {
		for _, test := range tc.cases {
			t.Run(tc.name+"_"+test.name, func(t *testing.T) {
				expectedOutput := GetExpectedTestOutput(t, test)
				assert.Equal(t, expectedOutput, ApplicableCveReviewContent(tc.severity, tc.finding, tc.fullDetails, tc.cve, tc.cveDetails, tc.impactedDependency, tc.remediation, test.writer))
			})
		}
	}
}

func TestIacReviewContent(t *testing.T) {
	testCases := []struct {
		name                           string
		severity, finding, fullDetails string
		cases                          []OutputTestCase
	}{
		{
			name:        "Iac review comment content",
			severity:    "Medium",
			finding:     "Missing auto upgrade was detected",
			fullDetails: "Resource `google_container_node_pool` should have `management.auto_upgrade=true`\n\nVulnerable example - \n```\nresource \"google_container_node_pool\" \"vulnerable_example\" {\n    management {\n     auto_upgrade = false\n   }\n}\n```\n",
			cases: []OutputTestCase{
				{
					name:               "Standard output",
					writer:             &StandardOutput{},
					expectedOutputPath: filepath.Join(testReviewCommentDir, "iac", "iac_review_content_standard.md"),
				},
				{
					name:               "Simplified output",
					writer:             &SimplifiedOutput{},
					expectedOutputPath: filepath.Join(testReviewCommentDir, "iac", "iac_review_content_simplified.md"),
				},
			},
		},
	}

	for _, tc := range testCases {
		for _, test := range tc.cases {
			t.Run(tc.name+"_"+test.name, func(t *testing.T) {
				expectedOutput := GetExpectedTestOutput(t, test)
				assert.Equal(t, expectedOutput, IacReviewContent(tc.severity, tc.finding, tc.fullDetails, test.writer))
			})
		}
	}
}

func TestSastReviewContent(t *testing.T) {
	testCases := []struct {
		name        string
		severity    string
		finding     string
		fullDetails string
		codeFlows   [][]formats.Location
		cases       []OutputTestCase
	}{
		{
			name:        "Sast review comment content",
			severity:    "Low",
			finding:     "Stack Trace Exposure",
			fullDetails: "\n### Overview\nStack trace exposure is a type of security vulnerability that occurs when a program reveals\nsensitive information, such as the names and locations of internal files and variables,\nin error messages or other diagnostic output. This can happen when a program crashes or\nencounters an error, and the stack trace (a record of the program's call stack at the time\nof the error) is included in the output.",
			codeFlows: [][]formats.Location{
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
			cases: []OutputTestCase{
				{
					name:               "Standard output",
					writer:             &StandardOutput{},
					expectedOutputPath: filepath.Join(testReviewCommentDir, "sast", "sast_review_content_standard.md"),
				},
				{
					name:               "Simplified output",
					writer:             &SimplifiedOutput{},
					expectedOutputPath: filepath.Join(testReviewCommentDir, "sast", "sast_review_content_simplified.md"),
				},
			},
		},
		{
			name:        "No code flows",
			severity:    "Low",
			finding:     "Stack Trace Exposure",
			fullDetails: "\n### Overview\nStack trace exposure is a type of security vulnerability that occurs when a program reveals\nsensitive information, such as the names and locations of internal files and variables,\nin error messages or other diagnostic output. This can happen when a program crashes or\nencounters an error, and the stack trace (a record of the program's call stack at the time\nof the error) is included in the output.",
			cases: []OutputTestCase{
				{
					name:               "Standard output",
					writer:             &StandardOutput{},
					expectedOutputPath: filepath.Join(testReviewCommentDir, "sast", "sast_review_content_no_code_flow_standard.md"),
				},
				{
					name:               "Simplified output",
					writer:             &SimplifiedOutput{},
					expectedOutputPath: filepath.Join(testReviewCommentDir, "sast", "sast_review_content_no_code_flow_simplified.md"),
				},
			},
		},
	}

	for _, tc := range testCases {
		for _, test := range tc.cases {
			t.Run(tc.name+"_"+test.name, func(t *testing.T) {
				expectedOutput := GetExpectedTestOutput(t, test)
				assert.Equal(t, expectedOutput, SastReviewContent(tc.severity, tc.finding, tc.fullDetails, tc.codeFlows, test.writer))
			})
		}
	}
}
