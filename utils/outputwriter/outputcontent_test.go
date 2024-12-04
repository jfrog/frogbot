package outputwriter

import (
	"path/filepath"
	"testing"

	"github.com/jfrog/froggit-go/vcsutils"
	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-cli-security/utils/severityutils"
	"github.com/stretchr/testify/assert"
)

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
					expectedOutputPath: []string{filepath.Join(testSummaryCommentDir, "structure", "summary_comment_no_issues_pr_not_entitled.md")},
				},
				{
					name:               "Pull Request entitled (Standard output)",
					writer:             &StandardOutput{MarkdownOutput{hasInternetConnection: true, entitledForJas: true}},
					expectedOutputPath: []string{filepath.Join(testSummaryCommentDir, "structure", "summary_comment_no_issues_pr_entitled.md")},
				},
				{
					name:               "Merge Request not entitled (Standard output)",
					writer:             &StandardOutput{MarkdownOutput{hasInternetConnection: true, vcsProvider: vcsutils.GitLab}},
					expectedOutputPath: []string{filepath.Join(testSummaryCommentDir, "structure", "summary_comment_no_issues_mr_not_entitled.md")},
				},
				{
					name:               "Merge Request entitled (Standard output)",
					writer:             &StandardOutput{MarkdownOutput{hasInternetConnection: true, vcsProvider: vcsutils.GitLab, entitledForJas: true}},
					expectedOutputPath: []string{filepath.Join(testSummaryCommentDir, "structure", "summary_comment_no_issues_mr_entitled.md")},
				},
				{
					name:               "Simplified output not entitled",
					writer:             &SimplifiedOutput{MarkdownOutput{hasInternetConnection: true}},
					expectedOutputPath: []string{filepath.Join(testSummaryCommentDir, "structure", "summary_comment_no_issues_simplified_not_entitled.md")},
				},
				{
					name:               "Simplified output entitled",
					writer:             &SimplifiedOutput{MarkdownOutput{hasInternetConnection: true, entitledForJas: true}},
					expectedOutputPath: []string{filepath.Join(testSummaryCommentDir, "structure", "summary_comment_no_issues_simplified_entitled.md")},
				},
				{
					name:               "Pull request not entitled custom title (Standard output)",
					writer:             &StandardOutput{MarkdownOutput{hasInternetConnection: true, pullRequestCommentTitle: "Custom title"}},
					expectedOutputPath: []string{filepath.Join(testSummaryCommentDir, "structure", "summary_comment_no_issues_pr_not_entitled_with_title.md")},
				},
				{
					name:               "Pull Request not entitled custom title avoid extra messages (Standard output)",
					writer:             &StandardOutput{MarkdownOutput{hasInternetConnection: true, pullRequestCommentTitle: "Custom title", avoidExtraMessages: true}},
					expectedOutputPath: []string{filepath.Join(testSummaryCommentDir, "structure", "summary_comment_no_issues_pr_entitled_with_title.md")},
				},
				{
					name:               "Pull request not entitled custom title (Simplified output)",
					writer:             &SimplifiedOutput{MarkdownOutput{hasInternetConnection: true, pullRequestCommentTitle: "Custom title"}},
					expectedOutputPath: []string{filepath.Join(testSummaryCommentDir, "structure", "summary_comment_no_issues_simplified_not_entitled_with_title.md")},
				},
				{
					name:               "Merge Request not entitled avoid extra messages (Standard output)",
					writer:             &StandardOutput{MarkdownOutput{hasInternetConnection: true, vcsProvider: vcsutils.GitLab, avoidExtraMessages: true}},
					expectedOutputPath: []string{filepath.Join(testSummaryCommentDir, "structure", "summary_comment_no_issues_mr_entitled.md")},
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
					expectedOutputPath: []string{filepath.Join(testSummaryCommentDir, "structure", "summary_comment_issues_pr_not_entitled.md")},
				},
				{
					name:               "Pull Request entitled (Standard output)",
					writer:             &StandardOutput{MarkdownOutput{hasInternetConnection: true, entitledForJas: true}},
					expectedOutputPath: []string{filepath.Join(testSummaryCommentDir, "structure", "summary_comment_issues_pr_entitled.md")},
				},
				{
					name:               "Merge Request not entitled (Standard output)",
					writer:             &StandardOutput{MarkdownOutput{hasInternetConnection: true, vcsProvider: vcsutils.GitLab}},
					expectedOutputPath: []string{filepath.Join(testSummaryCommentDir, "structure", "summary_comment_issues_mr_not_entitled.md")},
				},
				{
					name:               "Merge Request entitled (Standard output)",
					writer:             &StandardOutput{MarkdownOutput{hasInternetConnection: true, vcsProvider: vcsutils.GitLab, entitledForJas: true}},
					expectedOutputPath: []string{filepath.Join(testSummaryCommentDir, "structure", "summary_comment_issues_mr_entitled.md")},
				},
				{
					name:               "Simplified output not entitled",
					writer:             &SimplifiedOutput{MarkdownOutput{hasInternetConnection: true}},
					expectedOutputPath: []string{filepath.Join(testSummaryCommentDir, "structure", "summary_comment_issues_simplified_not_entitled.md")},
				},
				{
					name:               "Pull Request not entitled avoid extra messages (Standard output)",
					writer:             &StandardOutput{MarkdownOutput{hasInternetConnection: true, avoidExtraMessages: true}},
					expectedOutputPath: []string{filepath.Join(testSummaryCommentDir, "structure", "summary_comment_issues_pr_entitled.md")},
				},
				{
					name:               "Simplified output not entitled avoid extra messages",
					writer:             &SimplifiedOutput{MarkdownOutput{hasInternetConnection: true, avoidExtraMessages: true}},
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
					name:               "Pull Request not entitled custom title (Standard output)",
					writer:             &StandardOutput{MarkdownOutput{hasInternetConnection: true, pullRequestCommentTitle: "Custom title"}},
					expectedOutputPath: []string{filepath.Join(testSummaryCommentDir, "structure", "summary_comment_issues_pr_not_entitled_with_title.md")},
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
					name:               "Pull Request not entitled (Standard output)",
					writer:             &StandardOutput{MarkdownOutput{hasInternetConnection: true}},
					expectedOutputPath: []string{filepath.Join(testSummaryCommentDir, "structure", "fix_pr_not_entitled.md")},
				},
				{
					name:               "Pull Request entitled (Standard output)",
					writer:             &StandardOutput{MarkdownOutput{hasInternetConnection: true, entitledForJas: true}},
					expectedOutputPath: []string{filepath.Join(testSummaryCommentDir, "structure", "fix_pr_entitled.md")},
				},
				{
					name:               "Merge Request not entitled (Standard output)",
					writer:             &StandardOutput{MarkdownOutput{hasInternetConnection: true, vcsProvider: vcsutils.GitLab}},
					expectedOutputPath: []string{filepath.Join(testSummaryCommentDir, "structure", "fix_mr_not_entitled.md")},
				},
				{
					name:               "Merge Request entitled (Standard output)",
					writer:             &StandardOutput{MarkdownOutput{hasInternetConnection: true, vcsProvider: vcsutils.GitLab, entitledForJas: true}},
					expectedOutputPath: []string{filepath.Join(testSummaryCommentDir, "structure", "fix_mr_entitled.md")},
				},
				{
					name:               "Simplified output not entitled",
					writer:             &SimplifiedOutput{MarkdownOutput{hasInternetConnection: true}},
					expectedOutputPath: []string{filepath.Join(testSummaryCommentDir, "structure", "fix_simplified_not_entitled.md")},
				},
				{
					name:               "Simplified output not entitled ",
					writer:             &SimplifiedOutput{MarkdownOutput{hasInternetConnection: true}},
					expectedOutputPath: []string{filepath.Join(testSummaryCommentDir, "structure", "fix_simplified_not_entitled.md")},
				},
				{
					name:               "Simplified output entitled avoid extra messages",
					writer:             &SimplifiedOutput{MarkdownOutput{hasInternetConnection: true, avoidExtraMessages: true}},
					expectedOutputPath: []string{filepath.Join(testSummaryCommentDir, "structure", "fix_simplified_entitled.md")},
				},
			},
		},
	}

	for _, tc := range testCases {
		for _, test := range tc.cases {
			t.Run(tc.name+"_"+test.name, func(t *testing.T) {
				expectedOutput := GetExpectedTestOutput(t, test)
				output := GetPRSummaryContent([]string{MarkAsCodeSnippet("some content")}, tc.issuesExists, tc.isComment, test.writer)
				assert.Len(t, output, 1)
				assert.Equal(t, expectedOutput, output[0])
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
					Cves:          []formats.CveRow{{Id: "CVE-2022-26652"}},
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
			name: "multiple Vulnerabilities with Contextual Analysis",
			vulnerabilities: []formats.VulnerabilityOrViolationRow{
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
					Cves:          []formats.CveRow{{Id: "CVE-1111-11111", Applicability: &formats.Applicability{Status: "Not Applicable"}}},
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
					IssueId:       "XRAY-122345",
					JfrogResearchInformation: &formats.JfrogResearchInformation{
						Remediation: "some remediation",
					},
					Cves: []formats.CveRow{{}},
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
					Cves:       []formats.CveRow{},
				},
			},
			cases: []OutputTestCase{
				{
					name:               "Standard output",
					writer:             &StandardOutput{MarkdownOutput{showCaColumn: true}},
					expectedOutputPath: []string{filepath.Join(testSummaryCommentDir, "vulnerabilities", "vulnerabilities_standard.md")},
				},
				{
					name:               "Simplified output",
					writer:             &SimplifiedOutput{MarkdownOutput{showCaColumn: true}},
					expectedOutputPath: []string{filepath.Join(testSummaryCommentDir, "vulnerabilities", "vulnerabilities_simplified.md")},
				},
				{
					name:   "Split Standard output",
					writer: &StandardOutput{MarkdownOutput{showCaColumn: true, descriptionSizeLimit: 1720, commentSizeLimit: 1720}},
					expectedOutputPath: []string{
						filepath.Join(testSummaryCommentDir, "vulnerabilities", "vulnerabilities_standard_split1.md"),
						filepath.Join(testSummaryCommentDir, "vulnerabilities", "vulnerabilities_standard_split2.md"),
					},
				},
				{
					name:   "Split Simplified output",
					writer: &SimplifiedOutput{MarkdownOutput{showCaColumn: true, descriptionSizeLimit: 1000, commentSizeLimit: 1000}},
					expectedOutputPath: []string{
						filepath.Join(testSummaryCommentDir, "vulnerabilities", "vulnerabilities_simplified_split1.md"),
						filepath.Join(testSummaryCommentDir, "vulnerabilities", "vulnerabilities_simplified_split2.md"),
					},
				},
			},
		},
		{
			name: "Split vulnerabilities content",
		},
	}
	for _, tc := range testCases {
		for _, test := range tc.cases {
			t.Run(tc.name+"_"+test.name, func(t *testing.T) {
				expectedOutput := GetExpectedTestCaseOutput(t, test)
				output := ConvertContentToComments(VulnerabilitiesContent(tc.vulnerabilities, test.writer), test.writer)
				assert.Len(t, output, len(expectedOutput))
				assert.ElementsMatch(t, expectedOutput, output)
			})
		}
	}
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
			name: "License violations",
			licenses: []formats.LicenseViolationRow{
				{
					LicenseRow: formats.LicenseRow{
						LicenseKey: "License1",
						ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
							Components:                []formats.ComponentRow{{Name: "Comp1", Version: "1.0"}},
							ImpactedDependencyName:    "Dep1",
							ImpactedDependencyVersion: "2.0",
							SeverityDetails: formats.SeverityDetails{
								Severity: "High",
							},
						},
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
				},
			},
			cases: []OutputTestCase{
				{
					name:               "Standard output",
					writer:             &StandardOutput{},
					expectedOutputPath: []string{filepath.Join(testSummaryCommentDir, "license", "license_violation_standard.md")},
				},
				{
					name:               "Simplified output",
					writer:             &SimplifiedOutput{},
					expectedOutputPath: []string{filepath.Join(testSummaryCommentDir, "license", "license_violation_simplified.md")},
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
					expectedOutputPath: []string{filepath.Join(testReviewCommentDir, "applicable", "applicable_review_content_standard.md")},
				},
				{
					name:               "Simplified output",
					writer:             &SimplifiedOutput{},
					expectedOutputPath: []string{filepath.Join(testReviewCommentDir, "applicable", "applicable_review_content_simplified.md")},
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
				assert.Equal(t, expectedOutput, ApplicableCveReviewContent(tc.severity, tc.finding, tc.fullDetails, tc.cve, tc.cveDetails, tc.impactedDependency, tc.remediation, test.writer))
			})
		}
	}
}

func TestSecretsReviewContent(t *testing.T) {
	testCases := []struct {
		name                                   string
		severity, finding, fullDetails, status string
		cases                                  []OutputTestCase
	}{
		{
			name:        "Secret review comment content",
			severity:    "Medium",
			finding:     "Secret keys were found",
			fullDetails: "Storing hardcoded secrets in your source code or binary artifact could lead to several risks.\n\nIf the secret is associated with a wide scope of privileges, attackers could extract it from the source code or binary artifact and use it maliciously to attack many targets. For example, if the hardcoded password gives high-privilege access to an AWS account, the attackers may be able to query/modify company-wide sensitive data without per-user authentication.\n\n## Best practices\n\nUse safe storage when storing high-privilege secrets such as passwords and tokens, for example -\n\n* ### Environment Variables\n\nEnvironment variables are set outside of the application code, and can be dynamically passed to the application only when needed, for example -\n`SECRET_VAR=MySecret ./my_application`\nThis way, `MySecret` does not have to be hardcoded into `my_application`.\n\nNote that if your entire binary artifact is published (ex. a Docker container published to Docker Hub), the value for the environment variable must not be stored in the artifact itself (ex. inside the `Dockerfile` or one of the container's files) but rather must be passed dynamically, for example in the `docker run` call as an argument.\n\n* ### Secret management services\n\nExternal vendors offer cloud-based secret management services, that provide proper access control to each secret. The given access to each secret can be dynamically modified or even revoked. Some examples include -\n\n* [Hashicorp Vault](https://www.vaultproject.io)\n* [AWS KMS](https://aws.amazon.com/kms) (Key Management Service)\n* [Google Cloud KMS](https://cloud.google.com/security-key-management)\n\n## Least-privilege principle\n\nStoring a secret in a hardcoded manner can be made safer, by making sure the secret grants the least amount of privilege as needed by the application.\nFor example - if the application needs to read a specific table from a specific database, and the secret grants access to perform this operation **only** (meaning - no access to other tables, no write access at all) then the damage from any secret leaks is mitigated.\nThat being said, it is still not recommended to store secrets in a hardcoded manner, since this type of storage does not offer any way to revoke or moderate the usage of the secret.\n",
			cases: []OutputTestCase{
				{
					name:               "Standard output",
					writer:             &StandardOutput{},
					expectedOutputPath: []string{filepath.Join(testReviewCommentDir, "secrets", "secret_review_content_no_ca_standard.md")},
				},
				{
					name:               "Simplified output",
					writer:             &SimplifiedOutput{},
					expectedOutputPath: []string{filepath.Join(testReviewCommentDir, "secrets", "secret_review_content_no_ca_simplified.md")},
				},
			},
		},
		{
			name:        "Secret review comment content with applicability status",
			severity:    "Medium",
			status:      "Active",
			finding:     "Secret keys were found",
			fullDetails: "Storing hardcoded secrets in your source code or binary artifact could lead to several risks.\n\nIf the secret is associated with a wide scope of privileges, attackers could extract it from the source code or binary artifact and use it maliciously to attack many targets. For example, if the hardcoded password gives high-privilege access to an AWS account, the attackers may be able to query/modify company-wide sensitive data without per-user authentication.\n\n## Best practices\n\nUse safe storage when storing high-privilege secrets such as passwords and tokens, for example -\n\n* ### Environment Variables\n\nEnvironment variables are set outside of the application code, and can be dynamically passed to the application only when needed, for example -\n`SECRET_VAR=MySecret ./my_application`\nThis way, `MySecret` does not have to be hardcoded into `my_application`.\n\nNote that if your entire binary artifact is published (ex. a Docker container published to Docker Hub), the value for the environment variable must not be stored in the artifact itself (ex. inside the `Dockerfile` or one of the container's files) but rather must be passed dynamically, for example in the `docker run` call as an argument.\n\n* ### Secret management services\n\nExternal vendors offer cloud-based secret management services, that provide proper access control to each secret. The given access to each secret can be dynamically modified or even revoked. Some examples include -\n\n* [Hashicorp Vault](https://www.vaultproject.io)\n* [AWS KMS](https://aws.amazon.com/kms) (Key Management Service)\n* [Google Cloud KMS](https://cloud.google.com/security-key-management)\n\n## Least-privilege principle\n\nStoring a secret in a hardcoded manner can be made safer, by making sure the secret grants the least amount of privilege as needed by the application.\nFor example - if the application needs to read a specific table from a specific database, and the secret grants access to perform this operation **only** (meaning - no access to other tables, no write access at all) then the damage from any secret leaks is mitigated.\nThat being said, it is still not recommended to store secrets in a hardcoded manner, since this type of storage does not offer any way to revoke or moderate the usage of the secret.\n",
			cases: []OutputTestCase{
				{
					name:               "Standard output",
					writer:             &StandardOutput{},
					expectedOutputPath: []string{filepath.Join(testReviewCommentDir, "secrets", "secret_review_content_standard.md")},
				},
				{
					name:               "Simplified output",
					writer:             &SimplifiedOutput{},
					expectedOutputPath: []string{filepath.Join(testReviewCommentDir, "secrets", "secret_review_content_simplified.md")},
				},
			},
		},
	}

	for _, tc := range testCases {
		for _, test := range tc.cases {
			t.Run(tc.name+"_"+test.name, func(t *testing.T) {
				expectedOutput := GetExpectedTestOutput(t, test)
				assert.Equal(t, expectedOutput, SecretReviewContent(tc.severity, "id", tc.finding, tc.fullDetails, tc.status, test.writer))
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
					expectedOutputPath: []string{filepath.Join(testReviewCommentDir, "iac", "iac_review_content_standard.md")},
				},
				{
					name:               "Simplified output",
					writer:             &SimplifiedOutput{},
					expectedOutputPath: []string{filepath.Join(testReviewCommentDir, "iac", "iac_review_content_simplified.md")},
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
					expectedOutputPath: []string{filepath.Join(testReviewCommentDir, "sast", "sast_review_content_standard.md")},
				},
				{
					name:               "Simplified output",
					writer:             &SimplifiedOutput{},
					expectedOutputPath: []string{filepath.Join(testReviewCommentDir, "sast", "sast_review_content_simplified.md")},
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
					expectedOutputPath: []string{filepath.Join(testReviewCommentDir, "sast", "sast_review_content_no_code_flow_standard.md")},
				},
				{
					name:               "Simplified output",
					writer:             &SimplifiedOutput{},
					expectedOutputPath: []string{filepath.Join(testReviewCommentDir, "sast", "sast_review_content_no_code_flow_simplified.md")},
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
