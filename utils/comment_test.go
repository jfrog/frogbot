package utils

import (
	"testing"

	"github.com/jfrog/frogbot/v2/utils/issues"
	"github.com/jfrog/frogbot/v2/utils/outputwriter"
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/stretchr/testify/assert"
)

func TestGetFrogbotReviewComments(t *testing.T) {
	testCases := []struct {
		name             string
		existingComments []vcsclient.CommentInfo
		expectedOutput   []vcsclient.CommentInfo
	}{
		{
			name: "No frogbot comments",
			existingComments: []vcsclient.CommentInfo{
				{Content: outputwriter.FrogbotTitlePrefix},
				{Content: "some comment text" + outputwriter.MarkdownComment("with hidden comment")},
				{Content: outputwriter.CommentGeneratedByFrogbot},
			},
			expectedOutput: []vcsclient.CommentInfo{},
		},
		{
			name: "With frogbot comments",
			existingComments: []vcsclient.CommentInfo{
				{Content: outputwriter.FrogbotTitlePrefix},
				{Content: outputwriter.MarkdownComment(outputwriter.ReviewCommentId) + "A Frogbot review comment"},
				{Content: "some comment text" + outputwriter.MarkdownComment("with hidden comment")},
				{Content: outputwriter.ReviewCommentId},
				{Content: outputwriter.CommentGeneratedByFrogbot},
			},
			expectedOutput: []vcsclient.CommentInfo{
				{Content: outputwriter.MarkdownComment(outputwriter.ReviewCommentId) + "A Frogbot review comment"},
				{Content: outputwriter.ReviewCommentId},
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			output := getFrogbotComments(tc.existingComments)
			assert.ElementsMatch(t, tc.expectedOutput, output)
		})
	}
}

func TestGroupSimilarJasIssues(t *testing.T) {
	testCases := []struct {
		name          string
		issues        []formats.SourceCodeRow
		groupedIssues []jasCommentIssues
	}{
		{
			name: "No issues",
		},
		{
			name: "Single issue",
			issues: []formats.SourceCodeRow{
				{
					SeverityDetails: formats.SeverityDetails{Severity: "High"},
					Location:        formats.Location{File: "file1", StartLine: 1, StartColumn: 10, EndLine: 2, EndColumn: 11, Snippet: "snippet"},
					Finding:         "finding1",
					ScannerInfo:     formats.ScannerInfo{RuleId: "rule1"},
				},
			},
			groupedIssues: []jasCommentIssues{
				{
					formats.Location{File: "file1", StartLine: 1, StartColumn: 10, EndLine: 2, EndColumn: 11, Snippet: "snippet"},
					[]formats.SourceCodeRow{
						{
							SeverityDetails: formats.SeverityDetails{Severity: "High"},
							Location:        formats.Location{File: "file1", StartLine: 1, StartColumn: 10, EndLine: 2, EndColumn: 11, Snippet: "snippet"},
							Finding:         "finding1",
							ScannerInfo:     formats.ScannerInfo{RuleId: "rule1"},
						},
					},
				},
			},
		},
		{
			name: "Multiple issues - no similar issues",
			issues: []formats.SourceCodeRow{
				{
					SeverityDetails: formats.SeverityDetails{Severity: "High"},
					Location:        formats.Location{File: "file1", StartLine: 1, StartColumn: 10, EndLine: 2, EndColumn: 11, Snippet: "snippet"},
					Finding:         "finding1",
					ScannerInfo:     formats.ScannerInfo{RuleId: "rule1"},
				},
				{
					SeverityDetails: formats.SeverityDetails{Severity: "High"},
					Location:        formats.Location{File: "file1", StartLine: 1, StartColumn: 10, EndLine: 2, EndColumn: 11, Snippet: "snippet"},
					Finding:         "finding1",
					ScannerInfo:     formats.ScannerInfo{RuleId: "rule2"},
				},
			},
			groupedIssues: []jasCommentIssues{
				{
					formats.Location{File: "file1", StartLine: 1, StartColumn: 10, EndLine: 2, EndColumn: 11, Snippet: "snippet"},
					[]formats.SourceCodeRow{
						{
							SeverityDetails: formats.SeverityDetails{Severity: "High"},
							Location:        formats.Location{File: "file1", StartLine: 1, StartColumn: 10, EndLine: 2, EndColumn: 11, Snippet: "snippet"},
							Finding:         "finding1",
							ScannerInfo:     formats.ScannerInfo{RuleId: "rule1"},
						},
					},
				},
				{
					formats.Location{File: "file1", StartLine: 1, StartColumn: 10, EndLine: 2, EndColumn: 11, Snippet: "snippet"},
					[]formats.SourceCodeRow{
						{
							SeverityDetails: formats.SeverityDetails{Severity: "High"},
							Location:        formats.Location{File: "file1", StartLine: 1, StartColumn: 10, EndLine: 2, EndColumn: 11, Snippet: "snippet"},
							Finding:         "finding1",
							ScannerInfo:     formats.ScannerInfo{RuleId: "rule2"},
						},
					},
				},
			},
		},
		{
			name: "Multiple issues - with similar issues",
			issues: []formats.SourceCodeRow{
				{
					SeverityDetails: formats.SeverityDetails{Severity: "High"},
					Location:        formats.Location{File: "file1", StartLine: 1, StartColumn: 10, EndLine: 2, EndColumn: 11, Snippet: "snippet"},
					Finding:         "finding1",
					ScannerInfo:     formats.ScannerInfo{RuleId: "rule1"},
				},
				{
					SeverityDetails: formats.SeverityDetails{Severity: "Medium"},
					Location:        formats.Location{File: "file1", StartLine: 1, StartColumn: 10, EndLine: 2, EndColumn: 11, Snippet: "snippet"},
					Finding:         "finding2",
					ScannerInfo:     formats.ScannerInfo{RuleId: "rule1"},
				},
				{
					SeverityDetails: formats.SeverityDetails{Severity: "Low"},
					Location:        formats.Location{File: "file1", StartLine: 1, StartColumn: 10, EndLine: 2, EndColumn: 11, Snippet: "snippet"},
					Finding:         "finding3",
					ScannerInfo:     formats.ScannerInfo{RuleId: "rule2"},
				},
				{
					SeverityDetails: formats.SeverityDetails{Severity: "Medium"},
					Location:        formats.Location{File: "file2", StartLine: 1, StartColumn: 10, EndLine: 2, EndColumn: 11, Snippet: "snippet"},
					Finding:         "finding2",
					ScannerInfo:     formats.ScannerInfo{RuleId: "rule1"},
				},
			},
			groupedIssues: []jasCommentIssues{
				{
					formats.Location{File: "file1", StartLine: 1, StartColumn: 10, EndLine: 2, EndColumn: 11, Snippet: "snippet"},
					[]formats.SourceCodeRow{
						{
							SeverityDetails: formats.SeverityDetails{Severity: "High"},
							Location:        formats.Location{File: "file1", StartLine: 1, StartColumn: 10, EndLine: 2, EndColumn: 11, Snippet: "snippet"},
							Finding:         "finding1",
							ScannerInfo:     formats.ScannerInfo{RuleId: "rule1"},
						},
						{
							SeverityDetails: formats.SeverityDetails{Severity: "Medium"},
							Location:        formats.Location{File: "file1", StartLine: 1, StartColumn: 10, EndLine: 2, EndColumn: 11, Snippet: "snippet"},
							Finding:         "finding2",
							ScannerInfo:     formats.ScannerInfo{RuleId: "rule1"},
						},
					},
				},
				{
					formats.Location{File: "file1", StartLine: 1, StartColumn: 10, EndLine: 2, EndColumn: 11, Snippet: "snippet"},
					[]formats.SourceCodeRow{
						{
							SeverityDetails: formats.SeverityDetails{Severity: "Low"},
							Location:        formats.Location{File: "file1", StartLine: 1, StartColumn: 10, EndLine: 2, EndColumn: 11, Snippet: "snippet"},
							Finding:         "finding3",
							ScannerInfo:     formats.ScannerInfo{RuleId: "rule2"},
						},
					},
				},
				{
					formats.Location{File: "file2", StartLine: 1, StartColumn: 10, EndLine: 2, EndColumn: 11, Snippet: "snippet"},
					[]formats.SourceCodeRow{
						{
							SeverityDetails: formats.SeverityDetails{Severity: "Medium"},
							Location:        formats.Location{File: "file2", StartLine: 1, StartColumn: 10, EndLine: 2, EndColumn: 11, Snippet: "snippet"},
							Finding:         "finding2",
							ScannerInfo:     formats.ScannerInfo{RuleId: "rule1"},
						},
					},
				},
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			output := groupSimilarJasIssues(tc.issues)
			assert.ElementsMatch(t, tc.groupedIssues, output)
		})
	}
}

func TestGetNewReviewComments(t *testing.T) {
	writer := &outputwriter.StandardOutput{}
	testCases := []struct {
		name                    string
		generateSecretsComments bool
		issues                  *issues.ScansIssuesCollection
		expectedOutput          []ReviewComment
	}{
		{
			name: "No issues for review comments",
			issues: &issues.ScansIssuesCollection{
				ScaVulnerabilities: []formats.VulnerabilityOrViolationRow{
					{
						Summary:    "summary-2",
						Applicable: "Applicable",
						IssueId:    "XRAY-2",
						ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
							SeverityDetails:        formats.SeverityDetails{Severity: "low"},
							ImpactedDependencyName: "component-C",
						},
						Cves:       []formats.CveRow{{Id: "CVE-2023-4321"}},
						Technology: techutils.Npm,
					},
				},
				SecretsVulnerabilities: []formats.SourceCodeRow{
					{
						SeverityDetails: formats.SeverityDetails{
							Severity:         "High",
							SeverityNumValue: 13,
						},
						Finding: "Secret",
						ScannerInfo: formats.ScannerInfo{
							RuleId: "secret-rule",
						},
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
			},
			expectedOutput: []ReviewComment{},
		},
		{
			name:                    "Secret review comments",
			generateSecretsComments: true,
			issues: &issues.ScansIssuesCollection{
				ScaVulnerabilities: []formats.VulnerabilityOrViolationRow{
					{
						Summary:    "summary-2",
						Applicable: "Applicable",
						IssueId:    "XRAY-2",
						ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
							SeverityDetails:        formats.SeverityDetails{Severity: "low"},
							ImpactedDependencyName: "component-C",
						},
						Cves:       []formats.CveRow{{Id: "CVE-2023-4321"}},
						Technology: techutils.Npm,
					},
				},
				SecretsVulnerabilities: []formats.SourceCodeRow{
					{
						SeverityDetails: formats.SeverityDetails{
							Severity:         "High",
							SeverityNumValue: 13,
						},
						Finding:       "secret finding",
						Applicability: &formats.Applicability{Status: "Inactive"},
						ScannerInfo: formats.ScannerInfo{
							RuleId: "secret-rule",
						},
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
			},
			expectedOutput: []ReviewComment{
				{
					Location: formats.Location{
						File:        "index.js",
						StartLine:   5,
						StartColumn: 6,
						EndLine:     7,
						EndColumn:   8,
						Snippet:     "access token exposed",
					},
					Type: SecretComment,
					CommentInfo: vcsclient.PullRequestComment{
						CommentInfo: vcsclient.CommentInfo{
							Content: outputwriter.GenerateReviewCommentContent(outputwriter.SecretReviewContent(false, writer, formats.SourceCodeRow{
								SeverityDetails: formats.SeverityDetails{
									Severity:         "High",
									SeverityNumValue: 13,
								},
								ScannerInfo: formats.ScannerInfo{
									RuleId: "secret-rule",
								},
								Finding:       "secret finding",
								Applicability: &formats.Applicability{Status: "Inactive"},
							}), writer),
						},
						PullRequestDiff: vcsclient.PullRequestDiff{
							OriginalFilePath:    "index.js",
							OriginalStartLine:   5,
							OriginalStartColumn: 6,
							OriginalEndLine:     7,
							OriginalEndColumn:   8,
							NewFilePath:         "index.js",
							NewStartLine:        5,
							NewStartColumn:      6,
							NewEndLine:          7,
							NewEndColumn:        8,
						},
					},
				},
			},
		},
		{
			name:                    "Multiple violations, one review comments",
			generateSecretsComments: true,
			issues: &issues.ScansIssuesCollection{
				ScaVulnerabilities: []formats.VulnerabilityOrViolationRow{
					{
						Summary:    "summary-2",
						Applicable: "Applicable",
						IssueId:    "XRAY-2",
						ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
							SeverityDetails:        formats.SeverityDetails{Severity: "low"},
							ImpactedDependencyName: "component-C",
						},
						Cves:       []formats.CveRow{{Id: "CVE-2023-4321"}},
						Technology: techutils.Npm,
					},
				},
				SecretsViolations: []formats.SourceCodeRow{
					{
						SeverityDetails: formats.SeverityDetails{
							Severity:         "High",
							SeverityNumValue: 13,
						},
						ScannerInfo: formats.ScannerInfo{
							RuleId: "secret-rule",
						},
						Finding:       "secret finding",
						Applicability: &formats.Applicability{Status: "Inactive"},
						Location: formats.Location{
							File:        "index.js",
							StartLine:   5,
							StartColumn: 6,
							EndLine:     7,
							EndColumn:   8,
							Snippet:     "access token exposed",
						},
						ViolationContext: formats.ViolationContext{
							Watch: "watch",
						},
					},
					{
						SeverityDetails: formats.SeverityDetails{
							Severity:         "High",
							SeverityNumValue: 13,
						},
						ScannerInfo: formats.ScannerInfo{
							RuleId: "secret-rule",
						},
						Finding:       "secret finding",
						Applicability: &formats.Applicability{Status: "Inactive"},
						Location: formats.Location{
							File:        "index.js",
							StartLine:   5,
							StartColumn: 6,
							EndLine:     7,
							EndColumn:   8,
							Snippet:     "access token exposed",
						},
						ViolationContext: formats.ViolationContext{
							Watch: "watch2",
						},
					},
				},
			},
			expectedOutput: []ReviewComment{
				{
					Location: formats.Location{
						File:        "index.js",
						StartLine:   5,
						StartColumn: 6,
						EndLine:     7,
						EndColumn:   8,
						Snippet:     "access token exposed",
					},
					Type: SecretComment,
					CommentInfo: vcsclient.PullRequestComment{
						CommentInfo: vcsclient.CommentInfo{
							Content: outputwriter.GenerateReviewCommentContent(outputwriter.SecretReviewContent(true, writer,
								formats.SourceCodeRow{
									SeverityDetails: formats.SeverityDetails{Severity: "High", SeverityNumValue: 13},
									ScannerInfo: formats.ScannerInfo{
										RuleId: "secret-rule",
									},
									Finding:       "secret finding",
									Applicability: &formats.Applicability{Status: "Inactive"},
									ViolationContext: formats.ViolationContext{
										Watch: "watch",
									},
								},
								formats.SourceCodeRow{
									SeverityDetails: formats.SeverityDetails{Severity: "High", SeverityNumValue: 13},
									ScannerInfo: formats.ScannerInfo{
										RuleId: "secret-rule",
									},
									Finding:       "secret finding",
									Applicability: &formats.Applicability{Status: "Inactive"},
									ViolationContext: formats.ViolationContext{
										Watch: "watch2",
									},
								},
							), writer),
						},
						PullRequestDiff: vcsclient.PullRequestDiff{
							OriginalFilePath:    "index.js",
							OriginalStartLine:   5,
							OriginalStartColumn: 6,
							OriginalEndLine:     7,
							OriginalEndColumn:   8,
							NewFilePath:         "index.js",
							NewStartLine:        5,
							NewStartColumn:      6,
							NewEndLine:          7,
							NewEndColumn:        8,
						},
					},
				},
			},
		},
		{
			name: "With issues for review comments",
			issues: &issues.ScansIssuesCollection{
				ScaVulnerabilities: []formats.VulnerabilityOrViolationRow{
					{
						Summary:    "summary-2",
						Applicable: "Applicable",
						IssueId:    "XRAY-2",
						ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
							SeverityDetails:        formats.SeverityDetails{Severity: "Low"},
							ImpactedDependencyName: "component-C",
						},
						Cves:       []formats.CveRow{{Id: "CVE-2023-4321", Applicability: &formats.Applicability{Status: "Applicable", Evidence: []formats.Evidence{{Location: formats.Location{File: "file1", StartLine: 1, StartColumn: 10, EndLine: 2, EndColumn: 11, Snippet: "snippet"}}}}}},
						Technology: techutils.Npm,
					},
				},
				IacVulnerabilities: []formats.SourceCodeRow{
					{
						SeverityDetails: formats.SeverityDetails{
							Severity:         "High",
							SeverityNumValue: 13,
						},
						ScannerInfo: formats.ScannerInfo{
							RuleId: "aws-violation",
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
				SastVulnerabilities: []formats.SourceCodeRow{
					{
						SeverityDetails: formats.SeverityDetails{
							Severity:         "High",
							SeverityNumValue: 13,
						},
						ScannerInfo: formats.ScannerInfo{
							RuleId: "sast-rule",
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
			},
			expectedOutput: []ReviewComment{
				{
					Location: formats.Location{
						File:        "file1",
						StartLine:   1,
						StartColumn: 10,
						EndLine:     2,
						EndColumn:   11,
						Snippet:     "snippet",
					},
					Type: ApplicableComment,
					CommentInfo: vcsclient.PullRequestComment{
						CommentInfo: vcsclient.CommentInfo{
							Content: outputwriter.GenerateReviewCommentContent(outputwriter.ApplicableCveReviewContent(issues.ApplicableEvidences{
								Evidence: formats.Evidence{Location: formats.Location{File: "file1", StartLine: 1, StartColumn: 10, EndLine: 2, EndColumn: 11, Snippet: "snippet"}},
								Severity: "Low", IssueId: "CVE-2023-4321", CveSummary: "summary-2", ImpactedDependency: "component-C",
							}, writer), writer),
						},
						PullRequestDiff: vcsclient.PullRequestDiff{
							OriginalFilePath:    "file1",
							OriginalStartLine:   1,
							OriginalStartColumn: 10,
							OriginalEndLine:     2,
							OriginalEndColumn:   11,
							NewFilePath:         "file1",
							NewStartLine:        1,
							NewStartColumn:      10,
							NewEndLine:          2,
							NewEndColumn:        11,
						},
					},
				},
				{
					Location: formats.Location{
						File:        "file1",
						StartLine:   1,
						StartColumn: 10,
						EndLine:     2,
						EndColumn:   11,
						Snippet:     "aws-violation",
					},
					Type: IacComment,
					CommentInfo: vcsclient.PullRequestComment{
						CommentInfo: vcsclient.CommentInfo{
							Content: outputwriter.GenerateReviewCommentContent(outputwriter.IacReviewContent(false, writer, formats.SourceCodeRow{
								SeverityDetails: formats.SeverityDetails{
									Severity:         "High",
									SeverityNumValue: 13,
								},
								ScannerInfo: formats.ScannerInfo{
									RuleId: "aws-violation",
								},
								Finding: "Missing auto upgrade was detected",
							}), writer),
						},
						PullRequestDiff: vcsclient.PullRequestDiff{
							OriginalFilePath:    "file1",
							OriginalStartLine:   1,
							OriginalStartColumn: 10,
							OriginalEndLine:     2,
							OriginalEndColumn:   11,
							NewFilePath:         "file1",
							NewStartLine:        1,
							NewStartColumn:      10,
							NewEndLine:          2,
							NewEndColumn:        11,
						},
					},
				},
				{
					Location: formats.Location{
						File:        "file1",
						StartLine:   1,
						StartColumn: 10,
						EndLine:     2,
						EndColumn:   11,
						Snippet:     "snippet",
					},
					Type: SastComment,
					CommentInfo: vcsclient.PullRequestComment{
						CommentInfo: vcsclient.CommentInfo{
							Content: outputwriter.GenerateReviewCommentContent(outputwriter.SastReviewContent(false, writer, formats.SourceCodeRow{
								SeverityDetails: formats.SeverityDetails{
									Severity:         "High",
									SeverityNumValue: 13,
								},
								ScannerInfo: formats.ScannerInfo{
									RuleId: "sast-rule",
								},
								Finding: "XSS Vulnerability",
							}), writer),
						},
						PullRequestDiff: vcsclient.PullRequestDiff{
							OriginalFilePath:    "file1",
							OriginalStartLine:   1,
							OriginalStartColumn: 10,
							OriginalEndLine:     2,
							OriginalEndColumn:   11,
							NewFilePath:         "file1",
							NewStartLine:        1,
							NewStartColumn:      10,
							NewEndLine:          2,
							NewEndColumn:        11,
						},
					},
				},
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			repo := &Repository{OutputWriter: writer, Params: Params{Git: Git{PullRequestSecretComments: tc.generateSecretsComments}}}
			output := getNewReviewComments(repo, tc.issues)
			assert.ElementsMatch(t, tc.expectedOutput, output)
		})
	}
}
