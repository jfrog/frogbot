package utils

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jfrog/frogbot/utils/outputwriter"
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/froggit-go/vcsutils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-core/v2/xray/formats"
	"github.com/stretchr/testify/assert"
)

func TestCreatePullRequestMessageNoVulnerabilities(t *testing.T) {
	vulnerabilities := []formats.VulnerabilityOrViolationRow{}
	message := createPullRequestComment(&IssuesCollection{Vulnerabilities: vulnerabilities}, &outputwriter.StandardOutput{})

	expectedMessageByte, err := os.ReadFile(filepath.Join("..", "testdata", "messages", "novulnerabilities.md"))
	assert.NoError(t, err)
	expectedMessage := strings.ReplaceAll(string(expectedMessageByte), "\r\n", "\n")
	assert.Equal(t, expectedMessage, message)

	outputWriter := &outputwriter.StandardOutput{}
	outputWriter.SetVcsProvider(vcsutils.GitLab)
	message = createPullRequestComment(&IssuesCollection{Vulnerabilities: vulnerabilities}, outputWriter)

	expectedMessageByte, err = os.ReadFile(filepath.Join("..", "testdata", "messages", "novulnerabilitiesMR.md"))
	assert.NoError(t, err)
	expectedMessage = strings.ReplaceAll(string(expectedMessageByte), "\r\n", "\n")
	assert.Equal(t, expectedMessage, message)
}

func TestCreatePullRequestComment(t *testing.T) {
	vulnerabilities := []formats.VulnerabilityOrViolationRow{
		{
			Summary: "Summary XRAY-122345",
			ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
				SeverityDetails:           formats.SeverityDetails{Severity: "High"},
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
			Cves:          []formats.CveRow{{}},
		},
		{
			Summary: "Summary",
			ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
				SeverityDetails:           formats.SeverityDetails{Severity: "High"},
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
			Cves:          []formats.CveRow{{Id: "CVE-2022-26652"}},
		},
	}
	licenses := []formats.LicenseRow{
		{
			LicenseKey: "Apache-2.0",
			ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
				SeverityDetails:           formats.SeverityDetails{Severity: "High", SeverityNumValue: 13},
				ImpactedDependencyName:    "minimatch",
				ImpactedDependencyVersion: "1.2.3",
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
			},
		},
	}

	writerOutput := &outputwriter.StandardOutput{}
	writerOutput.SetJasOutputFlags(true, true)
	message := createPullRequestComment(&IssuesCollection{Vulnerabilities: vulnerabilities, Licenses: licenses}, writerOutput)

	expectedMessage := "<div align='center'>\n\n[![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/vulnerabilitiesBannerPR.png)](https://github.com/jfrog/frogbot#readme)\n\n</div>\n\n\n## 📦 Vulnerable Dependencies\n\n### ✍️ Summary\n\n<div align=\"center\">\n\n| SEVERITY                | CONTEXTUAL ANALYSIS                  | DIRECT DEPENDENCIES                  | IMPACTED DEPENDENCY                   | FIXED VERSIONS                       | CVES                       |\n| :---------------------: | :----------------------------------: | :----------------------------------: | :-----------------------------------: | :---------------------------------: | :---------------------------------: | \n| ![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/applicableHighSeverity.png)<br>    High | Undetermined | github.com/nats-io/nats-streaming-server:v0.21.0 | github.com/nats-io/nats-streaming-server:v0.21.0 | [0.24.1] |  -  |\n| ![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/applicableHighSeverity.png)<br>    High | Undetermined | github.com/mholt/archiver/v3:v3.5.1 | github.com/mholt/archiver/v3:v3.5.1 |  -  |  -  |\n| ![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/applicableMediumSeverity.png)<br>  Medium | Undetermined | github.com/nats-io/nats-streaming-server:v0.21.0 | github.com/nats-io/nats-streaming-server:v0.21.0 | [0.24.3] | CVE-2022-26652 |\n\n</div>\n\n## 🔬 Research Details\n\n<details>\n<summary> <b>[ XRAY-122345 ] github.com/nats-io/nats-streaming-server v0.21.0</b> </summary>\n<br>\n\n**Description:**\nSummary XRAY-122345\n\n\n</details>\n\n\n<details>\n<summary> <b>github.com/mholt/archiver/v3 v3.5.1</b> </summary>\n<br>\n\n**Description:**\nSummary\n\n\n</details>\n\n\n<details>\n<summary> <b>[ CVE-2022-26652 ] github.com/nats-io/nats-streaming-server v0.21.0</b> </summary>\n<br>\n\n**Description:**\nSummary CVE-2022-26652\n\n\n</details>\n\n\n## ⚖️ Violated Licenses \n\n<div align=\"center\">\n\n\n| LICENSE                | DIRECT DEPENDENCIES                  | IMPACTED DEPENDENCY                   | \n| :---------------------: | :----------------------------------: | :-----------------------------------: | \n| Apache-2.0 | root 1.0.0<br>minimatch 1.2.3 | minimatch 1.2.3 |\n\n</div>\n\n\n---\n<div align=\"center\">\n\n[🐸 JFrog Frogbot](https://github.com/jfrog/frogbot#readme)\n\n</div>"
	assert.Equal(t, expectedMessage, message)

	writerOutput.SetVcsProvider(vcsutils.GitLab)
	message = createPullRequestComment(&IssuesCollection{Vulnerabilities: vulnerabilities}, writerOutput)
	expectedMessage = "<div align='center'>\n\n[![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/vulnerabilitiesBannerMR.png)](https://github.com/jfrog/frogbot#readme)\n\n</div>\n\n\n## 📦 Vulnerable Dependencies\n\n### ✍️ Summary\n\n<div align=\"center\">\n\n| SEVERITY                | CONTEXTUAL ANALYSIS                  | DIRECT DEPENDENCIES                  | IMPACTED DEPENDENCY                   | FIXED VERSIONS                       | CVES                       |\n| :---------------------: | :----------------------------------: | :----------------------------------: | :-----------------------------------: | :---------------------------------: | :---------------------------------: | \n| ![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/applicableHighSeverity.png)<br>    High | Undetermined | github.com/nats-io/nats-streaming-server:v0.21.0 | github.com/nats-io/nats-streaming-server:v0.21.0 | [0.24.1] |  -  |\n| ![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/applicableHighSeverity.png)<br>    High | Undetermined | github.com/mholt/archiver/v3:v3.5.1 | github.com/mholt/archiver/v3:v3.5.1 |  -  |  -  |\n| ![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/applicableMediumSeverity.png)<br>  Medium | Undetermined | github.com/nats-io/nats-streaming-server:v0.21.0 | github.com/nats-io/nats-streaming-server:v0.21.0 | [0.24.3] | CVE-2022-26652 |\n\n</div>\n\n## 🔬 Research Details\n\n<details>\n<summary> <b>[ XRAY-122345 ] github.com/nats-io/nats-streaming-server v0.21.0</b> </summary>\n<br>\n\n**Description:**\nSummary XRAY-122345\n\n\n</details>\n\n\n<details>\n<summary> <b>github.com/mholt/archiver/v3 v3.5.1</b> </summary>\n<br>\n\n**Description:**\nSummary\n\n\n</details>\n\n\n<details>\n<summary> <b>[ CVE-2022-26652 ] github.com/nats-io/nats-streaming-server v0.21.0</b> </summary>\n<br>\n\n**Description:**\nSummary CVE-2022-26652\n\n\n</details>\n\n\n---\n<div align=\"center\">\n\n[🐸 JFrog Frogbot](https://github.com/jfrog/frogbot#readme)\n\n</div>"
	assert.Equal(t, expectedMessage, message)
}

func TestGetFrogbotReviewComments(t *testing.T) {
	testCases := []struct {
		name             string
		existingComments []vcsclient.CommentInfo
		expectedOutput   []vcsclient.CommentInfo
	}{
		{
			name: "No frogbot comments",
			existingComments: []vcsclient.CommentInfo{
				{
					Content: outputwriter.FrogbotTitlePrefix,
				},
				{
					Content: "some comment text" + outputwriter.MarkdownComment("with hidden comment"),
				},
				{
					Content: outputwriter.CommentGeneratedByFrogbot,
				},
			},
			expectedOutput: []vcsclient.CommentInfo{},
		},
		{
			name: "With frogbot comments",
			existingComments: []vcsclient.CommentInfo{
				{
					Content: outputwriter.FrogbotTitlePrefix,
				},
				{
					Content: outputwriter.MarkdownComment(outputwriter.ReviewCommentId) + "A Frogbot review comment",
				},
				{
					Content: "some comment text" + outputwriter.MarkdownComment("with hidden comment"),
				},
				{
					Content: outputwriter.ReviewCommentId,
				},
				{
					Content: outputwriter.CommentGeneratedByFrogbot,
				},
			},
			expectedOutput: []vcsclient.CommentInfo{
				{
					Content: outputwriter.MarkdownComment(outputwriter.ReviewCommentId) + "A Frogbot review comment",
				},
				{
					Content: outputwriter.ReviewCommentId,
				},
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			output := getFrogbotReviewComments(tc.existingComments)
			assert.ElementsMatch(t, tc.expectedOutput, output)
		})
	}
}

func TestGetNewReviewComments(t *testing.T) {
	repo := &Repository{OutputWriter: &outputwriter.StandardOutput{}}
	testCases := []struct {
		name           string
		issues         *IssuesCollection
		expectedOutput []ReviewComment
	}{
		{
			name: "No issues for review comments",
			issues: &IssuesCollection{
				Vulnerabilities: []formats.VulnerabilityOrViolationRow{
					{
						Summary:    "summary-2",
						Applicable: "Applicable",
						IssueId:    "XRAY-2",
						ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
							SeverityDetails:        formats.SeverityDetails{Severity: "low"},
							ImpactedDependencyName: "component-C",
						},
						Cves:       []formats.CveRow{{Id: "CVE-2023-4321"}},
						Technology: coreutils.Npm,
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
			},
			expectedOutput: []ReviewComment{},
		},
		{
			name: "With issues for review comments",
			issues: &IssuesCollection{
				Vulnerabilities: []formats.VulnerabilityOrViolationRow{
					{
						Summary:    "summary-2",
						Applicable: "Applicable",
						IssueId:    "XRAY-2",
						ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
							SeverityDetails:        formats.SeverityDetails{Severity: "Low"},
							ImpactedDependencyName: "component-C",
						},
						Cves:       []formats.CveRow{{Id: "CVE-2023-4321", Applicability: &formats.Applicability{Status: "Applicable", Evidence: []formats.Evidence{{Location: formats.Location{File: "file1", StartLine: 1, StartColumn: 10, EndLine: 2, EndColumn: 11, Snippet: "snippet"}}}}}},
						Technology: coreutils.Npm,
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
							Content: outputwriter.GenerateReviewCommentContent(repo.ApplicableCveReviewContent("Low", "", "", "CVE-2023-4321", "summary-2", "component-C:", ""), repo.OutputWriter),
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
							Content: outputwriter.GenerateReviewCommentContent(repo.IacReviewContent("High", "Missing auto upgrade was detected", ""), repo.OutputWriter),
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
							Content: outputwriter.GenerateReviewCommentContent(repo.SastReviewContent("High", "XSS Vulnerability", "", [][]formats.Location{}), repo.OutputWriter),
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
			output := getNewReviewComments(repo, tc.issues)
			assert.ElementsMatch(t, tc.expectedOutput, output)
		})
	}
}
