package outputwriter

import (
	"path/filepath"
	"testing"

	"github.com/jfrog/jfrog-cli-core/v2/xray/formats"
	"github.com/stretchr/testify/assert"
)

var (
	testMessagesDir = filepath.Join("..", "..", "testdata", "messages")
)

func TestApplicableReviewContent(t *testing.T) {
	testCases := []struct {
		name                                                                             string
		severity, finding, fullDetails, cve, cveDetails, impactedDependency, remediation string
		cases       []OutputTestCase
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
					expectedOutputPath: filepath.Join(testMessagesDir, "applicable", "applicable_review_content_standard.md"),
				},
				{
					name:               "Simplified output",
					writer:             &SimplifiedOutput{},
					expectedOutputPath: filepath.Join(testMessagesDir, "applicable", "applicable_review_content_simplified.md"),
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
					expectedOutputPath: filepath.Join(testMessagesDir, "applicable", "applicable_review_content_no_remediation_standard.md"),
				},
				{
					name:               "Simplified output",
					writer:             &SimplifiedOutput{},
					expectedOutputPath: filepath.Join(testMessagesDir, "applicable", "applicable_review_content_no_remediation_simplified.md"),
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
		cases       []OutputTestCase
	}{
		{
			name:           "Iac review comment content",
			severity:       "Medium",
			finding:        "Missing auto upgrade was detected",
			fullDetails:    "Resource `google_container_node_pool` should have `management.auto_upgrade=true`\n\nVulnerable example - \n```\nresource \"google_container_node_pool\" \"vulnerable_example\" {\n    management {\n     auto_upgrade = false\n   }\n}\n```\n",
			cases: []OutputTestCase{
				{
					name:               "Standard output",
					writer:             &StandardOutput{},
					expectedOutputPath: filepath.Join(testMessagesDir, "iac", "iac_review_content_standard.md"),
				},
				{
					name:               "Simplified output",
					writer:             &SimplifiedOutput{},
					expectedOutputPath: filepath.Join(testMessagesDir, "iac", "iac_review_content_simplified.md"),
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
					expectedOutputPath: filepath.Join(testMessagesDir, "sast", "sast_review_content_standard.md"),
				},
				{
					name:               "Simplified output",
					writer:             &SimplifiedOutput{},
					expectedOutputPath: filepath.Join(testMessagesDir, "sast", "sast_review_content_simplified.md"),
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
					expectedOutputPath: filepath.Join(testMessagesDir, "sast", "sast_review_content_no_code_flow_standard.md"),
				},
				{
					name:               "Simplified output",
					writer:             &SimplifiedOutput{},
					expectedOutputPath: filepath.Join(testMessagesDir, "sast", "sast_review_content_no_code_flow_simplified.md"),
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

// func TestCreatePullRequestMessageNoVulnerabilities(t *testing.T) {
// 	vulnerabilities := []formats.VulnerabilityOrViolationRow{}
// 	message := createPullRequestComment(&utils.IssuesCollection{Vulnerabilities: vulnerabilities}, &outputwriter.StandardOutput{})

// 	expectedMessageByte, err := os.ReadFile(filepath.Join("..", "testdata", "messages", "novulnerabilities.md"))
// 	assert.NoError(t, err)
// 	expectedMessage := strings.ReplaceAll(string(expectedMessageByte), "\r\n", "\n")
// 	assert.Equal(t, expectedMessage, message)

// 	outputWriter := &outputwriter.StandardOutput{}
// 	outputWriter.SetVcsProvider(vcsutils.GitLab)
// 	message = createPullRequestComment(&utils.IssuesCollection{Vulnerabilities: vulnerabilities}, outputWriter)

// 	expectedMessageByte, err = os.ReadFile(filepath.Join("..", "testdata", "messages", "novulnerabilitiesMR.md"))
// 	assert.NoError(t, err)
// 	expectedMessage = strings.ReplaceAll(string(expectedMessageByte), "\r\n", "\n")
// 	assert.Equal(t, expectedMessage, message)
// }

// func TestCreatePullRequestComment(t *testing.T) {
// 	vulnerabilities := []formats.VulnerabilityOrViolationRow{
// 		{
// 			Summary: "Summary XRAY-122345",
// 			ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
// 				SeverityDetails:           formats.SeverityDetails{Severity: "High"},
// 				ImpactedDependencyName:    "github.com/nats-io/nats-streaming-server",
// 				ImpactedDependencyVersion: "v0.21.0",
// 				Components: []formats.ComponentRow{
// 					{
// 						Name:    "github.com/nats-io/nats-streaming-server",
// 						Version: "v0.21.0",
// 					},
// 				},
// 			},
// 			Applicable:    "Undetermined",
// 			FixedVersions: []string{"[0.24.1]"},
// 			IssueId:       "XRAY-122345",
// 			Cves:          []formats.CveRow{{}},
// 		},
// 		{
// 			Summary: "Summary",
// 			ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
// 				SeverityDetails:           formats.SeverityDetails{Severity: "High"},
// 				ImpactedDependencyName:    "github.com/mholt/archiver/v3",
// 				ImpactedDependencyVersion: "v3.5.1",
// 				Components: []formats.ComponentRow{
// 					{
// 						Name:    "github.com/mholt/archiver/v3",
// 						Version: "v3.5.1",
// 					},
// 				},
// 			},
// 			Applicable: "Undetermined",
// 			Cves:       []formats.CveRow{},
// 		},
// 		{
// 			Summary: "Summary CVE-2022-26652",
// 			ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
// 				SeverityDetails:           formats.SeverityDetails{Severity: "Medium"},
// 				ImpactedDependencyName:    "github.com/nats-io/nats-streaming-server",
// 				ImpactedDependencyVersion: "v0.21.0",
// 				Components: []formats.ComponentRow{
// 					{
// 						Name:    "github.com/nats-io/nats-streaming-server",
// 						Version: "v0.21.0",
// 					},
// 				},
// 			},
// 			Applicable:    "Undetermined",
// 			FixedVersions: []string{"[0.24.3]"},
// 			Cves:          []formats.CveRow{{Id: "CVE-2022-26652"}},
// 		},
// 	}
// 	licenses := []formats.LicenseRow{
// 		{
// 			LicenseKey: "Apache-2.0",
// 			ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
// 				SeverityDetails:           formats.SeverityDetails{Severity: "High", SeverityNumValue: 13},
// 				ImpactedDependencyName:    "minimatch",
// 				ImpactedDependencyVersion: "1.2.3",
// 				Components: []formats.ComponentRow{
// 					{
// 						Name:    "root",
// 						Version: "1.0.0",
// 					},
// 					{
// 						Name:    "minimatch",
// 						Version: "1.2.3",
// 					},
// 				},
// 			},
// 		},
// 	}

// 	writerOutput := &outputwriter.StandardOutput{}
// 	writerOutput.SetJasOutputFlags(true, true)
// 	message := createPullRequestComment(&utils.IssuesCollection{Vulnerabilities: vulnerabilities, Licenses: licenses}, writerOutput)

// 	expectedMessage := "<div align='center'>\n\n[![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/vulnerabilitiesBannerPR.png)](https://github.com/jfrog/frogbot#readme)\n\n</div>\n\n## 📦 Vulnerable Dependencies\n### ✍️ Summary\n\n<div align=\"center\">\n\n| SEVERITY                | CONTEXTUAL ANALYSIS                  | DIRECT DEPENDENCIES                  | IMPACTED DEPENDENCY                   | FIXED VERSIONS                       | CVES                       |\n| :---------------------: | :----------------------------------: | :----------------------------------: | :-----------------------------------: | :---------------------------------: | :---------------------------------: | \n| ![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/applicableHighSeverity.png)<br>    High | Undetermined | github.com/nats-io/nats-streaming-server:v0.21.0 | github.com/nats-io/nats-streaming-server:v0.21.0 | [0.24.1] |  -  |\n| ![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/applicableHighSeverity.png)<br>    High | Undetermined | github.com/mholt/archiver/v3:v3.5.1 | github.com/mholt/archiver/v3:v3.5.1 |  -  |  -  |\n| ![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/applicableMediumSeverity.png)<br>  Medium | Undetermined | github.com/nats-io/nats-streaming-server:v0.21.0 | github.com/nats-io/nats-streaming-server:v0.21.0 | [0.24.3] | CVE-2022-26652 |\n\n</div>\n\n<details>\n<summary> <b>🔬 Research Details</b> </summary>\n<br>\n\n<details>\n<summary> <b>[ XRAY-122345 ] github.com/nats-io/nats-streaming-server v0.21.0</b> </summary>\n<br>\n\n**Description:**\nSummary XRAY-122345\n\n\n</details>\n\n<details>\n<summary> <b>github.com/mholt/archiver/v3 v3.5.1</b> </summary>\n<br>\n\n**Description:**\nSummary\n\n\n</details>\n\n<details>\n<summary> <b>[ CVE-2022-26652 ] github.com/nats-io/nats-streaming-server v0.21.0</b> </summary>\n<br>\n\n**Description:**\nSummary CVE-2022-26652\n\n\n</details>\n\n\n</details>\n\n## ⚖️ Violated Licenses\n<div align=\"center\">\n\n\n| LICENSE                | DIRECT DEPENDENCIES                  | IMPACTED DEPENDENCY                   | \n| :---------------------: | :----------------------------------: | :-----------------------------------: | \n| Apache-2.0 | root 1.0.0<br>minimatch 1.2.3 | minimatch 1.2.3 |\n\n</div>\n\n\n---\n\n<div align=\"center\">\n\n[🐸 JFrog Frogbot](https://github.com/jfrog/frogbot#readme)\n\n</div>"
// 	assert.Equal(t, expectedMessage, message)

// 	writerOutput.SetVcsProvider(vcsutils.GitLab)
// 	message = createPullRequestComment(&utils.IssuesCollection{Vulnerabilities: vulnerabilities}, writerOutput)
// 	expectedMessage = "<div align='center'>\n\n[![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/vulnerabilitiesBannerMR.png)](https://github.com/jfrog/frogbot#readme)\n\n</div>\n\n## 📦 Vulnerable Dependencies\n### ✍️ Summary\n\n<div align=\"center\">\n\n| SEVERITY                | CONTEXTUAL ANALYSIS                  | DIRECT DEPENDENCIES                  | IMPACTED DEPENDENCY                   | FIXED VERSIONS                       | CVES                       |\n| :---------------------: | :----------------------------------: | :----------------------------------: | :-----------------------------------: | :---------------------------------: | :---------------------------------: | \n| ![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/applicableHighSeverity.png)<br>    High | Undetermined | github.com/nats-io/nats-streaming-server:v0.21.0 | github.com/nats-io/nats-streaming-server:v0.21.0 | [0.24.1] |  -  |\n| ![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/applicableHighSeverity.png)<br>    High | Undetermined | github.com/mholt/archiver/v3:v3.5.1 | github.com/mholt/archiver/v3:v3.5.1 |  -  |  -  |\n| ![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/applicableMediumSeverity.png)<br>  Medium | Undetermined | github.com/nats-io/nats-streaming-server:v0.21.0 | github.com/nats-io/nats-streaming-server:v0.21.0 | [0.24.3] | CVE-2022-26652 |\n\n</div>\n\n<details>\n<summary> <b>🔬 Research Details</b> </summary>\n<br>\n\n<details>\n<summary> <b>[ XRAY-122345 ] github.com/nats-io/nats-streaming-server v0.21.0</b> </summary>\n<br>\n\n**Description:**\nSummary XRAY-122345\n\n\n</details>\n\n<details>\n<summary> <b>github.com/mholt/archiver/v3 v3.5.1</b> </summary>\n<br>\n\n**Description:**\nSummary\n\n\n</details>\n\n<details>\n<summary> <b>[ CVE-2022-26652 ] github.com/nats-io/nats-streaming-server v0.21.0</b> </summary>\n<br>\n\n**Description:**\nSummary CVE-2022-26652\n\n\n</details>\n\n\n</details>\n\n---\n\n<div align=\"center\">\n\n[🐸 JFrog Frogbot](https://github.com/jfrog/frogbot#readme)\n\n</div>"
// 	assert.Equal(t, expectedMessage, message)
// }
