package outputwriter

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
