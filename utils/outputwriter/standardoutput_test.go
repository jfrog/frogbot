package outputwriter

import (
	"fmt"
	"github.com/jfrog/froggit-go/vcsutils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-core/v2/xray/formats"
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
)

func TestStandardOutput_TableRow(t *testing.T) {
	var tests = []struct {
		vulnerability formats.VulnerabilityOrViolationRow
		expected      string
		name          string
	}{
		{
			name: "Single CVE and no direct dependencies",
			vulnerability: formats.VulnerabilityOrViolationRow{
				ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
					SeverityDetails:           formats.SeverityDetails{Severity: "Critical"},
					ImpactedDependencyName:    "testdep",
					ImpactedDependencyVersion: "1.0.0",
				},
				FixedVersions: []string{"2.0.0"},
				Cves:          []formats.CveRow{{Id: "CVE-2022-1234"}},
			},
			expected: "| ![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/applicableCriticalSeverity.png)<br>Critical |  | testdep:1.0.0 | 2.0.0 | CVE-2022-1234 |",
		},
		{
			name: "Multiple CVEs and no direct dependencies",
			vulnerability: formats.VulnerabilityOrViolationRow{
				ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
					SeverityDetails:           formats.SeverityDetails{Severity: "High"},
					ImpactedDependencyName:    "testdep2",
					ImpactedDependencyVersion: "1.0.0",
				},
				FixedVersions: []string{"2.0.0", "3.0.0"},
				Cves: []formats.CveRow{
					{Id: "CVE-2022-1234"},
					{Id: "CVE-2022-5678"},
				},
			},
			expected: "| ![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/applicableHighSeverity.png)<br>    High |  | testdep2:1.0.0 | 2.0.0<br>3.0.0 | CVE-2022-1234<br>CVE-2022-5678 |",
		},
		{
			name: "Single CVE and direct dependencies",
			vulnerability: formats.VulnerabilityOrViolationRow{
				ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
					SeverityDetails:           formats.SeverityDetails{Severity: "Low"},
					ImpactedDependencyName:    "testdep3",
					ImpactedDependencyVersion: "1.0.0",
					Components: []formats.ComponentRow{
						{Name: "dep1", Version: "1.0.0"},
						{Name: "dep2", Version: "2.0.0"},
					},
				},
				FixedVersions: []string{"2.0.0"},
				Cves:          []formats.CveRow{{Id: "CVE-2022-1234"}},
			},
			expected: "| ![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/applicableLowSeverity.png)<br>     Low | dep1:1.0.0<br>dep2:2.0.0 | testdep3:1.0.0 | 2.0.0 | CVE-2022-1234 |",
		},
		{
			name: "Multiple CVEs and direct dependencies",
			vulnerability: formats.VulnerabilityOrViolationRow{
				ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
					SeverityDetails:           formats.SeverityDetails{Severity: "High"},
					ImpactedDependencyName:    "impacted",
					ImpactedDependencyVersion: "3.0.0",
					Components: []formats.ComponentRow{
						{Name: "dep1", Version: "1.0.0"},
						{Name: "dep2", Version: "2.0.0"},
					},
				},
				Cves: []formats.CveRow{
					{Id: "CVE-1"},
					{Id: "CVE-2"},
				},
				FixedVersions: []string{"4.0.0", "5.0.0"},
			},
			expected: "| ![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/applicableHighSeverity.png)<br>    High | dep1:1.0.0<br>dep2:2.0.0 | impacted:3.0.0 | 4.0.0<br>5.0.0 | CVE-1<br>CVE-2 |",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			smo := &StandardOutput{}
			actualOutput := smo.VulnerabilitiesTableRow(tc.vulnerability)
			assert.Equal(t, tc.expected, actualOutput)
		})
	}
}

func TestStandardOutput_IsFrogbotResultComment(t *testing.T) {
	so := &StandardOutput{}

	tests := []struct {
		comment  string
		expected bool
	}{
		{
			comment:  "This is a comment with the " + GetIconTag(NoVulnerabilityPrBannerSource) + " icon",
			expected: true,
		},
		{
			comment:  "This is a comment with the " + GetIconTag(VulnerabilitiesPrBannerSource) + " icon",
			expected: true,
		},
		{
			comment:  "This is a comment with the " + GetIconTag(VulnerabilitiesMrBannerSource) + " icon",
			expected: true,
		},
		{
			comment:  "This is a comment with the " + GetIconTag(NoVulnerabilityMrBannerSource) + " icon",
			expected: true,
		},
		{
			comment:  "This is a comment with no icons",
			expected: false,
		},
	}

	for _, test := range tests {
		result := so.IsFrogbotResultComment(test.comment)
		assert.Equal(t, test.expected, result)
	}
}

func TestStandardOutput_VulnerabilitiesContent(t *testing.T) {
	// Create a new instance of StandardOutput
	so := &StandardOutput{}

	// Create some sample vulnerabilitiesRows for testing
	vulnerabilitiesRows := []formats.VulnerabilityOrViolationRow{
		{
			Summary: "CVE-2023-1234 summary",
			ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
				ImpactedDependencyName:    "Dependency1",
				ImpactedDependencyVersion: "1.0.0",
			},
		},
		{
			Summary: "CVE-2023-1234 summary",
			ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
				ImpactedDependencyName:    "Dependency2",
				ImpactedDependencyVersion: "2.0.0",
			},
		},
	}

	// Set the expected content string based on the sample data
	expectedContent := fmt.Sprintf(`
## 📦 Vulnerable Dependencies

### ✍️ Summary

<div align="center">

%s %s

</div>

## 🔬 Research Details

<details>
<summary> <b>%s%s %s</b> </summary>
<br>
%s

</details>

<details>
<summary> <b>%s%s %s</b> </summary>
<br>
%s

</details>
`,
		getVulnerabilitiesTableHeader(false),
		getVulnerabilitiesTableContent(vulnerabilitiesRows, so),
		"",
		vulnerabilitiesRows[0].ImpactedDependencyName,
		vulnerabilitiesRows[0].ImpactedDependencyVersion,
		createVulnerabilityDescription(&vulnerabilitiesRows[0]),
		"",
		vulnerabilitiesRows[1].ImpactedDependencyName,
		vulnerabilitiesRows[1].ImpactedDependencyVersion,
		createVulnerabilityDescription(&vulnerabilitiesRows[1]),
	)

	actualContent := so.VulnerabilitiesContent(vulnerabilitiesRows)
	assert.Equal(t, expectedContent, actualContent, "Content mismatch")
}

func TestStandardOutput_ContentWithContextualAnalysis(t *testing.T) {
	// Create a new instance of StandardOutput
	so := &StandardOutput{entitledForJas: true, vcsProvider: vcsutils.GitHub, showCaColumn: true}

	vulnerabilitiesRows := []formats.VulnerabilityOrViolationRow{}
	expectedContent := ""
	actualContent := so.VulnerabilitiesContent(vulnerabilitiesRows)
	assert.Equal(t, expectedContent, actualContent)

	// Create some sample vulnerabilitiesRows for testing
	vulnerabilitiesRows = []formats.VulnerabilityOrViolationRow{
		{
			Summary: "CVE-2023-1234 summary",
			ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
				ImpactedDependencyName:    "Dependency1",
				ImpactedDependencyVersion: "1.0.0",
			},
			Applicable: "Applicable",
			Technology: coreutils.Pip,
			Cves:       []formats.CveRow{{Id: "CVE-2023-1234"}, {Id: "CVE-2023-4321"}},
		},
		{
			Summary: "CVE-2023-1234 summary",
			ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
				ImpactedDependencyName:    "Dependency2",
				ImpactedDependencyVersion: "2.0.0",
			},
			Applicable: "Not Applicable",
			Technology: coreutils.Pip,
			Cves:       []formats.CveRow{{Id: "CVE-2022-4321"}},
		},
	}

	// Set the expected content string based on the sample data
	expectedContent = fmt.Sprintf(`
## 📦 Vulnerable Dependencies

### ✍️ Summary

<div align="center">

%s %s

</div>

## 🔬 Research Details

<details>
<summary> <b>%s%s %s</b> </summary>
<br>
%s

</details>

<details>
<summary> <b>%s%s %s</b> </summary>
<br>
%s

</details>
`,
		getVulnerabilitiesTableHeader(true),
		getVulnerabilitiesTableContent(vulnerabilitiesRows, so),
		fmt.Sprintf("[ %s ] ", strings.Join([]string{vulnerabilitiesRows[0].Cves[0].Id, vulnerabilitiesRows[0].Cves[1].Id}, ", ")),
		vulnerabilitiesRows[0].ImpactedDependencyName,
		vulnerabilitiesRows[0].ImpactedDependencyVersion,
		createVulnerabilityDescription(&vulnerabilitiesRows[0]),
		fmt.Sprintf("[ %s ] ", strings.Join([]string{vulnerabilitiesRows[1].Cves[0].Id}, ",")),
		vulnerabilitiesRows[1].ImpactedDependencyName,
		vulnerabilitiesRows[1].ImpactedDependencyVersion,
		createVulnerabilityDescription(&vulnerabilitiesRows[1]),
	)

	actualContent = so.VulnerabilitiesContent(vulnerabilitiesRows)
	assert.Equal(t, expectedContent, actualContent, "Content mismatch")
	assert.Contains(t, actualContent, "CONTEXTUAL ANALYSIS")
	assert.Contains(t, actualContent, "| Applicable |")
	assert.Contains(t, actualContent, "| Not Applicable |")
}

func TestStandardOutput_GetLicensesTableContent(t *testing.T) {
	writer := &StandardOutput{}
	testGetLicensesTableContent(t, writer)
}

func TestStandardOutput_ApplicableCveReviewContent(t *testing.T) {
	testCases := []struct {
		name                                                                             string
		severity, finding, fullDetails, cve, cveDetails, impactedDependency, remediation string
		expectedOutput                                                                   string
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
			expectedOutput:     "\n## 📦🔍 Contextual Analysis CVE Vulnerability\n<div align=\"center\">\n\n| Severity | Impacted Dependency | Finding | CVE |\n| :--------------: | :---: | :---: | :---: |\n| ![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/applicableCriticalSeverity.png)<br>Critical | werkzeug:1.0.1 | The vulnerable function flask.Flask.run is called | CVE-2022-29361 |\n\n</div>\n<details>\n<summary> <b>Description</b> </summary>\n<br>\nThe scanner checks whether the vulnerable `Development Server` of the `werkzeug` library is used by looking for calls to `werkzeug.serving.run_simple()`.\n\n</details>\n<details>\n<summary> <b>CVE details</b> </summary>\n<br>\ncveDetails\n\n</details>\n\n<details>\n<summary> <b>Remediation</b> </summary>\n<br>\nsome remediation\n\n</details>\n",
		},
		{
			name:               "No remediation",
			severity:           "Critical",
			finding:            "The vulnerable function flask.Flask.run is called",
			fullDetails:        "The scanner checks whether the vulnerable `Development Server` of the `werkzeug` library is used by looking for calls to `werkzeug.serving.run_simple()`.",
			cve:                "CVE-2022-29361",
			cveDetails:         "cveDetails",
			impactedDependency: "werkzeug:1.0.1",
			expectedOutput:     "\n## 📦🔍 Contextual Analysis CVE Vulnerability\n<div align=\"center\">\n\n| Severity | Impacted Dependency | Finding | CVE |\n| :--------------: | :---: | :---: | :---: |\n| ![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/applicableCriticalSeverity.png)<br>Critical | werkzeug:1.0.1 | The vulnerable function flask.Flask.run is called | CVE-2022-29361 |\n\n</div>\n<details>\n<summary> <b>Description</b> </summary>\n<br>\nThe scanner checks whether the vulnerable `Development Server` of the `werkzeug` library is used by looking for calls to `werkzeug.serving.run_simple()`.\n\n</details>\n<details>\n<summary> <b>CVE details</b> </summary>\n<br>\ncveDetails\n\n</details>\n",
		},
	}

	so := &StandardOutput{}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			output := so.ApplicableCveReviewContent(tc.severity, tc.finding, tc.fullDetails, tc.cve, tc.cveDetails, tc.impactedDependency, tc.remediation)
			assert.Equal(t, tc.expectedOutput, output)
		})
	}
}

func TestStandardOutput_IacReviewContent(t *testing.T) {
	testCases := []struct {
		name                           string
		severity, finding, fullDetails string
		expectedOutput                 string
	}{
		{
			name:           "Iac review comment content",
			severity:       "Medium",
			finding:        "Missing auto upgrade was detected",
			fullDetails:    "Resource `google_container_node_pool` should have `management.auto_upgrade=true`\n\nVulnerable example - \n```\nresource \"google_container_node_pool\" \"vulnerable_example\" {\n    management {\n     auto_upgrade = false\n   }\n}\n```\n",
			expectedOutput: "\n## 🛠️ Infrastructure as Code\n<div align=\"center\">\n\n| Severity | Finding |\n| :--------------: | :---: |\n| ![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/applicableMediumSeverity.png)<br>  Medium | Missing auto upgrade was detected |\n\n</div>\n<details>\n<summary> <b>Full description</b> </summary>\n<br>\nResource `google_container_node_pool` should have `management.auto_upgrade=true`\n\nVulnerable example - \n```\nresource \"google_container_node_pool\" \"vulnerable_example\" {\n    management {\n     auto_upgrade = false\n   }\n}\n```\n\n\n</details>\n",
		},
	}

	so := &StandardOutput{}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			output := IacReviewContent(tc.severity, tc.finding, tc.fullDetails, so)
			assert.Equal(t, tc.expectedOutput, output)
		})
	}
}

func TestStandardOutput_SastReviewContent(t *testing.T) {
	testCases := []struct {
		name           string
		severity       string
		finding        string
		fullDetails    string
		expectedOutput string
		codeFlows      [][]formats.Location
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
			expectedOutput: "\n## 🎯 Static Application Security Testing (SAST) Vulnerability\n<div align=\"center\">\n\n| Severity | Finding |\n| :--------------: | :---: |\n| ![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/applicableLowSeverity.png)<br>     Low | Stack Trace Exposure |\n\n</div>\n<details>\n<summary> <b>Full description</b> </summary>\n<br>\n\n### Overview\nStack trace exposure is a type of security vulnerability that occurs when a program reveals\nsensitive information, such as the names and locations of internal files and variables,\nin error messages or other diagnostic output. This can happen when a program crashes or\nencounters an error, and the stack trace (a record of the program's call stack at the time\nof the error) is included in the output.\n\n</details>\n\n<details>\n<summary> <b>Code Flows</b> </summary>\n<br>\n\n<details>\n<summary> <b>Vulnerable data flow analysis result</b> </summary>\n<br>\n\n↘️ `other-snippet` (at file2 line 1)\n\n↘️ `snippet` (at file line 0)\n\n\n</details>\n<details>\n<summary> <b>Vulnerable data flow analysis result</b> </summary>\n<br>\n\n↘️ `a-snippet` (at file line 10)\n\n↘️ `snippet` (at file line 0)\n\n\n</details>\n\n</details>\n",
		},
		{
			name:           "No code flows",
			severity:       "Low",
			finding:        "Stack Trace Exposure",
			fullDetails:    "\n### Overview\nStack trace exposure is a type of security vulnerability that occurs when a program reveals\nsensitive information, such as the names and locations of internal files and variables,\nin error messages or other diagnostic output. This can happen when a program crashes or\nencounters an error, and the stack trace (a record of the program's call stack at the time\nof the error) is included in the output.",
			expectedOutput: "\n## 🎯 Static Application Security Testing (SAST) Vulnerability\n<div align=\"center\">\n\n| Severity | Finding |\n| :--------------: | :---: |\n| ![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/applicableLowSeverity.png)<br>     Low | Stack Trace Exposure |\n\n</div>\n<details>\n<summary> <b>Full description</b> </summary>\n<br>\n\n### Overview\nStack trace exposure is a type of security vulnerability that occurs when a program reveals\nsensitive information, such as the names and locations of internal files and variables,\nin error messages or other diagnostic output. This can happen when a program crashes or\nencounters an error, and the stack trace (a record of the program's call stack at the time\nof the error) is included in the output.\n\n</details>\n",
		},
	}

	so := &StandardOutput{}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			output := so.SastReviewContent(tc.severity, tc.finding, tc.fullDetails, tc.codeFlows)
			assert.Equal(t, tc.expectedOutput, output)
		})
	}
}
