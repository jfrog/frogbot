package outputwriter

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// func TestSimplifiedOutput_VulnerabilitiesTableRow(t *testing.T) {
// 	type testCase struct {
// 		name           string
// 		vulnerability  formats.VulnerabilityOrViolationRow
// 		expectedOutput string
// 		showCaColumn   bool
// 	}

// 	testCases := []testCase{
// 		{
// 			name: "Single CVE and one direct dependency",
// 			vulnerability: formats.VulnerabilityOrViolationRow{
// 				ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
// 					SeverityDetails:           formats.SeverityDetails{Severity: "High"},
// 					ImpactedDependencyName:    "impacted_dep",
// 					ImpactedDependencyVersion: "2.0.0",
// 					Components: []formats.ComponentRow{
// 						{Name: "dep1", Version: "1.0.0"},
// 					},
// 				},
// 				FixedVersions: []string{"3.0.0"},
// 				Cves: []formats.CveRow{
// 					{Id: "CVE-2022-0001"},
// 				},
// 				Technology: coreutils.Nuget,
// 			},
// 			expectedOutput: "| High |  dep1:1.0.0 | impacted_dep:2.0.0 | 3.0.0 | CVE-2022-0001 |",
// 		},
// 		{
// 			name: "No CVE and multiple direct dependencies",
// 			vulnerability: formats.VulnerabilityOrViolationRow{
// 				ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
// 					SeverityDetails:           formats.SeverityDetails{Severity: "Low"},
// 					ImpactedDependencyName:    "impacted_dep",
// 					ImpactedDependencyVersion: "3.0.0",
// 					Components: []formats.ComponentRow{
// 						{Name: "dep1", Version: "1.0.0"},
// 						{Name: "dep2", Version: "2.0.0"},
// 					},
// 				},
// 				FixedVersions: []string{"4.0.0", "4.1.0", "4.2.0", "5.0.0"},
// 				Cves:          []formats.CveRow{},
// 				Technology:    coreutils.Dotnet,
// 			},
// 			expectedOutput: "| Low |  dep1:1.0.0 | impacted_dep:3.0.0 | 4.0.0, 4.1.0, 4.2.0, 5.0.0 |  -  |\n|  | dep2:2.0.0 |  |  |",
// 		},
// 		{
// 			name: "Multiple CVEs",
// 			vulnerability: formats.VulnerabilityOrViolationRow{
// 				ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
// 					SeverityDetails:           formats.SeverityDetails{Severity: "Critical"},
// 					ImpactedDependencyName:    "impacted_dep",
// 					ImpactedDependencyVersion: "4.0.0",
// 					Components:                []formats.ComponentRow{{Name: "direct", Version: "1.0.2"}},
// 				},
// 				Applicable:    "Applicable",
// 				FixedVersions: []string{"5.0.0", "6.0.0"},
// 				Cves: []formats.CveRow{
// 					{Id: "CVE-2022-0002"},
// 					{Id: "CVE-2022-0003"},
// 				},
// 				Technology: coreutils.Pip,
// 			},
// 			expectedOutput: "| Critical | Applicable | direct:1.0.2 | impacted_dep:4.0.0 | 5.0.0, 6.0.0 | CVE-2022-0002, CVE-2022-0003 |",
// 			showCaColumn:   true,
// 		},
// 	}

// 	for _, tc := range testCases {
// 		t.Run(tc.name, func(t *testing.T) {
// 			smo := &SimplifiedOutput{entitledForJas: true, showCaColumn: tc.showCaColumn}
// 			actualOutput := smo.VulnerabilitiesTableRow(tc.vulnerability)
// 			assert.Equal(t, tc.expectedOutput, actualOutput)
// 		})
// 	}
// }

// func TestSimplifiedOutput_VulnerabilitiesContent(t *testing.T) {
// 	// Create a new instance of StandardOutput
// 	so := &SimplifiedOutput{}

// 	// Create some sample vulnerabilitiesRows for testing
// 	vulnerabilitiesRows := []formats.VulnerabilityOrViolationRow{
// 		{
// 			Summary: "CVE-2023-1234 summary",
// 			ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
// 				SeverityDetails:           formats.SeverityDetails{Severity: "Critical"},
// 				ImpactedDependencyName:    "Dependency1",
// 				ImpactedDependencyVersion: "1.0.0",
// 				Components:                []formats.ComponentRow{{Name: "Direct1", Version: "1.0.0"}, {Name: "Direct2", Version: "2.0.0"}},
// 			},
// 			FixedVersions: []string{"2.2.3"},
// 			Cves:          []formats.CveRow{{Id: "CVE-2023-1234"}},
// 		},
// 		{
// 			ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
// 				SeverityDetails:           formats.SeverityDetails{Severity: "High"},
// 				ImpactedDependencyName:    "Dependency2",
// 				ImpactedDependencyVersion: "2.0.0",
// 				Components:                []formats.ComponentRow{{Name: "Direct1", Version: "1.0.0"}, {Name: "Direct2", Version: "2.0.0"}},
// 			},
// 			FixedVersions: []string{"2.2.3"},
// 			Cves:          []formats.CveRow{{Id: "CVE-2023-1234"}},
// 		},
// 	}

// 	// Set the expected content string based on the sample data
// 	expectedContent := fmt.Sprintf(`
// ---
// ## 📦 Vulnerable Dependencies
// ---

// ---
// ### ✍️ Summary
// ---

// %s %s

// ---
// ### 🔬 Research Details
// ---

// ---
// #### %s %s %s
// ---
// %s

// `,
// 		getVulnerabilitiesTableHeader(false),
// 		getVulnerabilitiesTableContent(vulnerabilitiesRows, so),
// 		fmt.Sprintf("[ %s ]", vulnerabilitiesRows[0].Cves[0].Id),
// 		vulnerabilitiesRows[0].ImpactedDependencyName,
// 		vulnerabilitiesRows[0].ImpactedDependencyVersion,
// 		createVulnerabilityDescription(&vulnerabilitiesRows[0]),
// 	)

// 	actualContent := VulnerabilitiesContent(vulnerabilitiesRows, so)
// 	assert.Equal(t, expectedContent, actualContent, "Content mismatch")

// 	vulnerabilitiesRows = []formats.VulnerabilityOrViolationRow{}
// 	expectedContent = ""
// 	actualContent = VulnerabilitiesContent(vulnerabilitiesRows, so)
// 	assert.Equal(t, expectedContent, actualContent, "Content mismatch")
// }

// func TestSimplifiedOutput_ContentWithContextualAnalysis(t *testing.T) {
// 	// Create a new instance of StandardOutput
// 	so := &SimplifiedOutput{entitledForJas: true, vcsProvider: vcsutils.BitbucketServer, showCaColumn: true}

// 	vulnerabilitiesRows := []formats.VulnerabilityOrViolationRow{
// 		{
// 			ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
// 				SeverityDetails:           formats.SeverityDetails{Severity: "High"},
// 				ImpactedDependencyName:    "Dependency1",
// 				ImpactedDependencyVersion: "1.0.0",
// 				Components:                []formats.ComponentRow{{Name: "Direct1", Version: "1.0.0"}, {Name: "Direct2", Version: "2.0.0"}},
// 			},
// 			FixedVersions: []string{"2.2.3"},
// 			Cves:          []formats.CveRow{{Id: "CVE-2023-1234"}},
// 			Applicable:    utils.Applicable.String(),
// 			Technology:    coreutils.Npm,
// 		},
// 		{
// 			Summary: "CVE-2023-1234 summary",
// 			ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
// 				SeverityDetails:           formats.SeverityDetails{Severity: "Low"},
// 				ImpactedDependencyName:    "Dependency2",
// 				ImpactedDependencyVersion: "2.0.0",
// 				Components:                []formats.ComponentRow{{Name: "Direct1", Version: "1.0.0"}, {Name: "Direct2", Version: "2.0.0"}},
// 			},
// 			FixedVersions: []string{"2.2.3"},
// 			Cves:          []formats.CveRow{{Id: "CVE-2024-1234"}},
// 			Applicable:    "Not Applicable",
// 			Technology:    coreutils.Poetry,
// 		},
// 	}

// 	expectedContent := fmt.Sprintf(`
// ---
// ## 📦 Vulnerable Dependencies
// ---

// ---
// ### ✍️ Summary
// ---

// %s %s

// ---
// ### 🔬 Research Details
// ---

// ---
// #### %s %s %s
// ---
// %s

// `,
// 		getVulnerabilitiesTableHeader(true),
// 		getVulnerabilitiesTableContent(vulnerabilitiesRows, so),
// 		fmt.Sprintf("[ %s ]", "CVE-2024-1234"),
// 		vulnerabilitiesRows[1].ImpactedDependencyName,
// 		vulnerabilitiesRows[1].ImpactedDependencyVersion,
// 		createVulnerabilityDescription(&vulnerabilitiesRows[1]),
// 	)

// 	actualContent := VulnerabilitiesContent(vulnerabilitiesRows, so)
// 	assert.Equal(t, expectedContent, actualContent, "Content mismatch")
// 	assert.Contains(t, actualContent, "CONTEXTUAL ANALYSIS")
// 	assert.Contains(t, actualContent, "| Applicable |")
// 	assert.Contains(t, actualContent, "| Not Applicable |")
// }

// func TestSimplifiedOutput_GetLicensesTableContent(t *testing.T) {
// 	writer := &SimplifiedOutput{}
// 	testGetLicensesTableContent(t, writer)
// }

func TestSimplifiedOutput_ApplicableCveReviewContent(t *testing.T) {
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
			expectedOutput:     "\n\n---\n## 📦🔍 Contextual Analysis CVE Vulnerability\n---\n\n| Severity | Impacted Dependency | Finding | CVE |\n| :--------------: | :---: | :---: | :---: |\n| Critical | werkzeug:1.0.1 | The vulnerable function flask.Flask.run is called | CVE-2022-29361 |\n---\n### Description\n---\nThe scanner checks whether the vulnerable `Development Server` of the `werkzeug` library is used by looking for calls to `werkzeug.serving.run_simple()`.\n---\n### CVE details\n---\ncveDetails\n\n---\n### Remediation\n---\nsome remediation\n",
		},
		{
			name:               "No remediation",
			severity:           "Critical",
			finding:            "The vulnerable function flask.Flask.run is called",
			fullDetails:        "The scanner checks whether the vulnerable `Development Server` of the `werkzeug` library is used by looking for calls to `werkzeug.serving.run_simple()`.",
			cve:                "CVE-2022-29361",
			cveDetails:         "cveDetails",
			impactedDependency: "werkzeug:1.0.1",
			expectedOutput:     "\n\n---\n## 📦🔍 Contextual Analysis CVE Vulnerability\n---\n\n| Severity | Impacted Dependency | Finding | CVE |\n| :--------------: | :---: | :---: | :---: |\n| Critical | werkzeug:1.0.1 | The vulnerable function flask.Flask.run is called | CVE-2022-29361 |\n---\n### Description\n---\nThe scanner checks whether the vulnerable `Development Server` of the `werkzeug` library is used by looking for calls to `werkzeug.serving.run_simple()`.\n---\n### CVE details\n---\ncveDetails\n",
		},
	}

	so := &SimplifiedOutput{}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			output := ApplicableCveReviewContent(tc.severity, tc.finding, tc.fullDetails, tc.cve, tc.cveDetails, tc.impactedDependency, tc.remediation, so)
			assert.Equal(t, tc.expectedOutput, output)
		})
	}
}

func TestSimplifiedOutput_IacReviewContent(t *testing.T) {
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
			expectedOutput: "\n\n---\n## 🛠️ Infrastructure as Code\n---\n\n| Severity | Finding |\n| :--------------: | :---: |\n| Medium | Missing auto upgrade was detected |\n---\n### Full description\n---\nResource `google_container_node_pool` should have `management.auto_upgrade=true`\n\nVulnerable example - \n```\nresource \"google_container_node_pool\" \"vulnerable_example\" {\n    management {\n     auto_upgrade = false\n   }\n}\n```\n\n",
		},
	}

	so := &SimplifiedOutput{}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			output := IacReviewContent(tc.severity, tc.finding, tc.fullDetails, so)
			assert.Equal(t, tc.expectedOutput, output)
		})
	}
}
