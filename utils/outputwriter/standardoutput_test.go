package outputwriter

import (
)

// func TestStandardOutput_TableRow(t *testing.T) {
// 	var tests = []struct {
// 		vulnerability formats.VulnerabilityOrViolationRow
// 		expected      string
// 		name          string
// 	}{
// 		{
// 			name: "Single CVE and no direct dependencies",
// 			vulnerability: formats.VulnerabilityOrViolationRow{
// 				ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
// 					SeverityDetails:           formats.SeverityDetails{Severity: "Critical"},
// 					ImpactedDependencyName:    "testdep",
// 					ImpactedDependencyVersion: "1.0.0",
// 				},
// 				FixedVersions: []string{"2.0.0"},
// 				Cves:          []formats.CveRow{{Id: "CVE-2022-1234"}},
// 			},
// 			expected: "| ![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/applicableCriticalSeverity.png)<br>Critical |  | testdep:1.0.0 | 2.0.0 | CVE-2022-1234 |",
// 		},
// 		{
// 			name: "Multiple CVEs and no direct dependencies",
// 			vulnerability: formats.VulnerabilityOrViolationRow{
// 				ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
// 					SeverityDetails:           formats.SeverityDetails{Severity: "High"},
// 					ImpactedDependencyName:    "testdep2",
// 					ImpactedDependencyVersion: "1.0.0",
// 				},
// 				FixedVersions: []string{"2.0.0", "3.0.0"},
// 				Cves: []formats.CveRow{
// 					{Id: "CVE-2022-1234"},
// 					{Id: "CVE-2022-5678"},
// 				},
// 			},
// 			expected: "| ![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/applicableHighSeverity.png)<br>    High |  | testdep2:1.0.0 | 2.0.0<br>3.0.0 | CVE-2022-1234<br>CVE-2022-5678 |",
// 		},
// 		{
// 			name: "Single CVE and direct dependencies",
// 			vulnerability: formats.VulnerabilityOrViolationRow{
// 				ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
// 					SeverityDetails:           formats.SeverityDetails{Severity: "Low"},
// 					ImpactedDependencyName:    "testdep3",
// 					ImpactedDependencyVersion: "1.0.0",
// 					Components: []formats.ComponentRow{
// 						{Name: "dep1", Version: "1.0.0"},
// 						{Name: "dep2", Version: "2.0.0"},
// 					},
// 				},
// 				FixedVersions: []string{"2.0.0"},
// 				Cves:          []formats.CveRow{{Id: "CVE-2022-1234"}},
// 			},
// 			expected: "| ![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/applicableLowSeverity.png)<br>     Low | dep1:1.0.0<br>dep2:2.0.0 | testdep3:1.0.0 | 2.0.0 | CVE-2022-1234 |",
// 		},
// 		{
// 			name: "Multiple CVEs and direct dependencies",
// 			vulnerability: formats.VulnerabilityOrViolationRow{
// 				ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
// 					SeverityDetails:           formats.SeverityDetails{Severity: "High"},
// 					ImpactedDependencyName:    "impacted",
// 					ImpactedDependencyVersion: "3.0.0",
// 					Components: []formats.ComponentRow{
// 						{Name: "dep1", Version: "1.0.0"},
// 						{Name: "dep2", Version: "2.0.0"},
// 					},
// 				},
// 				Cves: []formats.CveRow{
// 					{Id: "CVE-1"},
// 					{Id: "CVE-2"},
// 				},
// 				FixedVersions: []string{"4.0.0", "5.0.0"},
// 			},
// 			expected: "| ![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/applicableHighSeverity.png)<br>    High | dep1:1.0.0<br>dep2:2.0.0 | impacted:3.0.0 | 4.0.0<br>5.0.0 | CVE-1<br>CVE-2 |",
// 		},
// 	}

// 	for _, tc := range tests {
// 		t.Run(tc.name, func(t *testing.T) {
// 			smo := &StandardOutput{}
// 			actualOutput := VulnerabilitiesTableRow(tc.vulnerability, smo)
// 			assert.Equal(t, tc.expected, actualOutput)
// 		})
// 	}
// }

// func TestStandardOutput_VulnerabilitiesContent(t *testing.T) {
// 	// Create a new instance of StandardOutput
// 	so := &StandardOutput{}

// 	// Create some sample vulnerabilitiesRows for testing
// 	vulnerabilitiesRows := []formats.VulnerabilityOrViolationRow{
// 		{
// 			Summary: "CVE-2023-1234 summary",
// 			ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
// 				ImpactedDependencyName:    "Dependency1",
// 				ImpactedDependencyVersion: "1.0.0",
// 			},
// 		},
// 		{
// 			Summary: "CVE-2023-1234 summary",
// 			ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
// 				ImpactedDependencyName:    "Dependency2",
// 				ImpactedDependencyVersion: "2.0.0",
// 			},
// 		},
// 	}

// 	// Set the expected content string based on the sample data
// 	expectedContent := fmt.Sprintf(`
// ## 📦 Vulnerable Dependencies
// ### ✍️ Summary

// <div align="center">

// %s %s

// </div>

// <details>
// <summary> <b>🔬 Research Details</b> </summary>
// <br>

// <details>
// <summary> <b>%s%s %s</b> </summary>
// <br>
// %s

// </details>

// <details>
// <summary> <b>%s%s %s</b> </summary>
// <br>
// %s

// </details>

// </details>
// `,
// 		getVulnerabilitiesTableHeader(false),
// 		getVulnerabilitiesTableContent(vulnerabilitiesRows, so),
// 		"",
// 		vulnerabilitiesRows[0].ImpactedDependencyName,
// 		vulnerabilitiesRows[0].ImpactedDependencyVersion,
// 		createVulnerabilityDescription(&vulnerabilitiesRows[0]),
// 		"",
// 		vulnerabilitiesRows[1].ImpactedDependencyName,
// 		vulnerabilitiesRows[1].ImpactedDependencyVersion,
// 		createVulnerabilityDescription(&vulnerabilitiesRows[1]),
// 	)

// 	actualContent := so.VulnerabilitiesContent(vulnerabilitiesRows)
// 	assert.Equal(t, expectedContent, actualContent, "Content mismatch")
// }

// func TestStandardOutput_ContentWithContextualAnalysis(t *testing.T) {
// 	// Create a new instance of StandardOutput
// 	so := &StandardOutput{entitledForJas: true, vcsProvider: vcsutils.GitHub, showCaColumn: true}

// 	vulnerabilitiesRows := []formats.VulnerabilityOrViolationRow{}
// 	expectedContent := ""
// 	actualContent := VulnerabilitiesContent(vulnerabilitiesRows, so)
// 	assert.Equal(t, expectedContent, actualContent)

// 	// Create some sample vulnerabilitiesRows for testing
// 	vulnerabilitiesRows = []formats.VulnerabilityOrViolationRow{
// 		{
// 			Summary: "CVE-2023-1234 summary",
// 			ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
// 				ImpactedDependencyName:    "Dependency1",
// 				ImpactedDependencyVersion: "1.0.0",
// 			},
// 			Applicable: "Applicable",
// 			Technology: coreutils.Pip,
// 			Cves:       []formats.CveRow{{Id: "CVE-2023-1234"}, {Id: "CVE-2023-4321"}},
// 		},
// 		{
// 			Summary: "CVE-2023-1234 summary",
// 			ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
// 				ImpactedDependencyName:    "Dependency2",
// 				ImpactedDependencyVersion: "2.0.0",
// 			},
// 			Applicable: "Not Applicable",
// 			Technology: coreutils.Pip,
// 			Cves:       []formats.CveRow{{Id: "CVE-2022-4321"}},
// 		},
// 	}

// 	// Set the expected content string based on the sample data
// 	expectedContent = fmt.Sprintf(`
// ## 📦 Vulnerable Dependencies
// ### ✍️ Summary

// <div align="center">

// %s %s

// </div>

// <details>
// <summary> <b>🔬 Research Details</b> </summary>
// <br>

// <details>
// <summary> <b>%s%s %s</b> </summary>
// <br>
// %s

// </details>

// <details>
// <summary> <b>%s%s %s</b> </summary>
// <br>
// %s

// </details>

// </details>
// `,
// 		getVulnerabilitiesTableHeader(true),
// 		getVulnerabilitiesTableContent(vulnerabilitiesRows, so),
// 		fmt.Sprintf("[ %s ] ", strings.Join([]string{vulnerabilitiesRows[0].Cves[0].Id, vulnerabilitiesRows[0].Cves[1].Id}, ", ")),
// 		vulnerabilitiesRows[0].ImpactedDependencyName,
// 		vulnerabilitiesRows[0].ImpactedDependencyVersion,
// 		createVulnerabilityDescription(&vulnerabilitiesRows[0]),
// 		fmt.Sprintf("[ %s ] ", strings.Join([]string{vulnerabilitiesRows[1].Cves[0].Id}, ",")),
// 		vulnerabilitiesRows[1].ImpactedDependencyName,
// 		vulnerabilitiesRows[1].ImpactedDependencyVersion,
// 		createVulnerabilityDescription(&vulnerabilitiesRows[1]),
// 	)

// 	actualContent = VulnerabilitiesContent(vulnerabilitiesRows, so)
// 	assert.Equal(t, expectedContent, actualContent, "Content mismatch")
// 	assert.Contains(t, actualContent, "CONTEXTUAL ANALYSIS")
// 	assert.Contains(t, actualContent, "| Applicable |")
// 	assert.Contains(t, actualContent, "| Not Applicable |")
// }

// func TestStandardOutput_GetLicensesTableContent(t *testing.T) {
// 	writer := &StandardOutput{}
// 	testGetLicensesTableContent(t, writer)
// }
