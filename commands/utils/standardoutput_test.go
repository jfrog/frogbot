package utils

import (
	"fmt"
	"github.com/jfrog/froggit-go/vcsutils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-core/v2/xray/formats"
	"github.com/stretchr/testify/assert"
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
				Severity:                  "Critical",
				ImpactedDependencyName:    "testdep",
				ImpactedDependencyVersion: "1.0.0",
				FixedVersions:             []string{"2.0.0"},
				Cves:                      []formats.CveRow{{Id: "CVE-2022-1234"}},
			},
			expected: "| ![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/applicableCriticalSeverity.png)<br>Critical |  | testdep:1.0.0 | 2.0.0 |",
		},
		{
			name: "Multiple CVEs and no direct dependencies",
			vulnerability: formats.VulnerabilityOrViolationRow{
				Severity:                  "High",
				ImpactedDependencyName:    "testdep2",
				ImpactedDependencyVersion: "1.0.0",
				FixedVersions:             []string{"2.0.0", "3.0.0"},
				Cves: []formats.CveRow{
					{Id: "CVE-2022-1234"},
					{Id: "CVE-2022-5678"},
				},
			},
			expected: "| ![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/applicableHighSeverity.png)<br>    High |  | testdep2:1.0.0 | 2.0.0<br><br>3.0.0 |",
		},
		{
			name: "Single CVE and direct dependencies",
			vulnerability: formats.VulnerabilityOrViolationRow{
				Severity:                  "Low",
				ImpactedDependencyName:    "testdep3",
				ImpactedDependencyVersion: "1.0.0",
				FixedVersions:             []string{"2.0.0"},
				Cves:                      []formats.CveRow{{Id: "CVE-2022-1234"}},
				Components: []formats.ComponentRow{
					{Name: "dep1", Version: "1.0.0"},
					{Name: "dep2", Version: "2.0.0"},
				},
			},
			expected: "| ![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/applicableLowSeverity.png)<br>     Low | dep1:1.0.0<br><br>dep2:2.0.0 | testdep3:1.0.0 | 2.0.0 |",
		},
		{
			name: "Multiple CVEs and direct dependencies",
			vulnerability: formats.VulnerabilityOrViolationRow{
				Severity: "High",
				Cves: []formats.CveRow{
					{Id: "CVE-1"},
					{Id: "CVE-2"},
				},
				Components: []formats.ComponentRow{
					{Name: "dep1", Version: "1.0.0"},
					{Name: "dep2", Version: "2.0.0"},
				},
				ImpactedDependencyName:    "impacted",
				ImpactedDependencyVersion: "3.0.0",
				FixedVersions:             []string{"4.0.0", "5.0.0"},
			},
			expected: "| ![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/applicableHighSeverity.png)<br>    High | dep1:1.0.0<br><br>dep2:2.0.0 | impacted:3.0.0 | 4.0.0<br><br>5.0.0 |",
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
			ImpactedDependencyName:    "Dependency1",
			ImpactedDependencyVersion: "1.0.0",
		},
		{
			ImpactedDependencyName:    "Dependency2",
			ImpactedDependencyVersion: "2.0.0",
		},
	}

	// Set the expected content string based on the sample data
	expectedContent := fmt.Sprintf(`
## 📦 Vulnerable Dependencies 

### ✍️ Summary

<div align="center">

%s %s

</div>

## 👇 Details


<details>
<summary> <b>%s %s</b> </summary>
<br>
%s

</details>


<details>
<summary> <b>%s %s</b> </summary>
<br>
%s

</details>

`,
		so.VulnerabilitiesTableHeader(),
		getVulnerabilitiesTableContent(vulnerabilitiesRows, so),
		vulnerabilitiesRows[0].ImpactedDependencyName,
		vulnerabilitiesRows[0].ImpactedDependencyVersion,
		createVulnerabilityDescription(&vulnerabilitiesRows[0]),
		vulnerabilitiesRows[1].ImpactedDependencyName,
		vulnerabilitiesRows[1].ImpactedDependencyVersion,
		createVulnerabilityDescription(&vulnerabilitiesRows[1]),
	)

	actualContent := so.VulnerabilitiesContent(vulnerabilitiesRows)
	assert.Equal(t, expectedContent, actualContent, "Content mismatch")
}

func TestStandardOutput_ContentWithContextualAnalysis(t *testing.T) {
	// Create a new instance of StandardOutput
	so := &StandardOutput{entitledForJas: true, vcsProvider: vcsutils.GitHub}

	// Create some sample vulnerabilitiesRows for testing
	vulnerabilitiesRows := []formats.VulnerabilityOrViolationRow{
		{
			ImpactedDependencyName:    "Dependency1",
			ImpactedDependencyVersion: "1.0.0",
			Applicable:                "Applicable",
			Technology:                coreutils.Pip,
		},
		{
			ImpactedDependencyName:    "Dependency2",
			ImpactedDependencyVersion: "2.0.0",
			Applicable:                "Not Applicable",
			Technology:                coreutils.Pip,
		},
	}

	// Set the expected content string based on the sample data
	expectedContent := fmt.Sprintf(`
## 📦 Vulnerable Dependencies 

### ✍️ Summary

<div align="center">

%s %s

</div>

## 👇 Details


<details>
<summary> <b>%s %s</b> </summary>
<br>
%s

</details>


<details>
<summary> <b>%s %s</b> </summary>
<br>
%s

</details>

`,
		so.VulnerabilitiesTableHeader(),
		getVulnerabilitiesTableContent(vulnerabilitiesRows, so),
		vulnerabilitiesRows[0].ImpactedDependencyName,
		vulnerabilitiesRows[0].ImpactedDependencyVersion,
		createVulnerabilityDescription(&vulnerabilitiesRows[0]),
		vulnerabilitiesRows[1].ImpactedDependencyName,
		vulnerabilitiesRows[1].ImpactedDependencyVersion,
		createVulnerabilityDescription(&vulnerabilitiesRows[1]),
	)

	actualContent := so.VulnerabilitiesContent(vulnerabilitiesRows)
	assert.Equal(t, expectedContent, actualContent, "Content mismatch")
	assert.Contains(t, actualContent, "CONTEXTUAL ANALYSIS")
	assert.Contains(t, actualContent, "| Applicable |")
	assert.Contains(t, actualContent, "| Not Applicable |")
}

func TestStandardOutput_IacContent(t *testing.T) {
	testCases := []struct {
		name           string
		iacRows        []formats.IacSecretsRow
		expectedOutput string
	}{
		{
			name:           "Empty IAC rows",
			iacRows:        []formats.IacSecretsRow{},
			expectedOutput: "",
		},
		{
			name: "Single IAC row",
			iacRows: []formats.IacSecretsRow{
				{
					Severity:         "High",
					SeverityNumValue: 3,
					File:             "applicable/req_sw_terraform_azure_redis_auth.tf",
					LineColumn:       "11:1",
					Text:             "Missing Periodic patching was detected",
				},
			},
			expectedOutput: "\n## 🛠️ Infrastructure as Code \n\n<div align=\"center\">\n\n\n| SEVERITY                | FILE                  | LINE:COLUMN                   | FINDING                       |\n| :---------------------: | :----------------------------------: | :-----------------------------------: | :---------------------------------: | \n| ![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/applicableHighSeverity.png)<br>    High | applicable/req_sw_terraform_azure_redis_auth.tf | 11:1 | Missing Periodic patching was detected |\n\n</div>\n\n",
		},
		{
			name: "Multiple IAC rows",
			iacRows: []formats.IacSecretsRow{
				{
					Severity:         "High",
					SeverityNumValue: 3,
					File:             "applicable/req_sw_terraform_azure_redis_patch.tf",
					LineColumn:       "11:1",
					Text:             "Missing redis firewall definition or start_ip=0.0.0.0 was detected, Missing redis firewall definition or start_ip=0.0.0.0 was detected",
				},
				{
					Severity:         "High",
					SeverityNumValue: 3,
					File:             "applicable/req_sw_terraform_azure_redis_auth.tf",
					LineColumn:       "11:1",
					Text:             "Missing Periodic patching was detected",
				},
			},
			expectedOutput: "\n## 🛠️ Infrastructure as Code \n\n<div align=\"center\">\n\n\n| SEVERITY                | FILE                  | LINE:COLUMN                   | FINDING                       |\n| :---------------------: | :----------------------------------: | :-----------------------------------: | :---------------------------------: | \n| ![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/applicableHighSeverity.png)<br>    High | applicable/req_sw_terraform_azure_redis_patch.tf | 11:1 | Missing redis firewall definition or start_ip=0.0.0.0 was detected, Missing redis firewall definition or start_ip=0.0.0.0 was detected |\n| ![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/applicableHighSeverity.png)<br>    High | applicable/req_sw_terraform_azure_redis_auth.tf | 11:1 | Missing Periodic patching was detected |\n\n</div>\n\n",
		},
	}

	writer := &StandardOutput{}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			output := writer.IacContent(tc.iacRows)
			assert.Equal(t, tc.expectedOutput, output)
		})
	}
}

func TestStandardOutput_GetIacTableContent(t *testing.T) {
	testCases := []struct {
		name           string
		iacRows        []formats.IacSecretsRow
		expectedOutput string
	}{
		{
			name:           "Empty IAC rows",
			iacRows:        []formats.IacSecretsRow{},
			expectedOutput: "",
		},
		{
			name: "Single IAC row",
			iacRows: []formats.IacSecretsRow{
				{
					Severity:         "Medium",
					SeverityNumValue: 2,
					File:             "file1",
					LineColumn:       "1:10",
					Text:             "Public access to MySQL was detected",
					Type:             "azure_mysql_no_public",
				},
			},
			expectedOutput: "\n| ![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/applicableMediumSeverity.png)<br>  Medium | file1 | 1:10 | Public access to MySQL was detected |",
		},
		{
			name: "Multiple IAC rows",
			iacRows: []formats.IacSecretsRow{
				{
					Severity:         "High",
					SeverityNumValue: 3,
					File:             "file1",
					LineColumn:       "1:10",
					Text:             "Public access to MySQL was detected",
					Type:             "azure_mysql_no_public",
				},
				{
					Severity:         "Medium",
					SeverityNumValue: 2,
					File:             "file2",
					LineColumn:       "2:5",
					Text:             "Public access to MySQL was detected",
					Type:             "azure_mysql_no_public",
				},
			},
			expectedOutput: "\n| ![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/applicableHighSeverity.png)<br>    High | file1 | 1:10 | Public access to MySQL was detected |\n| ![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/applicableMediumSeverity.png)<br>  Medium | file2 | 2:5 | Public access to MySQL was detected |",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			output := getIacTableContent(tc.iacRows, &StandardOutput{})
			assert.Equal(t, tc.expectedOutput, output)
		})
	}
}
