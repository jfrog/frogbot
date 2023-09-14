package outputwriter

import (
	"fmt"
	"github.com/jfrog/froggit-go/vcsutils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-core/v2/xray/formats"
	"github.com/jfrog/jfrog-cli-core/v2/xray/utils"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestSimplifiedOutput_VulnerabilitiesTableRow(t *testing.T) {
	type testCase struct {
		name           string
		vulnerability  formats.VulnerabilityOrViolationRow
		expectedOutput string
		showCaColumn   bool
	}

	testCases := []testCase{
		{
			name: "Single CVE and one direct dependency",
			vulnerability: formats.VulnerabilityOrViolationRow{
				ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
					SeverityDetails:           formats.SeverityDetails{Severity: "High"},
					ImpactedDependencyName:    "impacted_dep",
					ImpactedDependencyVersion: "2.0.0",
					Components: []formats.ComponentRow{
						{Name: "dep1", Version: "1.0.0"},
					},
				},
				FixedVersions: []string{"3.0.0"},
				Cves: []formats.CveRow{
					{Id: "CVE-2022-0001"},
				},
				Technology: coreutils.Nuget,
			},
			expectedOutput: "| High |  dep1:1.0.0 | impacted_dep:2.0.0 | 3.0.0 | CVE-2022-0001 |",
		},
		{
			name: "No CVE and multiple direct dependencies",
			vulnerability: formats.VulnerabilityOrViolationRow{
				ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
					SeverityDetails:           formats.SeverityDetails{Severity: "Low"},
					ImpactedDependencyName:    "impacted_dep",
					ImpactedDependencyVersion: "3.0.0",
					Components: []formats.ComponentRow{
						{Name: "dep1", Version: "1.0.0"},
						{Name: "dep2", Version: "2.0.0"},
					},
				},
				FixedVersions: []string{"4.0.0", "4.1.0", "4.2.0", "5.0.0"},
				Cves:          []formats.CveRow{},
				Technology:    coreutils.Dotnet,
			},
			expectedOutput: "| Low |  dep1:1.0.0 | impacted_dep:3.0.0 | 4.0.0, 4.1.0, 4.2.0, 5.0.0 |  -  |\n|  | dep2:2.0.0 |  |  |",
		},
		{
			name: "Multiple CVEs",
			vulnerability: formats.VulnerabilityOrViolationRow{
				ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
					SeverityDetails:           formats.SeverityDetails{Severity: "Critical"},
					ImpactedDependencyName:    "impacted_dep",
					ImpactedDependencyVersion: "4.0.0",
					Components:                []formats.ComponentRow{{Name: "direct", Version: "1.0.2"}},
				},
				Applicable:    "Applicable",
				FixedVersions: []string{"5.0.0", "6.0.0"},
				Cves: []formats.CveRow{
					{Id: "CVE-2022-0002"},
					{Id: "CVE-2022-0003"},
				},
				Technology: coreutils.Pip,
			},
			expectedOutput: "| Critical | Applicable | direct:1.0.2 | impacted_dep:4.0.0 | 5.0.0, 6.0.0 | CVE-2022-0002, CVE-2022-0003 |",
			showCaColumn:   true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			smo := &SimplifiedOutput{entitledForJas: true, showCaColumn: tc.showCaColumn}
			actualOutput := smo.VulnerabilitiesTableRow(tc.vulnerability)
			assert.Equal(t, tc.expectedOutput, actualOutput)
		})
	}
}

func TestSimplifiedOutput_IsFrogbotResultComment(t *testing.T) {
	testCases := []struct {
		name     string
		comment  string
		expected bool
	}{
		{
			name:     "Starts with No Vulnerability Banner",
			comment:  "**👍 Frogbot scanned this pull request and found that it did not add vulnerable dependencies.** \n",
			expected: true,
		},
		{
			name:     "Starts with Vulnerabilities Banner",
			comment:  "**🚨 Frogbot scanned this pull request and found the below:**\n",
			expected: true,
		},
		{
			name:     "Does not start with Banner",
			comment:  "This is a random comment.",
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			smo := &SimplifiedOutput{}
			actual := smo.IsFrogbotResultComment(tc.comment)
			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestSimplifiedOutput_VulnerabilitiesContent(t *testing.T) {
	// Create a new instance of StandardOutput
	so := &SimplifiedOutput{}

	// Create some sample vulnerabilitiesRows for testing
	vulnerabilitiesRows := []formats.VulnerabilityOrViolationRow{
		{
			ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
				SeverityDetails:           formats.SeverityDetails{Severity: "Critical"},
				ImpactedDependencyName:    "Dependency1",
				ImpactedDependencyVersion: "1.0.0",
				Components:                []formats.ComponentRow{{Name: "Direct1", Version: "1.0.0"}, {Name: "Direct2", Version: "2.0.0"}},
			},
			FixedVersions: []string{"2.2.3"},
			Cves:          []formats.CveRow{{Id: "CVE-2023-1234"}},
		},
		{
			ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
				SeverityDetails:           formats.SeverityDetails{Severity: "High"},
				ImpactedDependencyName:    "Dependency2",
				ImpactedDependencyVersion: "2.0.0",
				Components:                []formats.ComponentRow{{Name: "Direct1", Version: "1.0.0"}, {Name: "Direct2", Version: "2.0.0"}},
			},
			FixedVersions: []string{"2.2.3"},
			Cves:          []formats.CveRow{{Id: "CVE-2023-1234"}},
		},
	}

	// Set the expected content string based on the sample data
	expectedContent := fmt.Sprintf(`
---
## 📦 Vulnerable Dependencies
---

### ✍️ Summary

%s %s

---
## 🔬 Research Details
---


#### %s %s %s

%s

#### %s %s %s

%s
`,
		getVulnerabilitiesTableHeader(false),
		getVulnerabilitiesTableContent(vulnerabilitiesRows, so),
		fmt.Sprintf("[ %s ]", vulnerabilitiesRows[0].Cves[0].Id),
		vulnerabilitiesRows[0].ImpactedDependencyName,
		vulnerabilitiesRows[0].ImpactedDependencyVersion,
		createVulnerabilityDescription(&vulnerabilitiesRows[0]),
		fmt.Sprintf("[ %s ]", vulnerabilitiesRows[1].Cves[0].Id),
		vulnerabilitiesRows[1].ImpactedDependencyName,
		vulnerabilitiesRows[1].ImpactedDependencyVersion,
		createVulnerabilityDescription(&vulnerabilitiesRows[1]),
	)

	actualContent := so.VulnerabilitiesContent(vulnerabilitiesRows)
	assert.Equal(t, expectedContent, actualContent, "Content mismatch")

	vulnerabilitiesRows = []formats.VulnerabilityOrViolationRow{}
	expectedContent = ""
	actualContent = so.VulnerabilitiesContent(vulnerabilitiesRows)
	assert.Equal(t, expectedContent, actualContent, "Content mismatch")
}

func TestSimplifiedOutput_ContentWithContextualAnalysis(t *testing.T) {
	// Create a new instance of StandardOutput
	so := &SimplifiedOutput{entitledForJas: true, vcsProvider: vcsutils.BitbucketServer, showCaColumn: true}

	vulnerabilitiesRows := []formats.VulnerabilityOrViolationRow{
		{
			ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
				SeverityDetails:           formats.SeverityDetails{Severity: "High"},
				ImpactedDependencyName:    "Dependency1",
				ImpactedDependencyVersion: "1.0.0",
				Components:                []formats.ComponentRow{{Name: "Direct1", Version: "1.0.0"}, {Name: "Direct2", Version: "2.0.0"}},
			},
			FixedVersions: []string{"2.2.3"},
			Cves:          []formats.CveRow{{Id: "CVE-2023-1234"}},
			Applicable:    utils.Applicable.String(),
			Technology:    coreutils.Npm,
		},
		{
			ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
				SeverityDetails:           formats.SeverityDetails{Severity: "Low"},
				ImpactedDependencyName:    "Dependency2",
				ImpactedDependencyVersion: "2.0.0",
				Components:                []formats.ComponentRow{{Name: "Direct1", Version: "1.0.0"}, {Name: "Direct2", Version: "2.0.0"}},
			},
			FixedVersions: []string{"2.2.3"},
			Cves:          []formats.CveRow{{Id: "CVE-2024-1234"}},
			Applicable:    "Not Applicable",
			Technology:    coreutils.Poetry,
		},
	}

	expectedContent := fmt.Sprintf(`
---
## 📦 Vulnerable Dependencies
---

### ✍️ Summary

%s %s

---
## 🔬 Research Details
---


#### %s %s %s

%s

#### %s %s %s

%s
`,
		getVulnerabilitiesTableHeader(true),
		getVulnerabilitiesTableContent(vulnerabilitiesRows, so),
		fmt.Sprintf("[ %s ]", "CVE-2023-1234"),
		vulnerabilitiesRows[0].ImpactedDependencyName,
		vulnerabilitiesRows[0].ImpactedDependencyVersion,
		createVulnerabilityDescription(&vulnerabilitiesRows[0]),
		fmt.Sprintf("[ %s ]", "CVE-2024-1234"),
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

func TestSimplifiedOutput_IacContent(t *testing.T) {
	testCases := []struct {
		name           string
		iacRows        []formats.SourceCodeRow
		expectedOutput string
	}{
		{
			name:           "Empty IAC rows",
			iacRows:        []formats.SourceCodeRow{},
			expectedOutput: "",
		},
		{
			name: "Single IAC row",
			iacRows: []formats.SourceCodeRow{
				{
					SeverityDetails: formats.SeverityDetails{Severity: "High", SeverityNumValue: 3},
					Location: formats.Location{
						File:        "applicable/req_sw_terraform_azure_redis_auth.tf",
						StartLine:   11,
						StartColumn: 1,
						Snippet:     "Missing Periodic patching was detected",
					},
				},
			},
			expectedOutput: "\n## 🛠️ Infrastructure as Code\n\n\n| SEVERITY                | FILE                  | LINE:COLUMN                   | FINDING                       |\n| :---------------------: | :----------------------------------: | :-----------------------------------: | :---------------------------------: | \n| High | applicable/req_sw_terraform_azure_redis_auth.tf | 11:1 | Missing Periodic patching was detected |\n\n",
		},
		{
			name: "Multiple IAC rows",
			iacRows: []formats.SourceCodeRow{
				{
					SeverityDetails: formats.SeverityDetails{Severity: "High", SeverityNumValue: 3},
					Location: formats.Location{
						File:        "applicable/req_sw_terraform_azure_redis_patch.tf",
						StartLine:   11,
						StartColumn: 1,
						Snippet:     "Missing redis firewall definition or start_ip=0.0.0.0 was detected, Missing redis firewall definition or start_ip=0.0.0.0 was detected",
					},
				},
				{
					SeverityDetails: formats.SeverityDetails{Severity: "High", SeverityNumValue: 3},
					Location: formats.Location{
						File:        "applicable/req_sw_terraform_azure_redis_auth.tf",
						StartLine:   11,
						StartColumn: 1,
						Snippet:     "Missing Periodic patching was detected",
					},
				},
			},
			expectedOutput: "\n## 🛠️ Infrastructure as Code\n\n\n| SEVERITY                | FILE                  | LINE:COLUMN                   | FINDING                       |\n| :---------------------: | :----------------------------------: | :-----------------------------------: | :---------------------------------: | \n| High | applicable/req_sw_terraform_azure_redis_patch.tf | 11:1 | Missing redis firewall definition or start_ip=0.0.0.0 was detected, Missing redis firewall definition or start_ip=0.0.0.0 was detected |\n| High | applicable/req_sw_terraform_azure_redis_auth.tf | 11:1 | Missing Periodic patching was detected |\n\n",
		},
	}

	writer := &SimplifiedOutput{}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			output := writer.IacTableContent(tc.iacRows)
			assert.Equal(t, tc.expectedOutput, output)
		})
	}
}

func TestSimplifiedOutput_GetIacTableContent(t *testing.T) {
	testCases := []struct {
		name           string
		iacRows        []formats.SourceCodeRow
		expectedOutput string
	}{
		{
			name:           "Empty IAC rows",
			iacRows:        []formats.SourceCodeRow{},
			expectedOutput: "",
		},
		{
			name: "Single IAC row",
			iacRows: []formats.SourceCodeRow{
				{
					SeverityDetails: formats.SeverityDetails{Severity: "Medium", SeverityNumValue: 2},
					Location: formats.Location{
						File:        "file1",
						StartLine:   1,
						StartColumn: 10,
						Snippet:     "Public access to MySQL was detected",
					},
				},
			},
			expectedOutput: "\n| Medium | file1 | 1:10 | Public access to MySQL was detected |",
		},
		{
			name: "Multiple IAC rows",
			iacRows: []formats.SourceCodeRow{
				{
					SeverityDetails: formats.SeverityDetails{Severity: "High", SeverityNumValue: 3},
					Location: formats.Location{
						File:        "file1",
						StartLine:   1,
						StartColumn: 10,
						Snippet:     "Public access to MySQL was detected",
					},
				},
				{
					SeverityDetails: formats.SeverityDetails{Severity: "Medium", SeverityNumValue: 2},
					Location: formats.Location{
						File:        "file2",
						StartLine:   2,
						StartColumn: 5,
						Snippet:     "Public access to MySQL was detected",
					},
				},
			},
			expectedOutput: "\n| High | file1 | 1:10 | Public access to MySQL was detected |\n| Medium | file2 | 2:5 | Public access to MySQL was detected |",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			output := getIacTableContent(tc.iacRows, &SimplifiedOutput{})
			assert.Equal(t, tc.expectedOutput, output)
		})
	}
}

func TestSimplifiedOutput_GetLicensesTableContent(t *testing.T) {
	writer := &SimplifiedOutput{}
	testGetLicensesTableContent(t, writer)
}
