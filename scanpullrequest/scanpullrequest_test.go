package scanpullrequest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/jfrog/frogbot/utils"
	"github.com/jfrog/frogbot/utils/outputwriter"
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/froggit-go/vcsutils"
	coreconfig "github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	audit "github.com/jfrog/jfrog-cli-core/v2/xray/commands/audit/generic"
	"github.com/jfrog/jfrog-cli-core/v2/xray/formats"
	xrayutils "github.com/jfrog/jfrog-cli-core/v2/xray/utils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray/scan"
	"github.com/stretchr/testify/assert"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	testMultiDirProjConfigPath       = "testdata/config/frogbot-config-multi-dir-test-proj.yml"
	testMultiDirProjConfigPathNoFail = "testdata/config/frogbot-config-multi-dir-test-proj-no-fail.yml"
	testProjSubdirConfigPath         = "testdata/config/frogbot-config-test-proj-subdir.yml"
	testCleanProjConfigPath          = "testdata/config/frogbot-config-clean-test-proj.yml"
	testProjConfigPath               = "testdata/config/frogbot-config-test-proj.yml"
	testProjConfigPathNoFail         = "testdata/config/frogbot-config-test-proj-no-fail.yml"
	testSourceBranchName             = "pr"
	testTargetBranchName             = "master"
)

func TestCreateVulnerabilitiesRows(t *testing.T) {
	// Previous scan with only one violation - XRAY-1
	previousScan := scan.ScanResponse{
		Violations: []scan.Violation{{
			IssueId:       "XRAY-1",
			Summary:       "summary-1",
			Severity:      "high",
			Cves:          []scan.Cve{},
			ViolationType: "security",
			Components:    map[string]scan.Component{"component-A": {}, "component-B": {}},
		}},
	}

	// Current scan with 2 violations - XRAY-1 and XRAY-2
	currentScan := scan.ScanResponse{
		Violations: []scan.Violation{
			{
				IssueId:       "XRAY-1",
				Summary:       "summary-1",
				Severity:      "high",
				ViolationType: "security",
				Components:    map[string]scan.Component{"component-A": {}, "component-B": {}},
			},
			{
				IssueId:       "XRAY-2",
				Summary:       "summary-2",
				ViolationType: "security",
				Severity:      "low",
				Components:    map[string]scan.Component{"component-C": {}, "component-D": {}},
			},
		},
	}

	// Run createNewIssuesRows and make sure that only the XRAY-2 violation exists in the results
	rows, err := createNewVulnerabilitiesRows(
		&audit.Results{ExtendedScanResults: &xrayutils.ExtendedScanResults{XrayResults: []services.ScanResponse{previousScan}}},
		&audit.Results{ExtendedScanResults: &xrayutils.ExtendedScanResults{XrayResults: []services.ScanResponse{currentScan}}},
	)
	assert.NoError(t, err)
	assert.Len(t, rows, 2)
	assert.Equal(t, "XRAY-2", rows[0].IssueId)
	assert.Equal(t, "low", rows[0].Severity)
	assert.Equal(t, "XRAY-2", rows[1].IssueId)
	assert.Equal(t, "low", rows[1].Severity)

	impactedPackageOne := rows[0].ImpactedDependencyName
	impactedPackageTwo := rows[1].ImpactedDependencyName
	assert.ElementsMatch(t, []string{"component-C", "component-D"}, []string{impactedPackageOne, impactedPackageTwo})
}

func TestCreateVulnerabilitiesRowsCaseNoPrevViolations(t *testing.T) {
	// Previous scan with no violation
	previousScan := scan.ScanResponse{
		Violations: []scan.Violation{},
	}

	// Current scan with 2 violations - XRAY-1 and XRAY-2
	currentScan := scan.ScanResponse{
		Violations: []scan.Violation{
			{
				IssueId:       "XRAY-1",
				Summary:       "summary-1",
				Severity:      "high",
				ViolationType: "security",
				Components:    map[string]scan.Component{"component-A": {}},
			},
			{
				IssueId:       "XRAY-2",
				Summary:       "summary-2",
				ViolationType: "security",
				Severity:      "low",
				Components:    map[string]scan.Component{"component-C": {}},
			},
		},
	}

	expected := []formats.VulnerabilityOrViolationRow{
		{
			IssueId:                "XRAY-1",
			Severity:               "high",
			ImpactedDependencyName: "component-A",
		},
		{
			IssueId:                "XRAY-2",
			Severity:               "low",
			ImpactedDependencyName: "component-C",
		},
	}

	// Run createNewIssuesRows and expect both XRAY-1 and XRAY-2 violation in the results
	rows, err := createNewVulnerabilitiesRows(
		&audit.Results{ExtendedScanResults: &xrayutils.ExtendedScanResults{XrayResults: []services.ScanResponse{previousScan}}},
		&audit.Results{ExtendedScanResults: &xrayutils.ExtendedScanResults{XrayResults: []services.ScanResponse{currentScan}}},
	)
	assert.NoError(t, err)
	assert.Len(t, rows, 2)
	assert.ElementsMatch(t, expected, rows)
}

func TestGetNewViolationsCaseNoNewViolations(t *testing.T) {
	// Previous scan with 2 violations - XRAY-1 and XRAY-2
	previousScan := scan.ScanResponse{
		Violations: []scan.Violation{
			{
				IssueId:       "XRAY-1",
				Severity:      "high",
				ViolationType: "security",
				Components:    map[string]scan.Component{"component-A": {}},
			},
			{
				IssueId:       "XRAY-2",
				Summary:       "summary-2",
				ViolationType: "security",
				Severity:      "low",
				Components:    map[string]scan.Component{"component-C": {}},
			},
		},
	}

	// Current scan with no violation
	currentScan := scan.ScanResponse{
		Violations: []scan.Violation{},
	}

	// Run createNewIssuesRows and expect no violations in the results
	rows, err := createNewVulnerabilitiesRows(
		&audit.Results{ExtendedScanResults: &xrayutils.ExtendedScanResults{XrayResults: []services.ScanResponse{previousScan}}},
		&audit.Results{ExtendedScanResults: &xrayutils.ExtendedScanResults{XrayResults: []services.ScanResponse{currentScan}}},
	)
	assert.NoError(t, err)
	assert.Len(t, rows, 0)
}

func TestGetAllVulnerabilities(t *testing.T) {
	// Current scan with 2 vulnerabilities - XRAY-1 and XRAY-2
	currentScan := scan.ScanResponse{
		Vulnerabilities: []scan.Vulnerability{
			{
				IssueId:    "XRAY-1",
				Summary:    "summary-1",
				Severity:   "high",
				Components: map[string]scan.Component{"component-A": {}, "component-B": {}},
			},
			{
				IssueId:    "XRAY-2",
				Summary:    "summary-2",
				Severity:   "low",
				Components: map[string]scan.Component{"component-C": {}, "component-D": {}},
			},
		},
	}

	expected := []formats.VulnerabilityOrViolationRow{
		{
			Summary:                "summary-1",
			IssueId:                "XRAY-1",
			Severity:               "high",
			ImpactedDependencyName: "component-A",
		},
		{
			Summary:                "summary-1",
			IssueId:                "XRAY-1",
			Severity:               "high",
			ImpactedDependencyName: "component-B",
		},
		{
			Summary:                "summary-2",
			IssueId:                "XRAY-2",
			Severity:               "low",
			ImpactedDependencyName: "component-C",
		},
		{
			Summary:                "summary-2",
			IssueId:                "XRAY-2",
			Severity:               "low",
			ImpactedDependencyName: "component-D",
		},
	}

	// Run createAllIssuesRows and make sure that XRAY-1 and XRAY-2 vulnerabilities exists in the results
	rows, err := getScanVulnerabilitiesRows(&audit.Results{ExtendedScanResults: &xrayutils.ExtendedScanResults{XrayResults: []services.ScanResponse{currentScan}}})
	assert.NoError(t, err)
	assert.Len(t, rows, 4)
	assert.ElementsMatch(t, expected, rows)
}

func TestGetNewVulnerabilities(t *testing.T) {
	// Previous scan with only one vulnerability - XRAY-1
	previousScan := scan.ScanResponse{
		Vulnerabilities: []scan.Vulnerability{{
			IssueId:    "XRAY-1",
			Summary:    "summary-1",
			Severity:   "high",
			Cves:       []scan.Cve{{Id: "CVE-2023-1234"}},
			Components: map[string]scan.Component{"component-A": {}, "component-B": {}},
			Technology: coreutils.Maven.ToString(),
		}},
	}

	// Current scan with 2 vulnerabilities - XRAY-1 and XRAY-2
	currentScan := scan.ScanResponse{
		Vulnerabilities: []scan.Vulnerability{
			{
				IssueId:    "XRAY-1",
				Summary:    "summary-1",
				Severity:   "high",
				Cves:       []scan.Cve{{Id: "CVE-2023-1234"}},
				Components: map[string]scan.Component{"component-A": {}, "component-B": {}},
				Technology: coreutils.Maven.ToString(),
			},
			{
				IssueId:    "XRAY-2",
				Summary:    "summary-2",
				Severity:   "low",
				Cves:       []scan.Cve{{Id: "CVE-2023-4321"}},
				Components: map[string]scan.Component{"component-C": {}, "component-D": {}},
				Technology: coreutils.Yarn.ToString(),
			},
		},
	}

	expected := []formats.VulnerabilityOrViolationRow{
		{
			Summary:                "summary-2",
			Applicable:             "Applicable",
			IssueId:                "XRAY-2",
			Severity:               "low",
			ImpactedDependencyName: "component-C",
			Cves:                   []formats.CveRow{{Id: "CVE-2023-4321"}},
			Technology:             coreutils.Yarn,
		},
		{
			Summary:                "summary-2",
			Applicable:             "Applicable",
			IssueId:                "XRAY-2",
			Severity:               "low",
			Cves:                   []formats.CveRow{{Id: "CVE-2023-4321"}},
			ImpactedDependencyName: "component-D",
			Technology:             coreutils.Yarn,
		},
	}

	// Run createNewIssuesRows and make sure that only the XRAY-2 vulnerability exists in the results
	rows, err := createNewVulnerabilitiesRows(
		&audit.Results{ExtendedScanResults: &xrayutils.ExtendedScanResults{XrayResults: []services.ScanResponse{previousScan}, EntitledForJas: true, ApplicabilityScanResults: map[string]string{"CVE-2023-4321": "Applicable"}}},
		&audit.Results{ExtendedScanResults: &xrayutils.ExtendedScanResults{XrayResults: []services.ScanResponse{currentScan}, EntitledForJas: true, ApplicabilityScanResults: map[string]string{"CVE-2023-4321": "Applicable"}}},
	)
	assert.NoError(t, err)
	assert.Len(t, rows, 2)
	assert.ElementsMatch(t, expected, rows)
}

func TestGetNewVulnerabilitiesCaseNoPrevVulnerabilities(t *testing.T) {
	// Previous scan with no vulnerabilities
	previousScan := scan.ScanResponse{
		Vulnerabilities: []scan.Vulnerability{},
	}

	// Current scan with 2 vulnerabilities - XRAY-1 and XRAY-2
	currentScan := scan.ScanResponse{
		Vulnerabilities: []scan.Vulnerability{
			{
				IssueId:             "XRAY-1",
				Summary:             "summary-1",
				Severity:            "high",
				ExtendedInformation: &scan.ExtendedInformation{FullDescription: "description-1"},
				Components:          map[string]scan.Component{"component-A": {}},
			},
			{
				IssueId:             "XRAY-2",
				Summary:             "summary-2",
				Severity:            "low",
				ExtendedInformation: &scan.ExtendedInformation{FullDescription: "description-2"},
				Components:          map[string]scan.Component{"component-B": {}},
			},
		},
	}

	expected := []formats.VulnerabilityOrViolationRow{
		{
			Summary:                  "summary-2",
			IssueId:                  "XRAY-2",
			Severity:                 "low",
			ImpactedDependencyName:   "component-B",
			JfrogResearchInformation: &formats.JfrogResearchInformation{Details: "description-2"},
		},
		{
			Summary:                  "summary-1",
			IssueId:                  "XRAY-1",
			Severity:                 "high",
			ImpactedDependencyName:   "component-A",
			JfrogResearchInformation: &formats.JfrogResearchInformation{Details: "description-1"},
		},
	}

	// Run createNewIssuesRows and expect both XRAY-1 and XRAY-2 vulnerability in the results
	rows, err := createNewVulnerabilitiesRows(
		&audit.Results{ExtendedScanResults: &xrayutils.ExtendedScanResults{XrayResults: []services.ScanResponse{previousScan}}},
		&audit.Results{ExtendedScanResults: &xrayutils.ExtendedScanResults{XrayResults: []services.ScanResponse{currentScan}}},
	)
	assert.NoError(t, err)
	assert.Len(t, rows, 2)
	assert.ElementsMatch(t, expected, rows)
}

func TestGetNewVulnerabilitiesCaseNoNewVulnerabilities(t *testing.T) {
	// Previous scan with 2 vulnerabilities - XRAY-1 and XRAY-2
	previousScan := scan.ScanResponse{
		Vulnerabilities: []scan.Vulnerability{
			{
				IssueId:    "XRAY-1",
				Summary:    "summary-1",
				Severity:   "high",
				Components: map[string]scan.Component{"component-A": {}},
			},
			{
				IssueId:    "XRAY-2",
				Summary:    "summary-2",
				Severity:   "low",
				Components: map[string]scan.Component{"component-B": {}},
			},
		},
	}

	// Current scan with no vulnerabilities
	currentScan := scan.ScanResponse{
		Vulnerabilities: []scan.Vulnerability{},
	}

	// Run createNewIssuesRows and expect no vulnerability in the results
	rows, err := createNewVulnerabilitiesRows(
		&audit.Results{ExtendedScanResults: &xrayutils.ExtendedScanResults{XrayResults: []services.ScanResponse{previousScan}}},
		&audit.Results{ExtendedScanResults: &xrayutils.ExtendedScanResults{XrayResults: []services.ScanResponse{currentScan}}},
	)
	assert.NoError(t, err)
	assert.Len(t, rows, 0)
}

func TestCreatePullRequestMessageNoVulnerabilities(t *testing.T) {
	vulnerabilities := []formats.VulnerabilityOrViolationRow{}
	message := createPullRequestMessage(vulnerabilities, nil, &outputwriter.StandardOutput{})

	expectedMessageByte, err := os.ReadFile(filepath.Join("..", "testdata", "messages", "novulnerabilities.md"))
	assert.NoError(t, err)
	expectedMessage := strings.ReplaceAll(string(expectedMessageByte), "\r\n", "\n")
	assert.Equal(t, expectedMessage, message)

	outputWriter := &outputwriter.StandardOutput{}
	outputWriter.SetVcsProvider(vcsutils.GitLab)
	message = createPullRequestMessage(vulnerabilities, nil, outputWriter)

	expectedMessageByte, err = os.ReadFile(filepath.Join("..", "testdata", "messages", "novulnerabilitiesMR.md"))
	assert.NoError(t, err)
	expectedMessage = strings.ReplaceAll(string(expectedMessageByte), "\r\n", "\n")
	assert.Equal(t, expectedMessage, message)
}

func TestCreatePullRequestMessage(t *testing.T) {
	vulnerabilities := []formats.VulnerabilityOrViolationRow{
		{
			Severity:                  "High",
			Applicable:                "Undetermined",
			ImpactedDependencyName:    "github.com/nats-io/nats-streaming-server",
			ImpactedDependencyVersion: "v0.21.0",
			FixedVersions:             []string{"[0.24.1]"},
			Components: []formats.ComponentRow{
				{
					Name:    "github.com/nats-io/nats-streaming-server",
					Version: "v0.21.0",
				},
			},
			Cves: []formats.CveRow{{Id: "CVE-2022-24450"}},
		},
		{
			Severity:                  "High",
			Applicable:                "Undetermined",
			ImpactedDependencyName:    "github.com/mholt/archiver/v3",
			ImpactedDependencyVersion: "v3.5.1",
			Components: []formats.ComponentRow{
				{
					Name:    "github.com/mholt/archiver/v3",
					Version: "v3.5.1",
				},
			},
			Cves: []formats.CveRow{},
		},
		{
			Severity:                  "Medium",
			Applicable:                "Undetermined",
			ImpactedDependencyName:    "github.com/nats-io/nats-streaming-server",
			ImpactedDependencyVersion: "v0.21.0",
			FixedVersions:             []string{"[0.24.3]"},
			Components: []formats.ComponentRow{
				{
					Name:    "github.com/nats-io/nats-streaming-server",
					Version: "v0.21.0",
				},
			},
			Cves: []formats.CveRow{{Id: "CVE-2022-26652"}},
		},
	}
	iac := []formats.IacSecretsRow{
		{
			Severity:   "Low",
			File:       "test.js",
			LineColumn: "1:20",
			Text:       "kms_key_id='' was detected",
			Type:       "aws_cloudtrail_encrypt",
		},
		{
			Severity:   "High",
			File:       "test2.js",
			LineColumn: "4:30",
			Text:       "Deprecated TLS version was detected",
			Type:       "aws_cloudfront_tls_version",
		},
	}
	writerOutput := &outputwriter.StandardOutput{}
	writerOutput.SetJasOutputFlags(true, true)
	message := createPullRequestMessage(vulnerabilities, iac, writerOutput)

	expectedMessage := "<div align='center'>\n\n[![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/vulnerabilitiesBannerPR.png)](https://github.com/jfrog/frogbot#readme)\n\n</div>\n\n\n## 📦 Vulnerable Dependencies \n\n### ✍️ Summary\n\n<div align=\"center\">\n\n| SEVERITY                | CONTEXTUAL ANALYSIS                  | DIRECT DEPENDENCIES                  | IMPACTED DEPENDENCY                   | FIXED VERSIONS                       |\n| :---------------------: | :----------------------------------: | :----------------------------------: | :-----------------------------------: | :---------------------------------: | \n| ![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/applicableHighSeverity.png)<br>    High | Undetermined | github.com/nats-io/nats-streaming-server:v0.21.0 | github.com/nats-io/nats-streaming-server:v0.21.0 | [0.24.1] |\n| ![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/applicableHighSeverity.png)<br>    High | Undetermined | github.com/mholt/archiver/v3:v3.5.1 | github.com/mholt/archiver/v3:v3.5.1 |  |\n| ![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/applicableMediumSeverity.png)<br>  Medium | Undetermined | github.com/nats-io/nats-streaming-server:v0.21.0 | github.com/nats-io/nats-streaming-server:v0.21.0 | [0.24.3] |\n\n</div>\n\n## 👇 Details\n\n\n<details>\n<summary> <b>github.com/nats-io/nats-streaming-server v0.21.0</b> </summary>\n<br>\n\n- **Severity** 🔥 High\n- **Contextual Analysis:** Undetermined\n- **Package Name:** github.com/nats-io/nats-streaming-server\n- **Current Version:** v0.21.0\n- **Fixed Version:** [0.24.1]\n- **CVE:** CVE-2022-24450\n\n\n</details>\n\n\n<details>\n<summary> <b>github.com/mholt/archiver/v3 v3.5.1</b> </summary>\n<br>\n\n- **Severity** 🔥 High\n- **Contextual Analysis:** Undetermined\n- **Package Name:** github.com/mholt/archiver/v3\n- **Current Version:** v3.5.1\n\n\n</details>\n\n\n<details>\n<summary> <b>github.com/nats-io/nats-streaming-server v0.21.0</b> </summary>\n<br>\n\n- **Severity** 🎃 Medium\n- **Contextual Analysis:** Undetermined\n- **Package Name:** github.com/nats-io/nats-streaming-server\n- **Current Version:** v0.21.0\n- **Fixed Version:** [0.24.3]\n- **CVE:** CVE-2022-26652\n\n\n</details>\n\n\n## 🛠️ Infrastructure as Code \n\n<div align=\"center\">\n\n\n| SEVERITY                | FILE                  | LINE:COLUMN                   | FINDING                       |\n| :---------------------: | :----------------------------------: | :-----------------------------------: | :---------------------------------: | \n| ![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/applicableLowSeverity.png)<br>     Low | test.js | 1:20 | kms_key_id='' was detected |\n| ![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/applicableHighSeverity.png)<br>    High | test2.js | 4:30 | Deprecated TLS version was detected |\n\n</div>\n\n\n<div align=\"center\">\n\n[JFrog Frogbot](https://github.com/jfrog/frogbot#readme)\n\n</div>\n"
	assert.Equal(t, expectedMessage, message)

	writerOutput.SetVcsProvider(vcsutils.GitLab)
	message = createPullRequestMessage(vulnerabilities, iac, writerOutput)
	expectedMessage = "<div align='center'>\n\n[![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/vulnerabilitiesBannerMR.png)](https://github.com/jfrog/frogbot#readme)\n\n</div>\n\n\n## 📦 Vulnerable Dependencies \n\n### ✍️ Summary\n\n<div align=\"center\">\n\n| SEVERITY                | CONTEXTUAL ANALYSIS                  | DIRECT DEPENDENCIES                  | IMPACTED DEPENDENCY                   | FIXED VERSIONS                       |\n| :---------------------: | :----------------------------------: | :----------------------------------: | :-----------------------------------: | :---------------------------------: | \n| ![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/applicableHighSeverity.png)<br>    High | Undetermined | github.com/nats-io/nats-streaming-server:v0.21.0 | github.com/nats-io/nats-streaming-server:v0.21.0 | [0.24.1] |\n| ![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/applicableHighSeverity.png)<br>    High | Undetermined | github.com/mholt/archiver/v3:v3.5.1 | github.com/mholt/archiver/v3:v3.5.1 |  |\n| ![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/applicableMediumSeverity.png)<br>  Medium | Undetermined | github.com/nats-io/nats-streaming-server:v0.21.0 | github.com/nats-io/nats-streaming-server:v0.21.0 | [0.24.3] |\n\n</div>\n\n## 👇 Details\n\n\n<details>\n<summary> <b>github.com/nats-io/nats-streaming-server v0.21.0</b> </summary>\n<br>\n\n- **Severity** 🔥 High\n- **Contextual Analysis:** Undetermined\n- **Package Name:** github.com/nats-io/nats-streaming-server\n- **Current Version:** v0.21.0\n- **Fixed Version:** [0.24.1]\n- **CVE:** CVE-2022-24450\n\n\n</details>\n\n\n<details>\n<summary> <b>github.com/mholt/archiver/v3 v3.5.1</b> </summary>\n<br>\n\n- **Severity** 🔥 High\n- **Contextual Analysis:** Undetermined\n- **Package Name:** github.com/mholt/archiver/v3\n- **Current Version:** v3.5.1\n\n\n</details>\n\n\n<details>\n<summary> <b>github.com/nats-io/nats-streaming-server v0.21.0</b> </summary>\n<br>\n\n- **Severity** 🎃 Medium\n- **Contextual Analysis:** Undetermined\n- **Package Name:** github.com/nats-io/nats-streaming-server\n- **Current Version:** v0.21.0\n- **Fixed Version:** [0.24.3]\n- **CVE:** CVE-2022-26652\n\n\n</details>\n\n\n## 🛠️ Infrastructure as Code \n\n<div align=\"center\">\n\n\n| SEVERITY                | FILE                  | LINE:COLUMN                   | FINDING                       |\n| :---------------------: | :----------------------------------: | :-----------------------------------: | :---------------------------------: | \n| ![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/applicableLowSeverity.png)<br>     Low | test.js | 1:20 | kms_key_id='' was detected |\n| ![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/applicableHighSeverity.png)<br>    High | test2.js | 4:30 | Deprecated TLS version was detected |\n\n</div>\n\n\n<div align=\"center\">\n\n[JFrog Frogbot](https://github.com/jfrog/frogbot#readme)\n\n</div>\n"
	assert.Equal(t, expectedMessage, message)
}

func TestScanPullRequest(t *testing.T) {
	tests := []struct {
		testName             string
		configPath           string
		projectName          string
		failOnSecurityIssues bool
	}{
		{
			testName:             "ScanPullRequest",
			configPath:           testProjConfigPath,
			projectName:          "test-proj",
			failOnSecurityIssues: true,
		},
		{
			testName:             "ScanPullRequestNoFail",
			configPath:           testProjConfigPathNoFail,
			projectName:          "test-proj",
			failOnSecurityIssues: false,
		},
		{
			testName:             "ScanPullRequestSubdir",
			configPath:           testProjSubdirConfigPath,
			projectName:          "test-proj-subdir",
			failOnSecurityIssues: true,
		},
		{
			testName:             "ScanPullRequestNoIssues",
			configPath:           testCleanProjConfigPath,
			projectName:          "clean-test-proj",
			failOnSecurityIssues: false,
		},
		{
			testName:             "ScanPullRequestMultiWorkDir",
			configPath:           testMultiDirProjConfigPathNoFail,
			projectName:          "multi-dir-test-proj",
			failOnSecurityIssues: false,
		},
		{
			testName:             "ScanPullRequestMultiWorkDirNoFail",
			configPath:           testMultiDirProjConfigPath,
			projectName:          "multi-dir-test-proj",
			failOnSecurityIssues: true,
		},
	}
	for _, test := range tests {
		t.Run(test.testName, func(t *testing.T) {
			testScanPullRequest(t, test.configPath, test.projectName, test.failOnSecurityIssues)
		})
	}
}

func testScanPullRequest(t *testing.T, configPath, projectName string, failOnSecurityIssues bool) {
	params, restoreEnv := utils.VerifyEnv(t)
	defer restoreEnv()

	// Create mock GitLab server
	server := httptest.NewServer(createGitLabHandler(t, projectName))
	defer server.Close()

	configAggregator, client := prepareConfigAndClient(t, configPath, server, params)
	_, cleanUp := utils.PrepareTestEnvironment(t, projectName, "scanpullrequest")
	defer cleanUp()

	// Run "frogbot scan pull request"
	var scanPullRequest ScanPullRequestCmd
	err := scanPullRequest.Run(configAggregator, client)
	if failOnSecurityIssues {
		assert.EqualErrorf(t, err, securityIssueFoundErr, "Error should be: %v, got: %v", securityIssueFoundErr, err)
	} else {
		assert.NoError(t, err)
	}

	// Check env sanitize
	err = utils.SanitizeEnv()
	assert.NoError(t, err)
	utils.AssertSanitizedEnv(t)
}

func TestVerifyGitHubFrogbotEnvironment(t *testing.T) {
	// Init mock
	client := CreateMockVcsClient(t)
	environment := "frogbot"
	client.EXPECT().GetRepositoryInfo(context.Background(), gitParams.RepoOwner, gitParams.RepoName).Return(vcsclient.RepositoryInfo{}, nil)
	client.EXPECT().GetRepositoryEnvironmentInfo(context.Background(), gitParams.RepoOwner, gitParams.RepoName, environment).Return(vcsclient.RepositoryEnvironmentInfo{Reviewers: []string{"froggy"}}, nil)
	assert.NoError(t, os.Setenv(utils.GitHubActionsEnv, "true"))

	// Run verifyGitHubFrogbotEnvironment
	err := verifyGitHubFrogbotEnvironment(client, gitParams)
	assert.NoError(t, err)
}

func TestVerifyGitHubFrogbotEnvironmentNoEnv(t *testing.T) {
	// Redirect log to avoid negative output
	previousLogger := redirectLogOutputToNil()
	defer log.SetLogger(previousLogger)

	// Init mock
	client := CreateMockVcsClient(t)
	environment := "frogbot"
	client.EXPECT().GetRepositoryInfo(context.Background(), gitParams.RepoOwner, gitParams.RepoName).Return(vcsclient.RepositoryInfo{}, nil)
	client.EXPECT().GetRepositoryEnvironmentInfo(context.Background(), gitParams.RepoOwner, gitParams.RepoName, environment).Return(vcsclient.RepositoryEnvironmentInfo{}, errors.New("404"))
	assert.NoError(t, os.Setenv(utils.GitHubActionsEnv, "true"))

	// Run verifyGitHubFrogbotEnvironment
	err := verifyGitHubFrogbotEnvironment(client, gitParams)
	assert.ErrorContains(t, err, noGitHubEnvErr)
}

func TestVerifyGitHubFrogbotEnvironmentNoReviewers(t *testing.T) {
	// Init mock
	client := CreateMockVcsClient(t)
	environment := "frogbot"
	client.EXPECT().GetRepositoryInfo(context.Background(), gitParams.RepoOwner, gitParams.RepoName).Return(vcsclient.RepositoryInfo{}, nil)
	client.EXPECT().GetRepositoryEnvironmentInfo(context.Background(), gitParams.RepoOwner, gitParams.RepoName, environment).Return(vcsclient.RepositoryEnvironmentInfo{}, nil)
	assert.NoError(t, os.Setenv(utils.GitHubActionsEnv, "true"))

	// Run verifyGitHubFrogbotEnvironment
	err := verifyGitHubFrogbotEnvironment(client, gitParams)
	assert.ErrorContains(t, err, noGitHubEnvReviewersErr)
}

func TestVerifyGitHubFrogbotEnvironmentOnPrem(t *testing.T) {
	repoConfig := &utils.Repository{
		Params: utils.Params{Git: utils.Git{
			VcsInfo: vcsclient.VcsInfo{APIEndpoint: "https://acme.vcs.io"}},
		},
	}

	// Run verifyGitHubFrogbotEnvironment
	err := verifyGitHubFrogbotEnvironment(&vcsclient.GitHubClient{}, repoConfig)
	assert.NoError(t, err)
}

func prepareConfigAndClient(t *testing.T, configPath string, server *httptest.Server, serverParams coreconfig.ServerDetails) (utils.RepoAggregator, vcsclient.VcsClient) {
	gitTestParams := &utils.Git{
		GitProvider: vcsutils.GitHub,
		RepoOwner:   "jfrog",
		VcsInfo: vcsclient.VcsInfo{
			Token:       "123456",
			APIEndpoint: server.URL,
		},
		PullRequestDetails: vcsclient.PullRequestInfo{ID: int64(1)},
	}
	utils.SetEnvAndAssert(t, map[string]string{utils.GitPullRequestIDEnv: "1"})

	configData, err := utils.ReadConfigFromFileSystem(configPath)
	assert.NoError(t, err)
	configAggregator, err := utils.BuildRepoAggregator(configData, gitTestParams, &serverParams)
	assert.NoError(t, err)

	client, err := vcsclient.NewClientBuilder(vcsutils.GitLab).ApiEndpoint(server.URL).Token("123456").Build()
	assert.NoError(t, err)
	return configAggregator, client
}

// Create HTTP handler to mock GitLab server
func createGitLabHandler(t *testing.T, projectName string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch {
		// Return 200 on ping
		case r.RequestURI == "/api/v4/":
			w.WriteHeader(http.StatusOK)
		// Mimic get pull request by ID
		case r.RequestURI == fmt.Sprintf("/api/v4/projects/jfrog%s/merge_requests/1", "%2F"+projectName):
			w.WriteHeader(http.StatusOK)
			expectedResponse, err := os.ReadFile(filepath.Join("..", "expectedPullRequestDetailsResponse.json"))
			assert.NoError(t, err)
			_, err = w.Write(expectedResponse)
			assert.NoError(t, err)
		// Mimic download specific branch to scan
		case r.RequestURI == fmt.Sprintf("/api/v4/projects/jfrog%s/repository/archive.tar.gz?sha=%s", "%2F"+projectName, testSourceBranchName):
			w.WriteHeader(http.StatusOK)
			repoFile, err := os.ReadFile(filepath.Join("..", projectName, "sourceBranch.gz"))
			assert.NoError(t, err)
			_, err = w.Write(repoFile)
			assert.NoError(t, err)
		// Download repository mock
		case r.RequestURI == fmt.Sprintf("/api/v4/projects/jfrog%s/repository/archive.tar.gz?sha=%s", "%2F"+projectName, testTargetBranchName):
			w.WriteHeader(http.StatusOK)
			repoFile, err := os.ReadFile(filepath.Join("..", projectName, "targetBranch.gz"))
			assert.NoError(t, err)
			_, err = w.Write(repoFile)
			assert.NoError(t, err)
			return
		// clean-test-proj should not include any vulnerabilities so assertion is not needed.
		case r.RequestURI == fmt.Sprintf("/api/v4/projects/jfrog%s/merge_requests/133/notes", "%2Fclean-test-proj") && r.Method == http.MethodPost:
			w.WriteHeader(http.StatusOK)
			_, err := w.Write([]byte("{}"))
			assert.NoError(t, err)
			return
		case r.RequestURI == fmt.Sprintf("/api/v4/projects/jfrog%s/merge_requests/133/notes", "%2Fclean-test-proj") && r.Method == http.MethodGet:
			w.WriteHeader(http.StatusOK)
			comments, err := os.ReadFile(filepath.Join("..", "commits.json"))
			assert.NoError(t, err)
			_, err = w.Write(comments)
			assert.NoError(t, err)
		// Return 200 when using the REST that creates the comment
		case r.RequestURI == fmt.Sprintf("/api/v4/projects/jfrog%s/merge_requests/133/notes", "%2F"+projectName) && r.Method == http.MethodPost:
			buf := new(bytes.Buffer)
			_, err := buf.ReadFrom(r.Body)
			assert.NoError(t, err)
			assert.NotEmpty(t, buf.String())

			var expectedResponse []byte
			switch {
			case strings.Contains(projectName, "multi-dir"):
				expectedResponse, err = os.ReadFile(filepath.Join("..", "expectedResponseMultiDir.json"))
			case strings.Contains(projectName, "pip"):
				expectedResponse, err = os.ReadFile(filepath.Join("..", "expectedResponsePip.json"))
			default:
				expectedResponse, err = os.ReadFile(filepath.Join("..", "expectedResponse.json"))
			}
			assert.NoError(t, err)
			assert.JSONEq(t, string(expectedResponse), buf.String())

			w.WriteHeader(http.StatusOK)
			_, err = w.Write([]byte("{}"))
			assert.NoError(t, err)
		case r.RequestURI == fmt.Sprintf("/api/v4/projects/jfrog%s/merge_requests/133/notes", "%2F"+projectName) && r.Method == http.MethodGet:
			w.WriteHeader(http.StatusOK)
			comments, err := os.ReadFile(filepath.Join("..", "commits.json"))
			assert.NoError(t, err)
			_, err = w.Write(comments)
			assert.NoError(t, err)
		}
	}
}

func TestCreateNewIacRows(t *testing.T) {
	testCases := []struct {
		name                            string
		targetIacResults                []xrayutils.IacOrSecretResult
		sourceIacResults                []xrayutils.IacOrSecretResult
		expectedAddedIacVulnerabilities []formats.IacSecretsRow
	}{
		{
			name: "No vulnerabilities in source IaC results",
			targetIacResults: []xrayutils.IacOrSecretResult{
				{
					Severity:   "High",
					File:       "file1",
					LineColumn: "1:10",
					Text:       "aws violation",
				},
			},
			sourceIacResults:                []xrayutils.IacOrSecretResult{},
			expectedAddedIacVulnerabilities: []formats.IacSecretsRow{},
		},
		{
			name:             "No vulnerabilities in target IaC results",
			targetIacResults: []xrayutils.IacOrSecretResult{},
			sourceIacResults: []xrayutils.IacOrSecretResult{
				{
					Severity:   "High",
					File:       "file1",
					LineColumn: "1:10",
					Text:       "aws violation",
				},
			},
			expectedAddedIacVulnerabilities: []formats.IacSecretsRow{
				{
					Severity:         "High",
					File:             "file1",
					LineColumn:       "1:10",
					Text:             "aws violation",
					SeverityNumValue: 10,
				},
			},
		},
		{
			name: "Some new vulnerabilities in source IaC results",
			targetIacResults: []xrayutils.IacOrSecretResult{
				{
					Severity:   "High",
					File:       "file1",
					LineColumn: "1:10",
					Text:       "aws violation",
				},
			},
			sourceIacResults: []xrayutils.IacOrSecretResult{
				{
					Severity:   "Medium",
					File:       "file2",
					LineColumn: "2:5",
					Text:       "gcp violation",
				},
			},
			expectedAddedIacVulnerabilities: []formats.IacSecretsRow{
				{
					Severity:         "Medium",
					SeverityNumValue: 8,
					File:             "file2",
					LineColumn:       "2:5",
					Text:             "gcp violation",
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			targetIacRows := xrayutils.PrepareSecrets(tc.targetIacResults)
			sourceIacRows := xrayutils.PrepareSecrets(tc.sourceIacResults)
			addedIacVulnerabilities := createNewIacOrSecretsRows(targetIacRows, sourceIacRows)
			assert.ElementsMatch(t, tc.expectedAddedIacVulnerabilities, addedIacVulnerabilities)
		})
	}
}

func TestCreateNewSecretRows(t *testing.T) {
	testCases := []struct {
		name                                string
		targetSecretsResults                []xrayutils.IacOrSecretResult
		sourceSecretsResults                []xrayutils.IacOrSecretResult
		expectedAddedSecretsVulnerabilities []formats.IacSecretsRow
	}{
		{
			name: "No vulnerabilities in source secrets results",
			targetSecretsResults: []xrayutils.IacOrSecretResult{
				{
					Severity:   "High",
					File:       "file1",
					LineColumn: "1:10",
					Type:       "Secret",
					Text:       "Sensitive information",
				},
			},
			sourceSecretsResults:                []xrayutils.IacOrSecretResult{},
			expectedAddedSecretsVulnerabilities: []formats.IacSecretsRow{},
		},
		{
			name:                 "No vulnerabilities in target secrets results",
			targetSecretsResults: []xrayutils.IacOrSecretResult{},
			sourceSecretsResults: []xrayutils.IacOrSecretResult{
				{
					Severity:   "High",
					File:       "file1",
					LineColumn: "1:10",
					Type:       "Secret",
					Text:       "Sensitive information",
				},
			},
			expectedAddedSecretsVulnerabilities: []formats.IacSecretsRow{
				{
					Severity:         "High",
					File:             "file1",
					LineColumn:       "1:10",
					Type:             "Secret",
					Text:             "Sensitive information",
					SeverityNumValue: 10,
				},
			},
		},
		{
			name: "Some new vulnerabilities in source secrets results",
			targetSecretsResults: []xrayutils.IacOrSecretResult{
				{
					Severity:   "High",
					File:       "file1",
					LineColumn: "1:10",
					Type:       "Secret",
					Text:       "Sensitive information",
				},
			},
			sourceSecretsResults: []xrayutils.IacOrSecretResult{
				{
					Severity:   "Medium",
					File:       "file2",
					LineColumn: "2:5",
					Type:       "Secret",
					Text:       "Confidential data",
				},
			},
			expectedAddedSecretsVulnerabilities: []formats.IacSecretsRow{
				{
					Severity:         "Medium",
					SeverityNumValue: 8,
					File:             "file2",
					LineColumn:       "2:5",
					Text:             "Confidential data",
					Type:             "Secret",
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			targetSecretsRows := xrayutils.PrepareSecrets(tc.targetSecretsResults)
			sourceSecretsRows := xrayutils.PrepareSecrets(tc.sourceSecretsResults)
			addedSecretsVulnerabilities := createNewIacOrSecretsRows(targetSecretsRows, sourceSecretsRows)
			assert.ElementsMatch(t, tc.expectedAddedSecretsVulnerabilities, addedSecretsVulnerabilities)
		})
	}
}

func TestDeletePreviousPullRequestMessages(t *testing.T) {
	repository := &utils.Repository{
		Params: utils.Params{
			Git: utils.Git{
				PullRequestDetails: vcsclient.PullRequestInfo{Target: vcsclient.BranchInfo{
					Repository: "repo",
					Owner:      "owner",
				}, ID: 17},
			},
		},
		OutputWriter: &outputwriter.StandardOutput{},
	}
	client := CreateMockVcsClient(t)

	// Test with comment returned
	client.EXPECT().ListPullRequestComments(context.Background(), "owner", "repo", 17).Return([]vcsclient.CommentInfo{
		{ID: 20, Content: outputwriter.GetBanner(outputwriter.NoVulnerabilityPrBannerSource) + "text \n table\n text text text", Created: time.Unix(3, 0)},
	}, nil)
	client.EXPECT().DeletePullRequestComment(context.Background(), "owner", "repo", 17, 20).Return(nil).AnyTimes()
	err := deleteExistingPullRequestComment(repository, client)
	assert.NoError(t, err)

	// Test with no comment returned
	client.EXPECT().ListPullRequestComments(context.Background(), "owner", "repo", 17).Return([]vcsclient.CommentInfo{}, nil)
	err = deleteExistingPullRequestComment(repository, client)
	assert.NoError(t, err)

	// Test with error returned
	client.EXPECT().ListPullRequestComments(context.Background(), "owner", "repo", 17).Return(nil, errors.New("error"))
	err = deleteExistingPullRequestComment(repository, client)
	assert.Error(t, err)
}

// Set new logger with output redirection to a null logger. This is useful for negative tests.
// Caller is responsible to set the old log back.
func redirectLogOutputToNil() (previousLog log.Log) {
	previousLog = log.Logger
	newLog := log.NewLogger(log.ERROR, nil)
	newLog.SetOutputWriter(io.Discard)
	newLog.SetLogsWriter(io.Discard, 0)
	log.SetLogger(newLog)
	return previousLog
}
