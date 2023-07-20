package commands

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/jfrog/frogbot/commands/utils"
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/froggit-go/vcsutils"
	coreconfig "github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	audit "github.com/jfrog/jfrog-cli-core/v2/xray/commands/audit/generic"
	"github.com/jfrog/jfrog-cli-core/v2/xray/formats"
	utils2 "github.com/jfrog/jfrog-cli-core/v2/xray/utils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray/services"
	"github.com/stretchr/testify/assert"
	clitool "github.com/urfave/cli/v2"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	testMultiDirProjConfigPath       = "testdata/config/frogbot-config-multi-dir-test-proj.yml"
	testMultiDirProjConfigPathNoFail = "testdata/config/frogbot-config-multi-dir-test-proj-no-fail.yml"
	testProjSubdirConfigPath         = "testdata/config/frogbot-config-test-proj-subdir.yml"
	testCleanProjConfigPath          = "testdata/config/frogbot-config-clean-test-proj.yml"
	testProjConfigPath               = "testdata/config/frogbot-config-test-proj.yml"
	testProjConfigPathNoFail         = "testdata/config/frogbot-config-test-proj-no-fail.yml"
	testSameBranchProjConfigPath     = "testdata/config/frogbot-config-test-same-branch-fail.yml"
)

func TestCreateVulnerabilitiesRows(t *testing.T) {
	// Previous scan with only one violation - XRAY-1
	previousScan := services.ScanResponse{
		Violations: []services.Violation{{
			IssueId:       "XRAY-1",
			Summary:       "summary-1",
			Severity:      "high",
			Cves:          []services.Cve{},
			ViolationType: "security",
			Components:    map[string]services.Component{"component-A": {}, "component-B": {}},
		}},
	}

	// Current scan with 2 violations - XRAY-1 and XRAY-2
	currentScan := services.ScanResponse{
		Violations: []services.Violation{
			{
				IssueId:       "XRAY-1",
				Summary:       "summary-1",
				Severity:      "high",
				ViolationType: "security",
				Components:    map[string]services.Component{"component-A": {}, "component-B": {}},
			},
			{
				IssueId:       "XRAY-2",
				Summary:       "summary-2",
				ViolationType: "security",
				Severity:      "low",
				Components:    map[string]services.Component{"component-C": {}, "component-D": {}},
			},
		},
	}

	// Run createNewIssuesRows and make sure that only the XRAY-2 violation exists in the results
	rows, err := createNewIssuesRows(
		&audit.Results{ExtendedScanResults: &utils2.ExtendedScanResults{XrayResults: []services.ScanResponse{previousScan}}},
		&audit.Results{ExtendedScanResults: &utils2.ExtendedScanResults{XrayResults: []services.ScanResponse{currentScan}}},
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
	previousScan := services.ScanResponse{
		Violations: []services.Violation{},
	}

	// Current scan with 2 violations - XRAY-1 and XRAY-2
	currentScan := services.ScanResponse{
		Violations: []services.Violation{
			{
				IssueId:       "XRAY-1",
				Summary:       "summary-1",
				Severity:      "high",
				ViolationType: "security",
				Components:    map[string]services.Component{"component-A": {}},
			},
			{
				IssueId:       "XRAY-2",
				Summary:       "summary-2",
				ViolationType: "security",
				Severity:      "low",
				Components:    map[string]services.Component{"component-C": {}},
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
	rows, err := createNewIssuesRows(
		&audit.Results{ExtendedScanResults: &utils2.ExtendedScanResults{XrayResults: []services.ScanResponse{previousScan}}},
		&audit.Results{ExtendedScanResults: &utils2.ExtendedScanResults{XrayResults: []services.ScanResponse{currentScan}}},
	)
	assert.NoError(t, err)
	assert.Len(t, rows, 2)
	assert.ElementsMatch(t, expected, rows)
}

func TestGetNewViolationsCaseNoNewViolations(t *testing.T) {
	// Previous scan with 2 violations - XRAY-1 and XRAY-2
	previousScan := services.ScanResponse{
		Violations: []services.Violation{
			{
				IssueId:       "XRAY-1",
				Severity:      "high",
				ViolationType: "security",
				Components:    map[string]services.Component{"component-A": {}},
			},
			{
				IssueId:       "XRAY-2",
				Summary:       "summary-2",
				ViolationType: "security",
				Severity:      "low",
				Components:    map[string]services.Component{"component-C": {}},
			},
		},
	}

	// Current scan with no violation
	currentScan := services.ScanResponse{
		Violations: []services.Violation{},
	}

	// Run createNewIssuesRows and expect no violations in the results
	rows, err := createNewIssuesRows(
		&audit.Results{ExtendedScanResults: &utils2.ExtendedScanResults{XrayResults: []services.ScanResponse{previousScan}}},
		&audit.Results{ExtendedScanResults: &utils2.ExtendedScanResults{XrayResults: []services.ScanResponse{currentScan}}},
	)
	assert.NoError(t, err)
	assert.Len(t, rows, 0)
}

func TestGetAllVulnerabilities(t *testing.T) {
	// Current scan with 2 vulnerabilities - XRAY-1 and XRAY-2
	currentScan := services.ScanResponse{
		Vulnerabilities: []services.Vulnerability{
			{
				IssueId:    "XRAY-1",
				Summary:    "summary-1",
				Severity:   "high",
				Components: map[string]services.Component{"component-A": {}, "component-B": {}},
			},
			{
				IssueId:    "XRAY-2",
				Summary:    "summary-2",
				Severity:   "low",
				Components: map[string]services.Component{"component-C": {}, "component-D": {}},
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
	rows, err := getScanVulnerabilitiesRows(&audit.Results{ExtendedScanResults: &utils2.ExtendedScanResults{XrayResults: []services.ScanResponse{currentScan}}})
	assert.NoError(t, err)
	assert.Len(t, rows, 4)
	assert.ElementsMatch(t, expected, rows)
}

func TestGetNewVulnerabilities(t *testing.T) {
	// Previous scan with only one vulnerability - XRAY-1
	previousScan := services.ScanResponse{
		Vulnerabilities: []services.Vulnerability{{
			IssueId:    "XRAY-1",
			Summary:    "summary-1",
			Severity:   "high",
			Cves:       []services.Cve{{Id: "CVE-2023-1234"}},
			Components: map[string]services.Component{"component-A": {}, "component-B": {}},
			Technology: coreutils.Maven.ToString(),
		}},
	}

	// Current scan with 2 vulnerabilities - XRAY-1 and XRAY-2
	currentScan := services.ScanResponse{
		Vulnerabilities: []services.Vulnerability{
			{
				IssueId:    "XRAY-1",
				Summary:    "summary-1",
				Severity:   "high",
				Cves:       []services.Cve{{Id: "CVE-2023-1234"}},
				Components: map[string]services.Component{"component-A": {}, "component-B": {}},
				Technology: coreutils.Maven.ToString(),
			},
			{
				IssueId:    "XRAY-2",
				Summary:    "summary-2",
				Severity:   "low",
				Cves:       []services.Cve{{Id: "CVE-2023-4321"}},
				Components: map[string]services.Component{"component-C": {}, "component-D": {}},
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
	rows, err := createNewIssuesRows(
		&audit.Results{ExtendedScanResults: &utils2.ExtendedScanResults{XrayResults: []services.ScanResponse{previousScan}, EntitledForJas: true, ApplicabilityScanResults: map[string]string{"CVE-2023-4321": "Applicable"}}},
		&audit.Results{ExtendedScanResults: &utils2.ExtendedScanResults{XrayResults: []services.ScanResponse{currentScan}, EntitledForJas: true, ApplicabilityScanResults: map[string]string{"CVE-2023-4321": "Applicable"}}},
	)
	assert.NoError(t, err)
	assert.Len(t, rows, 2)
	assert.ElementsMatch(t, expected, rows)
}

func TestGetNewVulnerabilitiesCaseNoPrevVulnerabilities(t *testing.T) {
	// Previous scan with no vulnerabilities
	previousScan := services.ScanResponse{
		Vulnerabilities: []services.Vulnerability{},
	}

	// Current scan with 2 vulnerabilities - XRAY-1 and XRAY-2
	currentScan := services.ScanResponse{
		Vulnerabilities: []services.Vulnerability{
			{
				IssueId:             "XRAY-1",
				Summary:             "summary-1",
				Severity:            "high",
				ExtendedInformation: &services.ExtendedInformation{FullDescription: "description-1"},
				Components:          map[string]services.Component{"component-A": {}},
			},
			{
				IssueId:             "XRAY-2",
				Summary:             "summary-2",
				Severity:            "low",
				ExtendedInformation: &services.ExtendedInformation{FullDescription: "description-2"},
				Components:          map[string]services.Component{"component-B": {}},
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
	rows, err := createNewIssuesRows(
		&audit.Results{ExtendedScanResults: &utils2.ExtendedScanResults{XrayResults: []services.ScanResponse{previousScan}}},
		&audit.Results{ExtendedScanResults: &utils2.ExtendedScanResults{XrayResults: []services.ScanResponse{currentScan}}},
	)
	assert.NoError(t, err)
	assert.Len(t, rows, 2)
	assert.ElementsMatch(t, expected, rows)
}

func TestGetNewVulnerabilitiesCaseNoNewVulnerabilities(t *testing.T) {
	// Previous scan with 2 vulnerabilities - XRAY-1 and XRAY-2
	previousScan := services.ScanResponse{
		Vulnerabilities: []services.Vulnerability{
			{
				IssueId:    "XRAY-1",
				Summary:    "summary-1",
				Severity:   "high",
				Components: map[string]services.Component{"component-A": {}},
			},
			{
				IssueId:    "XRAY-2",
				Summary:    "summary-2",
				Severity:   "low",
				Components: map[string]services.Component{"component-B": {}},
			},
		},
	}

	// Current scan with no vulnerabilities
	currentScan := services.ScanResponse{
		Vulnerabilities: []services.Vulnerability{},
	}

	// Run createNewIssuesRows and expect no vulnerability in the results
	rows, err := createNewIssuesRows(
		&audit.Results{ExtendedScanResults: &utils2.ExtendedScanResults{XrayResults: []services.ScanResponse{previousScan}}},
		&audit.Results{ExtendedScanResults: &utils2.ExtendedScanResults{XrayResults: []services.ScanResponse{currentScan}}},
	)
	assert.NoError(t, err)
	assert.Len(t, rows, 0)
}

func TestCreatePullRequestMessageNoVulnerabilities(t *testing.T) {
	vulnerabilities := []formats.VulnerabilityOrViolationRow{}
	message := createPullRequestMessage(vulnerabilities, nil, &utils.StandardOutput{})

	expectedMessageByte, err := os.ReadFile(filepath.Join("testdata", "messages", "novulnerabilities.md"))
	assert.NoError(t, err)
	expectedMessage := strings.ReplaceAll(string(expectedMessageByte), "\r\n", "\n")
	assert.Equal(t, expectedMessage, message)

	outputWriter := &utils.StandardOutput{}
	outputWriter.SetVcsProvider(vcsutils.GitLab)
	message = createPullRequestMessage(vulnerabilities, nil, outputWriter)

	expectedMessageByte, err = os.ReadFile(filepath.Join("testdata", "messages", "novulnerabilitiesMR.md"))
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
	writerOutput := &utils.StandardOutput{}
	writerOutput.SetEntitledForJas(true)
	message := createPullRequestMessage(vulnerabilities, iac, writerOutput)

	expectedMessage := "[![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/vulnerabilitiesBannerPR.png)](https://github.com/jfrog/frogbot#readme)\n## 📦 Vulnerable Dependencies \n\n### ✍️ Summary\n\n<div align=\"center\">\n\n| SEVERITY                | CONTEXTUAL ANALYSIS                  | DIRECT DEPENDENCIES                  | IMPACTED DEPENDENCY                   | FIXED VERSIONS                       |\n| :---------------------: | :----------------------------------: | :----------------------------------: | :-----------------------------------: | :---------------------------------: | \n| ![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/applicableHighSeverity.png)<br>    High | github.com/nats-io/nats-streaming-server:v0.21.0 | github.com/nats-io/nats-streaming-server:v0.21.0 | [0.24.1] |\n| ![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/applicableHighSeverity.png)<br>    High | github.com/mholt/archiver/v3:v3.5.1 | github.com/mholt/archiver/v3:v3.5.1 |  |\n| ![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/applicableMediumSeverity.png)<br>  Medium | github.com/nats-io/nats-streaming-server:v0.21.0 | github.com/nats-io/nats-streaming-server:v0.21.0 | [0.24.3] |\n\n</div>\n\n## 👇 Details\n\n\n<details>\n<summary> <b>github.com/nats-io/nats-streaming-server v0.21.0</b> </summary>\n<br>\n\n- **Severity** 🔥 High\n- **Contextual Analysis:** Undetermined\n- **Package Name:** github.com/nats-io/nats-streaming-server\n- **Current Version:** v0.21.0\n- **Fixed Version:** [0.24.1]\n- **CVE:** CVE-2022-24450\n\n\n</details>\n\n\n<details>\n<summary> <b>github.com/mholt/archiver/v3 v3.5.1</b> </summary>\n<br>\n\n- **Severity** 🔥 High\n- **Contextual Analysis:** Undetermined\n- **Package Name:** github.com/mholt/archiver/v3\n- **Current Version:** v3.5.1\n\n\n</details>\n\n\n<details>\n<summary> <b>github.com/nats-io/nats-streaming-server v0.21.0</b> </summary>\n<br>\n\n- **Severity** 🎃 Medium\n- **Contextual Analysis:** Undetermined\n- **Package Name:** github.com/nats-io/nats-streaming-server\n- **Current Version:** v0.21.0\n- **Fixed Version:** [0.24.3]\n- **CVE:** CVE-2022-26652\n\n\n</details>\n\n\n## 🛠️ Infrastructure as Code \n\n<div align=\"center\">\n\n\n| SEVERITY                | FILE                  | LINE:COLUMN                   | FINDING                       |\n| :---------------------: | :----------------------------------: | :-----------------------------------: | :---------------------------------: | \n| ![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/applicableLowSeverity.png)<br>     Low | test.js | 1:20 | kms_key_id='' was detected |\n| ![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/applicableHighSeverity.png)<br>    High | test2.js | 4:30 | Deprecated TLS version was detected |\n\n</div>\n\n\n<div align=\"center\">\n\n[JFrog Frogbot](https://github.com/jfrog/frogbot#readme)\n\n</div>\n"
	assert.Equal(t, expectedMessage, message)

	writerOutput.SetVcsProvider(vcsutils.GitLab)
	message = createPullRequestMessage(vulnerabilities, iac, writerOutput)
	expectedMessage = "[![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/vulnerabilitiesBannerMR.png)](https://github.com/jfrog/frogbot#readme)\n## 📦 Vulnerable Dependencies \n\n### ✍️ Summary\n\n<div align=\"center\">\n\n| SEVERITY                | CONTEXTUAL ANALYSIS                  | DIRECT DEPENDENCIES                  | IMPACTED DEPENDENCY                   | FIXED VERSIONS                       |\n| :---------------------: | :----------------------------------: | :----------------------------------: | :-----------------------------------: | :---------------------------------: | \n| ![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/applicableHighSeverity.png)<br>    High | github.com/nats-io/nats-streaming-server:v0.21.0 | github.com/nats-io/nats-streaming-server:v0.21.0 | [0.24.1] |\n| ![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/applicableHighSeverity.png)<br>    High | github.com/mholt/archiver/v3:v3.5.1 | github.com/mholt/archiver/v3:v3.5.1 |  |\n| ![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/applicableMediumSeverity.png)<br>  Medium | github.com/nats-io/nats-streaming-server:v0.21.0 | github.com/nats-io/nats-streaming-server:v0.21.0 | [0.24.3] |\n\n</div>\n\n## 👇 Details\n\n\n<details>\n<summary> <b>github.com/nats-io/nats-streaming-server v0.21.0</b> </summary>\n<br>\n\n- **Severity** 🔥 High\n- **Contextual Analysis:** Undetermined\n- **Package Name:** github.com/nats-io/nats-streaming-server\n- **Current Version:** v0.21.0\n- **Fixed Version:** [0.24.1]\n- **CVE:** CVE-2022-24450\n\n\n</details>\n\n\n<details>\n<summary> <b>github.com/mholt/archiver/v3 v3.5.1</b> </summary>\n<br>\n\n- **Severity** 🔥 High\n- **Contextual Analysis:** Undetermined\n- **Package Name:** github.com/mholt/archiver/v3\n- **Current Version:** v3.5.1\n\n\n</details>\n\n\n<details>\n<summary> <b>github.com/nats-io/nats-streaming-server v0.21.0</b> </summary>\n<br>\n\n- **Severity** 🎃 Medium\n- **Contextual Analysis:** Undetermined\n- **Package Name:** github.com/nats-io/nats-streaming-server\n- **Current Version:** v0.21.0\n- **Fixed Version:** [0.24.3]\n- **CVE:** CVE-2022-26652\n\n\n</details>\n\n\n## 🛠️ Infrastructure as Code \n\n<div align=\"center\">\n\n\n| SEVERITY                | FILE                  | LINE:COLUMN                   | FINDING                       |\n| :---------------------: | :----------------------------------: | :-----------------------------------: | :---------------------------------: | \n| ![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/applicableLowSeverity.png)<br>     Low | test.js | 1:20 | kms_key_id='' was detected |\n| ![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/applicableHighSeverity.png)<br>    High | test2.js | 4:30 | Deprecated TLS version was detected |\n\n</div>\n\n\n<div align=\"center\">\n\n[JFrog Frogbot](https://github.com/jfrog/frogbot#readme)\n\n</div>\n"
	assert.Equal(t, expectedMessage, message)
}

func TestRunInstallIfNeeded(t *testing.T) {
	scanSetup := utils.ScanDetails{
		Project: &utils.Project{},
	}
	scanSetup.SetFailOnInstallationErrors(true)
	assert.NoError(t, runInstallIfNeeded(&scanSetup, ""))
	tmpDir, err := fileutils.CreateTempDir()
	assert.NoError(t, err)
	defer func() {
		err = fileutils.RemoveTempDir(tmpDir)
		assert.NoError(t, err)
	}()
	params := &utils.Project{
		InstallCommandName: "echo",
		InstallCommandArgs: []string{"Hello"},
	}
	scanSetup.Project = params
	assert.NoError(t, runInstallIfNeeded(&scanSetup, tmpDir))

	scanSetup.InstallCommandName = "not-exist"
	scanSetup.InstallCommandArgs = []string{"1", "2"}
	scanSetup.SetFailOnInstallationErrors(false)
	assert.NoError(t, runInstallIfNeeded(&scanSetup, tmpDir))

	params = &utils.Project{
		InstallCommandName: "not-existed",
		InstallCommandArgs: []string{"1", "2"},
	}
	scanSetup.Project = params
	scanSetup.SetFailOnInstallationErrors(true)
	assert.Error(t, runInstallIfNeeded(&scanSetup, tmpDir))
}

func TestScanPullRequest(t *testing.T) {
	testScanPullRequest(t, testProjConfigPath, "test-proj", true)
}

func TestScanPullRequestSameBranchFail(t *testing.T) {
	params, restoreEnv := verifyEnv(t)
	defer restoreEnv()

	// Create mock GitLab server
	projectName := "test-same-branch-fail"

	server := httptest.NewServer(createGitLabHandler(t, projectName))
	defer server.Close()

	configAggregator, client := prepareConfigAndClient(t, testSameBranchProjConfigPath, server, params)
	_, cleanUp := utils.PrepareTestEnvironment(t, projectName, "scanpullrequest")
	defer cleanUp()

	// Run "frogbot scan pull request"
	var scanPullRequest ScanPullRequestCmd
	err := scanPullRequest.Run(configAggregator, client)
	exceptedError := fmt.Errorf(utils.ErrScanPullRequestSameBranches, "main")
	assert.Equal(t, exceptedError, err)

	// Check env sanitize
	err = utils.SanitizeEnv()
	assert.NoError(t, err)
	utils.AssertSanitizedEnv(t)
}

func TestScanPullRequestNoFail(t *testing.T) {
	testScanPullRequest(t, testProjConfigPathNoFail, "test-proj", false)
}

func TestScanPullRequestSubdir(t *testing.T) {
	testScanPullRequest(t, testProjSubdirConfigPath, "test-proj-subdir", true)
}

func TestScanPullRequestNoIssues(t *testing.T) {
	testScanPullRequest(t, testCleanProjConfigPath, "clean-test-proj", false)
}

func TestScanPullRequestMultiWorkDir(t *testing.T) {
	testScanPullRequest(t, testMultiDirProjConfigPath, "multi-dir-test-proj", true)
}

func TestScanPullRequestMultiWorkDirNoFail(t *testing.T) {
	testScanPullRequest(t, testMultiDirProjConfigPathNoFail, "multi-dir-test-proj", false)
}

func testScanPullRequest(t *testing.T, configPath, projectName string, failOnSecurityIssues bool) {
	params, restoreEnv := verifyEnv(t)
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
	client := mockVcsClient(t)
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
	client := mockVcsClient(t)
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
	client := mockVcsClient(t)
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
		Params: utils.Params{Git: utils.Git{ClientInfo: utils.ClientInfo{
			VcsInfo: vcsclient.VcsInfo{APIEndpoint: "https://acme.vcs.io"}}},
		},
	}

	// Run verifyGitHubFrogbotEnvironment
	err := verifyGitHubFrogbotEnvironment(&vcsclient.GitHubClient{}, repoConfig)
	assert.NoError(t, err)
}

func prepareConfigAndClient(t *testing.T, configPath string, server *httptest.Server, serverParams coreconfig.ServerDetails) (utils.RepoAggregator, vcsclient.VcsClient) {
	gitTestParams := &utils.Git{
		ClientInfo: utils.ClientInfo{
			GitProvider: vcsutils.GitHub,
			RepoOwner:   "jfrog",
			VcsInfo: vcsclient.VcsInfo{
				Token:       "123456",
				APIEndpoint: server.URL,
			},
		},
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

func TestScanPullRequestError(t *testing.T) {
	app := clitool.App{Commands: GetCommands()}
	assert.Error(t, app.Run([]string{"frogbot", "spr"}))
}

// Create HTTP handler to mock GitLab server
func createGitLabHandler(t *testing.T, projectName string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Return 200 on ping
		if r.RequestURI == "/api/v4/" {
			w.WriteHeader(http.StatusOK)
			return
		}

		// Return test-proj.tar.gz when using DownloadRepository
		if r.RequestURI == fmt.Sprintf("/api/v4/projects/jfrog%s/repository/archive.tar.gz?sha=master", "%2F"+projectName) {
			w.WriteHeader(http.StatusOK)
			repoFile, err := os.ReadFile(filepath.Join("..", projectName+".tar.gz"))
			assert.NoError(t, err)
			_, err = w.Write(repoFile)
			assert.NoError(t, err)
		}
		// clean-test-proj should not include any vulnerabilities so assertion is not needed.
		if r.RequestURI == fmt.Sprintf("/api/v4/projects/jfrog%s/merge_requests/1/notes", "%2Fclean-test-proj") {
			w.WriteHeader(http.StatusOK)
			_, err := w.Write([]byte("{}"))
			assert.NoError(t, err)
			return
		}

		// Return 200 when using the REST that creates the comment
		if r.RequestURI == fmt.Sprintf("/api/v4/projects/jfrog%s/merge_requests/1/notes", "%2F"+projectName) {
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
		}
	}
}

// Check connection details with JFrog instance.
// Return a callback method that restores the credentials after the test is done.
func verifyEnv(t *testing.T) (server coreconfig.ServerDetails, restoreFunc func()) {
	url := strings.TrimSuffix(os.Getenv(utils.JFrogUrlEnv), "/")
	username := os.Getenv(utils.JFrogUserEnv)
	password := os.Getenv(utils.JFrogPasswordEnv)
	token := os.Getenv(utils.JFrogTokenEnv)
	if url == "" {
		assert.FailNow(t, fmt.Sprintf("'%s' is not set", utils.JFrogUrlEnv))
	}
	if token == "" && (username == "" || password == "") {
		assert.FailNow(t, fmt.Sprintf("'%s' or '%s' and '%s' are not set", utils.JFrogTokenEnv, utils.JFrogUserEnv, utils.JFrogPasswordEnv))
	}
	server.Url = url
	server.XrayUrl = url + "/xray/"
	server.ArtifactoryUrl = url + "/artifactory/"
	server.User = username
	server.Password = password
	server.AccessToken = token
	restoreFunc = func() {
		utils.SetEnvAndAssert(t, map[string]string{
			utils.JFrogUrlEnv:          url,
			utils.JFrogTokenEnv:        token,
			utils.JFrogUserEnv:         username,
			utils.JFrogPasswordEnv:     password,
			utils.GitAggregateFixesEnv: "FALSE",
		})
	}
	return
}

func TestGetFullPathWorkingDirs(t *testing.T) {
	sampleProject := utils.Project{
		WorkingDirs: []string{filepath.Join("a", "b"), filepath.Join("a", "b", "c"), ".", filepath.Join("c", "d", "e", "f")},
	}
	baseWd := "tempDir"
	fullPathWds := getFullPathWorkingDirs(sampleProject.WorkingDirs, baseWd)
	expectedWds := []string{filepath.Join("tempDir", "a", "b"), filepath.Join("tempDir", "a", "b", "c"), "tempDir", filepath.Join("tempDir", "c", "d", "e", "f")}
	for _, expectedWd := range expectedWds {
		assert.Contains(t, fullPathWds, expectedWd)
	}
}

func TestCreateNewIacRows(t *testing.T) {
	testCases := []struct {
		name                            string
		targetIacResults                []utils2.IacOrSecretResult
		sourceIacResults                []utils2.IacOrSecretResult
		expectedAddedIacVulnerabilities []formats.IacSecretsRow
	}{
		{
			name: "No vulnerabilities in source IaC results",
			targetIacResults: []utils2.IacOrSecretResult{
				{
					Severity:   "High",
					File:       "file1",
					LineColumn: "1:10",
					Type:       "Secret",
					Text:       "Sensitive information",
				},
			},
			sourceIacResults:                []utils2.IacOrSecretResult{},
			expectedAddedIacVulnerabilities: []formats.IacSecretsRow{},
		},
		{
			name:             "No vulnerabilities in target IaC results",
			targetIacResults: []utils2.IacOrSecretResult{},
			sourceIacResults: []utils2.IacOrSecretResult{
				{
					Severity:   "High",
					File:       "file1",
					LineColumn: "1:10",
					Type:       "Secret",
					Text:       "Sensitive information",
				},
			},
			expectedAddedIacVulnerabilities: []formats.IacSecretsRow{
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
			name: "Some new vulnerabilities in source IaC results",
			targetIacResults: []utils2.IacOrSecretResult{
				{
					Severity:   "High",
					File:       "file1",
					LineColumn: "1:10",
					Type:       "Secret",
					Text:       "Sensitive information",
				},
			},
			sourceIacResults: []utils2.IacOrSecretResult{
				{
					Severity:   "Medium",
					File:       "file2",
					LineColumn: "2:5",
					Type:       "Secret",
					Text:       "Confidential data",
				},
			},
			expectedAddedIacVulnerabilities: []formats.IacSecretsRow{
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
			addedIacVulnerabilities := createNewIacRows(tc.targetIacResults, tc.sourceIacResults)
			assert.ElementsMatch(t, tc.expectedAddedIacVulnerabilities, addedIacVulnerabilities)
		})
	}
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
