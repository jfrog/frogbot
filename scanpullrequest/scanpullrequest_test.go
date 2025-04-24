package scanpullrequest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/jfrog/jfrog-cli-security/utils/xsc"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jfrog/frogbot/v2/utils"
	"github.com/jfrog/frogbot/v2/utils/issues"
	"github.com/jfrog/frogbot/v2/utils/outputwriter"
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/froggit-go/vcsutils"
	coreconfig "github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-security/tests/validations"
	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/formats/sarifutils"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/results/conversion"
	"github.com/jfrog/jfrog-cli-security/utils/severityutils"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray/services"
	"github.com/owenrumney/go-sarif/v2/sarif"
	"github.com/stretchr/testify/assert"
	// securityUtils "github.com/jfrog/jfrog-cli-security/utils"
	// securityTestUtils "github.com/jfrog/jfrog-cli-security/tests/utils"
	// xscServices "github.com/jfrog/jfrog-client-go/xsc/services"
)

const (
	testMultiDirProjConfigPath       = "testdata/config/frogbot-config-multi-dir-test-proj.yml"
	testMultiDirProjConfigPathNoFail = "testdata/config/frogbot-config-multi-dir-test-proj-no-fail.yml"
	testProjSubdirConfigPath         = "testdata/config/frogbot-config-test-proj-subdir.yml"
	testCleanProjConfigPath          = "testdata/config/frogbot-config-clean-test-proj.yml"
	testProjConfigPath               = "testdata/config/frogbot-config-test-proj.yml"
	testProjConfigPathNoFail         = "testdata/config/frogbot-config-test-proj-no-fail.yml"
	testJasProjConfigPath            = "testdata/config/frogbot-config-jas-diff-proj.yml"
	testSourceBranchName             = "pr"
	testTargetBranchName             = "master"
)

func createScaDiff(t *testing.T, previousScan, currentScan services.ScanResponse, applicable bool, allowedLicenses ...string) (securityViolationsRows []formats.VulnerabilityOrViolationRow, licenseViolations []formats.LicenseViolationRow) {
	sourceResults, err := scaToDummySimpleJsonResults(currentScan, applicable, allowedLicenses...)
	assert.NoError(t, err)
	targetResults, err := scaToDummySimpleJsonResults(previousScan, applicable, allowedLicenses...)
	assert.NoError(t, err)
	securityViolationsRows = getUniqueVulnerabilityOrViolationRows(
		append(targetResults.Vulnerabilities, targetResults.SecurityViolations...),
		append(sourceResults.Vulnerabilities, sourceResults.SecurityViolations...),
	)
	licenseViolations = getUniqueLicenseRows(targetResults.LicensesViolations, sourceResults.LicensesViolations)
	return
}

func scaToDummySimpleJsonResults(response services.ScanResponse, applicable bool, allowedLicenses ...string) (formats.SimpleJsonResults, error) {
	convertor := conversion.NewCommandResultsConvertor(conversion.ResultConvertParams{IncludeVulnerabilities: true, HasViolationContext: true, AllowedLicenses: allowedLicenses})
	jasResults := &results.JasScansResults{}
	if applicable {
		jasResults.ApplicabilityScanResults = append(jasResults.ApplicabilityScanResults, validations.NewMockJasRuns(sarifutils.CreateRunWithDummyResults(sarifutils.CreateResultWithOneLocation("file1", 1, 10, 2, 11, "snippet", "applic_CVE-2023-4321", "")))...)
	}
	cmdResults := &results.SecurityCommandResults{EntitledForJas: applicable, Targets: []*results.TargetResults{{
		ScanTarget: results.ScanTarget{Target: "dummy"},
		JasResults: jasResults,
		ScaResults: &results.ScaScanResults{XrayResults: validations.NewMockScaResults(response)},
	}}}
	return convertor.ConvertToSimpleJson(cmdResults)
}

func createJasDiff(t *testing.T, scanType jasutils.JasScanType, source, target []*sarif.Result) (jasViolationsRows []formats.SourceCodeRow) {
	sourceResults, err := jasToDummySimpleJsonResults(scanType, source)
	assert.NoError(t, err)
	targetResults, err := jasToDummySimpleJsonResults(scanType, target)
	assert.NoError(t, err)

	var targetJasResults, sourceJasResults []formats.SourceCodeRow
	switch scanType {
	case jasutils.Sast:
		targetJasResults = targetResults.SastVulnerabilities
		sourceJasResults = sourceResults.SastVulnerabilities
	case jasutils.Secrets:
		targetJasResults = targetResults.SecretsVulnerabilities
		sourceJasResults = sourceResults.SecretsVulnerabilities
	case jasutils.IaC:
		targetJasResults = targetResults.IacsVulnerabilities
		sourceJasResults = sourceResults.IacsVulnerabilities
	}

	return createNewSourceCodeRows(targetJasResults, sourceJasResults)
}

func jasToDummySimpleJsonResults(scanType jasutils.JasScanType, jasScanResults []*sarif.Result) (formats.SimpleJsonResults, error) {
	convertor := conversion.NewCommandResultsConvertor(conversion.ResultConvertParams{IncludeVulnerabilities: true, HasViolationContext: true})

	jasResults := &results.JasScansResults{JasVulnerabilities: results.JasScanResults{}}
	switch scanType {
	case jasutils.Sast:
		jasResults.JasVulnerabilities.SastScanResults = append(jasResults.JasVulnerabilities.SastScanResults, validations.NewMockJasRuns(sarifutils.CreateRunWithDummyResults(jasScanResults...))...)
	case jasutils.Secrets:
		jasResults.JasVulnerabilities.SecretsScanResults = append(jasResults.JasVulnerabilities.SecretsScanResults, validations.NewMockJasRuns(sarifutils.CreateRunWithDummyResults(jasScanResults...))...)
	case jasutils.IaC:
		jasResults.JasVulnerabilities.IacScanResults = append(jasResults.JasVulnerabilities.IacScanResults, validations.NewMockJasRuns(sarifutils.CreateRunWithDummyResults(jasScanResults...))...)
	}
	cmdResults := &results.SecurityCommandResults{EntitledForJas: true, Targets: []*results.TargetResults{{
		ScanTarget: results.ScanTarget{Target: "dummy"},
		JasResults: jasResults,
	}}}
	return convertor.ConvertToSimpleJson(cmdResults)
}

func TestCreateVulnerabilitiesRows(t *testing.T) {
	// Previous scan with only one violation - XRAY-1
	previousScan := services.ScanResponse{
		Violations: []services.Violation{
			{
				IssueId:       "XRAY-1",
				Summary:       "summary-1",
				Severity:      "high",
				Cves:          []services.Cve{},
				ViolationType: "security",
				Components:    map[string]services.Component{"component-A": {}, "component-B": {}},
			},
			{
				IssueId:       "XRAY-4",
				ViolationType: "license",
				Severity:      "low",
				LicenseKey:    "Apache-2.0",
				Components:    map[string]services.Component{"Dep-2": {}},
			},
		},
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
			{
				IssueId:       "XRAY-3",
				ViolationType: "license",
				Severity:      "low",
				LicenseKey:    "MIT",
				Components:    map[string]services.Component{"Dep-1": {}},
			},
		},
	}

	// Run createNewIssuesRows and make sure that only the XRAY-2 violation exists in the results
	securityViolationsRows, licenseViolations := createScaDiff(t, previousScan, currentScan, false)

	assert.Len(t, licenseViolations, 1)
	assert.Len(t, securityViolationsRows, 2)
	assert.Equal(t, "XRAY-2", securityViolationsRows[0].IssueId)
	assert.Equal(t, "Low", securityViolationsRows[0].Severity)
	assert.Equal(t, "XRAY-2", securityViolationsRows[1].IssueId)
	assert.Equal(t, "Low", securityViolationsRows[1].Severity)
	assert.Equal(t, "MIT", licenseViolations[0].LicenseKey)
	assert.Equal(t, "Dep-1", licenseViolations[0].ImpactedDependencyName)

	impactedPackageOne := securityViolationsRows[0].ImpactedDependencyName
	impactedPackageTwo := securityViolationsRows[1].ImpactedDependencyName
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
			{
				IssueId:       "XRAY-3",
				ViolationType: "license",
				LicenseKey:    "MIT",
				Severity:      "low",
				Components:    map[string]services.Component{"Dep-1": {}},
			},
		},
	}

	expectedVulns := []formats.VulnerabilityOrViolationRow{
		{
			IssueId: "XRAY-1",
			Summary: "summary-1",
			ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
				SeverityDetails:        formats.SeverityDetails{Severity: "High", SeverityNumValue: 18},
				ImpactedDependencyName: "component-A",
			},
		},
		{
			IssueId: "XRAY-2",
			Summary: "summary-2",
			ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
				SeverityDetails:        formats.SeverityDetails{Severity: "Low", SeverityNumValue: 10},
				ImpactedDependencyName: "component-C",
			},
		},
	}

	expectedLicenses := []formats.LicenseRow{
		{
			ImpactedDependencyDetails: formats.ImpactedDependencyDetails{ImpactedDependencyName: "Dep-1"},
			LicenseKey:                "MIT",
		},
	}

	// Run createNewIssuesRows and expect both XRAY-1 and XRAY-2 violation in the results
	securityViolationsRows, licenseViolations := createScaDiff(t, previousScan, currentScan, false)

	assert.Len(t, licenseViolations, 1)
	assert.Len(t, securityViolationsRows, 2)
	assert.ElementsMatch(t, expectedVulns, securityViolationsRows)
	assert.Equal(t, expectedLicenses[0].ImpactedDependencyName, licenseViolations[0].ImpactedDependencyName)
	assert.Equal(t, expectedLicenses[0].LicenseKey, licenseViolations[0].LicenseKey)
}

func TestGetNewViolationsCaseNoNewViolations(t *testing.T) {
	// Previous scan with 2 security violations and 1 license violation - XRAY-1 and XRAY-2
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
			{
				IssueId:       "XRAY-3",
				LicenseKey:    "MIT",
				Severity:      "medium",
				ViolationType: "license",
				Components:    map[string]services.Component{"component-B": {}},
			},
		},
	}

	// Current scan with no violation
	currentScan := services.ScanResponse{
		Violations: []services.Violation{},
	}

	// Run createNewIssuesRows and expect no violations in the results
	securityViolationsRows, licenseViolations := createScaDiff(t, previousScan, currentScan, false, "MIT")

	assert.Len(t, securityViolationsRows, 0)
	assert.Len(t, licenseViolations, 0)
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
			Technology: techutils.Maven.String(),
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
				Technology: techutils.Maven.String(),
			},
			{
				IssueId:    "XRAY-2",
				Summary:    "summary-2",
				Severity:   "low",
				Cves:       []services.Cve{{Id: "CVE-2023-4321"}},
				Components: map[string]services.Component{"component-C": {}, "component-D": {}},
				Technology: techutils.Yarn.String(),
			},
		},
	}

	expected := []formats.VulnerabilityOrViolationRow{
		{
			Summary:    "summary-2",
			Applicable: "Applicable",
			IssueId:    "XRAY-2",
			ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
				SeverityDetails:        formats.SeverityDetails{Severity: "Low", SeverityNumValue: 13},
				ImpactedDependencyName: "component-C",
			},
			Cves:       []formats.CveRow{{Id: "CVE-2023-4321", Applicability: &formats.Applicability{Status: "Applicable", ScannerDescription: "rule-msg", Evidence: []formats.Evidence{{Reason: "result-msg", Location: formats.Location{File: "file1", StartLine: 1, StartColumn: 10, EndLine: 2, EndColumn: 11, Snippet: "snippet"}}}}}},
			Technology: techutils.Yarn,
		},
		{
			Summary:    "summary-2",
			Applicable: "Applicable",
			IssueId:    "XRAY-2",
			ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
				SeverityDetails:        formats.SeverityDetails{Severity: "Low", SeverityNumValue: 13},
				ImpactedDependencyName: "component-D",
			},
			Cves:       []formats.CveRow{{Id: "CVE-2023-4321", Applicability: &formats.Applicability{Status: "Applicable", ScannerDescription: "rule-msg", Evidence: []formats.Evidence{{Reason: "result-msg", Location: formats.Location{File: "file1", StartLine: 1, StartColumn: 10, EndLine: 2, EndColumn: 11, Snippet: "snippet"}}}}}},
			Technology: techutils.Yarn,
		},
	}

	// Run createNewIssuesRows and make sure that only the XRAY-2 vulnerability exists in the results
	securityViolationsRows, licenseViolations := createScaDiff(t, previousScan, currentScan, true)

	assert.Len(t, securityViolationsRows, 2)
	assert.Len(t, licenseViolations, 0)
	assert.ElementsMatch(t, expected, securityViolationsRows)
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
			Summary: "summary-2",
			IssueId: "XRAY-2",
			ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
				SeverityDetails:        formats.SeverityDetails{Severity: "Low", SeverityNumValue: 10},
				ImpactedDependencyName: "component-B",
			},
			JfrogResearchInformation: &formats.JfrogResearchInformation{Details: "description-2"},
		},
		{
			Summary: "summary-1",
			IssueId: "XRAY-1",
			ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
				SeverityDetails:        formats.SeverityDetails{Severity: "High", SeverityNumValue: 18},
				ImpactedDependencyName: "component-A",
			},
			JfrogResearchInformation: &formats.JfrogResearchInformation{Details: "description-1"},
		},
	}

	// Run createNewIssuesRows and expect both XRAY-1 and XRAY-2 vulnerability in the results
	securityViolationsRows, licenseViolations := createScaDiff(t, previousScan, currentScan, false)

	assert.Len(t, securityViolationsRows, 2)
	assert.Len(t, licenseViolations, 0)
	assert.ElementsMatch(t, expected, securityViolationsRows)
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
	securityViolationsRows, licenseViolations := createScaDiff(t, previousScan, currentScan, false)

	assert.Len(t, securityViolationsRows, 0)
	assert.Len(t, licenseViolations, 0)
}

func TestScanResultsToIssuesCollection(t *testing.T) {
	allowedLicenses := []string{"MIT"}
	auditResults := &results.SecurityCommandResults{EntitledForJas: true, ResultContext: results.ResultContext{IncludeVulnerabilities: true}, Targets: []*results.TargetResults{{
		ScanTarget: results.ScanTarget{Target: "dummy"},
		ScaResults: &results.ScaScanResults{
			XrayResults: validations.NewMockScaResults(services.ScanResponse{
				Vulnerabilities: []services.Vulnerability{
					{Cves: []services.Cve{{Id: "CVE-2022-2122"}}, Severity: "High", Components: map[string]services.Component{"Dep-1": {FixedVersions: []string{"1.2.3"}}}},
					{Cves: []services.Cve{{Id: "CVE-2023-3122"}}, Severity: "Low", Components: map[string]services.Component{"Dep-2": {FixedVersions: []string{"1.2.2"}}}},
				},
				Licenses: []services.License{{Key: "Apache-2.0", Components: map[string]services.Component{"Dep-1": {FixedVersions: []string{"1.2.3"}}}}},
			}),
		},
		JasResults: &results.JasScansResults{
			ApplicabilityScanResults: validations.NewMockJasRuns(
				sarifutils.CreateRunWithDummyResults(
					sarifutils.CreateDummyPassingResult("applic_CVE-2023-3122"),
					sarifutils.CreateResultWithOneLocation("file1", 1, 10, 2, 11, "snippet", "applic_CVE-2022-2122", ""),
				),
			),
			JasVulnerabilities: results.JasScanResults{
				IacScanResults: validations.NewMockJasRuns(
					sarifutils.CreateRunWithDummyResults(
						sarifutils.CreateResultWithLocations("Missing auto upgrade was detected", "rule", severityutils.SeverityToSarifSeverityLevel(severityutils.High).String(),
							sarifutils.CreateLocation("file1", 1, 10, 2, 11, "aws-violation"),
						),
					),
				),
				SecretsScanResults: validations.NewMockJasRuns(
					sarifutils.CreateRunWithDummyResults(
						sarifutils.CreateResultWithLocations("Secret", "rule", severityutils.SeverityToSarifSeverityLevel(severityutils.High).String(),
							sarifutils.CreateLocation("index.js", 5, 6, 7, 8, "access token exposed"),
						),
					),
				),
				SastScanResults: validations.NewMockJasRuns(
					sarifutils.CreateRunWithDummyResults(
						sarifutils.CreateResultWithLocations("XSS Vulnerability", "rule", severityutils.SeverityToSarifSeverityLevel(severityutils.High).String(),
							sarifutils.CreateLocation("file1", 1, 10, 2, 11, "snippet"),
						),
					),
				),
			},
		},
	}}}
	expectedOutput := &issues.ScansIssuesCollection{
		ScaVulnerabilities: []formats.VulnerabilityOrViolationRow{
			{
				Applicable:    "Applicable",
				FixedVersions: []string{"1.2.3"},
				ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
					SeverityDetails:        formats.SeverityDetails{Severity: "High", SeverityNumValue: 21},
					ImpactedDependencyName: "Dep-1",
				},
				Cves: []formats.CveRow{{Id: "CVE-2022-2122", Applicability: &formats.Applicability{Status: "Applicable", ScannerDescription: "rule-msg", Evidence: []formats.Evidence{{Reason: "result-msg", Location: formats.Location{File: "file1", StartLine: 1, StartColumn: 10, EndLine: 2, EndColumn: 11, Snippet: "snippet"}}}}}},
			},
			{
				Applicable:    "Not Applicable",
				FixedVersions: []string{"1.2.2"},
				ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
					SeverityDetails:        formats.SeverityDetails{Severity: "Low", SeverityNumValue: 2},
					ImpactedDependencyName: "Dep-2",
				},
				Cves: []formats.CveRow{{Id: "CVE-2023-3122", Applicability: &formats.Applicability{Status: "Not Applicable", ScannerDescription: "rule-msg"}}},
			},
		},
		IacVulnerabilities: []formats.SourceCodeRow{
			{
				SeverityDetails: formats.SeverityDetails{
					Severity:         "High",
					SeverityNumValue: 21,
				},
				ScannerInfo: formats.ScannerInfo{
					ScannerDescription: "rule-msg",
					RuleId:             "rule",
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
		SecretsVulnerabilities: []formats.SourceCodeRow{
			{
				SeverityDetails: formats.SeverityDetails{
					Severity:         "High",
					SeverityNumValue: 21,
				},
				ScannerInfo: formats.ScannerInfo{
					ScannerDescription: "rule-msg",
					RuleId:             "rule",
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
		SastVulnerabilities: []formats.SourceCodeRow{
			{
				SeverityDetails: formats.SeverityDetails{
					Severity:         "High",
					SeverityNumValue: 21,
				},
				ScannerInfo: formats.ScannerInfo{
					ScannerDescription: "rule-msg",
					RuleId:             "rule",
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
		LicensesViolations: []formats.LicenseViolationRow{
			{
				LicenseRow: formats.LicenseRow{
					LicenseKey: "Apache-2.0",
					ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
						SeverityDetails: formats.SeverityDetails{
							Severity:         "Medium",
							SeverityNumValue: 14,
						},
						ImpactedDependencyName: "Dep-1",
					},
				},
				ViolationContext: formats.ViolationContext{
					Watch: "jfrog_custom_license_violation",
				},
			},
		},
	}

	issuesRows, err := scanResultsToIssuesCollection(auditResults, allowedLicenses)

	if assert.NoError(t, err) {
		assert.ElementsMatch(t, expectedOutput.ScaVulnerabilities, issuesRows.ScaVulnerabilities)
		assert.ElementsMatch(t, expectedOutput.IacVulnerabilities, issuesRows.IacVulnerabilities)
		assert.ElementsMatch(t, expectedOutput.SecretsVulnerabilities, issuesRows.SecretsVulnerabilities)
		assert.ElementsMatch(t, expectedOutput.SastVulnerabilities, issuesRows.SastVulnerabilities)
		assert.ElementsMatch(t, expectedOutput.LicensesViolations, issuesRows.LicensesViolations)
	}
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
	configAggregator, client, cleanUp := preparePullRequestTest(t, projectName, configPath)
	defer cleanUp()

	// Run "frogbot scan pull request"
	var scanPullRequest ScanPullRequestCmd
	err := scanPullRequest.Run(configAggregator, client, utils.MockHasConnection())
	if failOnSecurityIssues {
		assert.EqualErrorf(t, err, SecurityIssueFoundErr, "Error should be: %v, got: %v", SecurityIssueFoundErr, err)
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

func prepareConfigAndClient(t *testing.T, xrayVersion, xscVersion, configPath string, server *httptest.Server, serverParams coreconfig.ServerDetails, gitServerParams GitServerParams) (utils.RepoAggregator, vcsclient.VcsClient) {
	gitTestParams := &utils.Git{
		GitProvider: vcsutils.GitHub,
		RepoOwner:   gitServerParams.RepoOwner,
		VcsInfo: vcsclient.VcsInfo{
			Token:       "123456",
			APIEndpoint: server.URL,
		},
		PullRequestDetails: gitServerParams.prDetails,
	}
	utils.SetEnvAndAssert(t, map[string]string{utils.GitPullRequestIDEnv: fmt.Sprintf("%d", gitServerParams.prDetails.ID)})

	client, err := vcsclient.NewClientBuilder(vcsutils.GitLab).ApiEndpoint(server.URL).Token("123456").Build()
	assert.NoError(t, err)

	configData, err := utils.ReadConfigFromFileSystem(configPath)
	assert.NoError(t, err)
	configAggregator, err := utils.BuildRepoAggregator(xrayVersion, xscVersion, client, configData, gitTestParams, &serverParams, utils.ScanPullRequest)
	assert.NoError(t, err)

	return configAggregator, client
}

func TestCreateNewIacRows(t *testing.T) {
	testCases := []struct {
		name                            string
		targetIacResults                []*sarif.Result
		sourceIacResults                []*sarif.Result
		expectedAddedIacVulnerabilities []formats.SourceCodeRow
	}{
		{
			name: "No vulnerabilities in source IaC results",
			targetIacResults: []*sarif.Result{
				sarifutils.CreateResultWithLocations("Missing auto upgrade was detected", "rule", severityutils.SeverityToSarifSeverityLevel(severityutils.High).String(),
					sarifutils.CreateLocation("file1", 1, 10, 2, 11, "aws-violation"),
				),
			},
			sourceIacResults:                []*sarif.Result{},
			expectedAddedIacVulnerabilities: []formats.SourceCodeRow{},
		},
		{
			name:             "No vulnerabilities in target IaC results",
			targetIacResults: []*sarif.Result{},
			sourceIacResults: []*sarif.Result{
				sarifutils.CreateResultWithLocations("Missing auto upgrade was detected", "rule", severityutils.SeverityToSarifSeverityLevel(severityutils.High).String(),
					sarifutils.CreateLocation("file1", 1, 10, 2, 11, "aws-violation"),
				),
			},
			expectedAddedIacVulnerabilities: []formats.SourceCodeRow{
				{
					SeverityDetails: formats.SeverityDetails{
						Severity:         "High",
						SeverityNumValue: 21,
					},
					ScannerInfo: formats.ScannerInfo{
						RuleId:             "rule",
						ScannerDescription: "rule-msg",
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
		},
		{
			name: "Some new vulnerabilities in source IaC results",
			targetIacResults: []*sarif.Result{
				sarifutils.CreateResultWithLocations("Missing auto upgrade was detected", "rule", severityutils.SeverityToSarifSeverityLevel(severityutils.High).String(),
					sarifutils.CreateLocation("file1", 1, 10, 2, 11, "aws-violation"),
				),
			},
			sourceIacResults: []*sarif.Result{
				sarifutils.CreateResultWithLocations("enable_private_endpoint=false was detected", "rule", severityutils.SeverityToSarifSeverityLevel(severityutils.Medium).String(),
					sarifutils.CreateLocation("file2", 2, 5, 3, 6, "gcp-violation"),
				),
			},
			expectedAddedIacVulnerabilities: []formats.SourceCodeRow{
				{
					SeverityDetails: formats.SeverityDetails{
						Severity:         "Medium",
						SeverityNumValue: 17,
					},
					ScannerInfo: formats.ScannerInfo{
						RuleId:             "rule",
						ScannerDescription: "rule-msg",
					},
					Finding: "enable_private_endpoint=false was detected",
					Location: formats.Location{
						File:        "file2",
						StartLine:   2,
						StartColumn: 5,
						EndLine:     3,
						EndColumn:   6,
						Snippet:     "gcp-violation",
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			addedIacVulnerabilities := createJasDiff(t, jasutils.IaC, tc.sourceIacResults, tc.targetIacResults)
			assert.ElementsMatch(t, tc.expectedAddedIacVulnerabilities, addedIacVulnerabilities)
		})
	}
}

func TestCreateNewSecretRows(t *testing.T) {
	testCases := []struct {
		name                                string
		targetSecretsResults                []*sarif.Result
		sourceSecretsResults                []*sarif.Result
		expectedAddedSecretsVulnerabilities []formats.SourceCodeRow
	}{
		{
			name: "No vulnerabilities in source secrets results",
			targetSecretsResults: []*sarif.Result{
				sarifutils.CreateResultWithLocations("Secret", "rule", severityutils.SeverityToSarifSeverityLevel(severityutils.High).String(),
					sarifutils.CreateLocation("file1", 1, 10, 2, 11, "Sensitive information"),
				),
			},
			sourceSecretsResults:                []*sarif.Result{},
			expectedAddedSecretsVulnerabilities: []formats.SourceCodeRow{},
		},
		{
			name:                 "No vulnerabilities in target secrets results",
			targetSecretsResults: []*sarif.Result{},
			sourceSecretsResults: []*sarif.Result{
				sarifutils.CreateResultWithLocations("Secret", "rule", severityutils.SeverityToSarifSeverityLevel(severityutils.High).String(),
					sarifutils.CreateLocation("file1", 1, 10, 2, 11, "Sensitive information"),
				),
			},
			expectedAddedSecretsVulnerabilities: []formats.SourceCodeRow{
				{
					SeverityDetails: formats.SeverityDetails{
						Severity:         "High",
						SeverityNumValue: 21,
					},
					ScannerInfo: formats.ScannerInfo{
						RuleId:             "rule",
						ScannerDescription: "rule-msg",
					},
					Finding: "Secret",
					Location: formats.Location{
						File:        "file1",
						StartLine:   1,
						StartColumn: 10,
						EndLine:     2,
						EndColumn:   11,
						Snippet:     "Sensitive information",
					},
				},
			},
		},
		{
			name: "Some new vulnerabilities in source secrets results",
			targetSecretsResults: []*sarif.Result{
				sarifutils.CreateResultWithLocations("Secret", "rule", severityutils.SeverityToSarifSeverityLevel(severityutils.High).String(),
					sarifutils.CreateLocation("file1", 1, 10, 2, 11, "Sensitive information"),
				),
			},
			sourceSecretsResults: []*sarif.Result{
				sarifutils.CreateResultWithLocations("Secret", "rule", severityutils.SeverityToSarifSeverityLevel(severityutils.Medium).String(),
					sarifutils.CreateLocation("file2", 2, 5, 3, 6, "Confidential data"),
				),
			},
			expectedAddedSecretsVulnerabilities: []formats.SourceCodeRow{
				{
					SeverityDetails: formats.SeverityDetails{
						Severity:         "Medium",
						SeverityNumValue: 17,
					},
					ScannerInfo: formats.ScannerInfo{
						RuleId:             "rule",
						ScannerDescription: "rule-msg",
					},
					Finding: "Secret",
					Location: formats.Location{
						File:        "file2",
						StartLine:   2,
						StartColumn: 5,
						EndLine:     3,
						EndColumn:   6,
						Snippet:     "Confidential data",
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			addedSecretsVulnerabilities := createJasDiff(t, jasutils.Secrets, tc.sourceSecretsResults, tc.targetSecretsResults)
			assert.ElementsMatch(t, tc.expectedAddedSecretsVulnerabilities, addedSecretsVulnerabilities)
		})
	}
}

func TestCreateNewSastRows(t *testing.T) {
	testCases := []struct {
		name                             string
		targetSastResults                []*sarif.Result
		sourceSastResults                []*sarif.Result
		expectedAddedSastVulnerabilities []formats.SourceCodeRow
	}{
		{
			name: "No vulnerabilities in source Sast results",
			targetSastResults: []*sarif.Result{
				sarifutils.CreateResultWithLocations("XSS Vulnerability", "rule", severityutils.SeverityToSarifSeverityLevel(severityutils.High).String(),
					sarifutils.CreateLocation("file1", 1, 10, 2, 11, "snippet"),
				),
			},
			sourceSastResults:                []*sarif.Result{},
			expectedAddedSastVulnerabilities: []formats.SourceCodeRow{},
		},
		{
			name:              "No vulnerabilities in target Sast results",
			targetSastResults: []*sarif.Result{},
			sourceSastResults: []*sarif.Result{
				sarifutils.CreateResultWithLocations("XSS Vulnerability", "rule", severityutils.SeverityToSarifSeverityLevel(severityutils.High).String(),
					sarifutils.CreateLocation("file1", 1, 10, 2, 11, "snippet"),
				),
			},
			expectedAddedSastVulnerabilities: []formats.SourceCodeRow{
				{
					SeverityDetails: formats.SeverityDetails{
						Severity:         "High",
						SeverityNumValue: 21,
					},
					ScannerInfo: formats.ScannerInfo{
						RuleId:             "rule",
						ScannerDescription: "rule-msg",
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
		{
			name: "Some new vulnerabilities in source Sast results",
			targetSastResults: []*sarif.Result{
				sarifutils.CreateResultWithLocations("XSS Vulnerability", "rule", severityutils.SeverityToSarifSeverityLevel(severityutils.High).String(),
					sarifutils.CreateLocation("file1", 1, 10, 2, 11, "snippet"),
				),
			},
			sourceSastResults: []*sarif.Result{
				sarifutils.CreateResultWithLocations("Stack Trace Exposure", "rule", severityutils.SeverityToSarifSeverityLevel(severityutils.Medium).String(),
					sarifutils.CreateLocation("file2", 2, 5, 3, 6, "other-snippet"),
				),
			},
			expectedAddedSastVulnerabilities: []formats.SourceCodeRow{
				{
					SeverityDetails: formats.SeverityDetails{
						Severity:         "Medium",
						SeverityNumValue: 17,
					},
					ScannerInfo: formats.ScannerInfo{
						RuleId:             "rule",
						ScannerDescription: "rule-msg",
					},
					Finding: "Stack Trace Exposure",
					Location: formats.Location{
						File:        "file2",
						StartLine:   2,
						StartColumn: 5,
						EndLine:     3,
						EndColumn:   6,
						Snippet:     "other-snippet",
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			addedSastVulnerabilities := createJasDiff(t, jasutils.Sast, tc.sourceSastResults, tc.targetSastResults)
			assert.ElementsMatch(t, tc.expectedAddedSastVulnerabilities, addedSastVulnerabilities)
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

	testCases := []struct {
		name         string
		commentsOnPR []vcsclient.CommentInfo
		err          error
	}{
		{
			name: "Test with comment returned",
			commentsOnPR: []vcsclient.CommentInfo{
				{ID: 20, Content: outputwriter.GetBanner(outputwriter.NoVulnerabilityPrBannerSource) + "text \n table\n text text text", Created: time.Unix(3, 0)},
			},
		},
		{
			name: "Test with no comment returned",
		},
		{
			name: "Test with error returned",
			err:  errors.New("error"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Test with comment returned
			client.EXPECT().ListPullRequestComments(context.Background(), "owner", "repo", 17).Return(tc.commentsOnPR, tc.err)
			client.EXPECT().DeletePullRequestComment(context.Background(), "owner", "repo", 17, 20).Return(nil).AnyTimes()
			err := utils.DeleteExistingPullRequestComments(repository, client)
			if tc.err == nil {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestDeletePreviousPullRequestReviewMessages(t *testing.T) {
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

	testCases := []struct {
		name         string
		commentsOnPR []vcsclient.CommentInfo
		err          error
	}{
		{
			name: "Test with comment returned",
			commentsOnPR: []vcsclient.CommentInfo{
				{ID: 20, Content: outputwriter.MarkdownComment(outputwriter.ReviewCommentId) + "text \n table\n text text text", Created: time.Unix(3, 0)},
			},
		},
		{
			name: "Test with no comment returned",
		},
		{
			name: "Test with error returned",
			err:  errors.New("error"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Test with comment returned
			client.EXPECT().ListPullRequestReviewComments(context.Background(), "", "", 17).Return(tc.commentsOnPR, tc.err)
			client.EXPECT().DeletePullRequestReviewComments(context.Background(), "", "", 17, tc.commentsOnPR).Return(nil).AnyTimes()
			err := utils.DeleteExistingPullRequestReviewComments(repository, 17, client)
			if tc.err == nil {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestAggregateScanResults(t *testing.T) {
	scanResult1 := services.ScanResponse{
		Violations:      []services.Violation{{IssueId: "Violation 1"}},
		Vulnerabilities: []services.Vulnerability{{IssueId: "Vulnerability 1"}},
		Licenses:        []services.License{{Name: "License 1"}},
	}

	scanResult2 := services.ScanResponse{
		Violations:      []services.Violation{{IssueId: "Violation 2"}},
		Vulnerabilities: []services.Vulnerability{{IssueId: "Vulnerability 2"}},
		Licenses:        []services.License{{Name: "License 2"}},
	}

	aggregateResult := aggregateScanResults([]services.ScanResponse{scanResult1, scanResult2})
	expectedResult := services.ScanResponse{
		Violations: []services.Violation{
			{IssueId: "Violation 1"},
			{IssueId: "Violation 2"},
		},
		Vulnerabilities: []services.Vulnerability{
			{IssueId: "Vulnerability 1"},
			{IssueId: "Vulnerability 2"},
		},
		Licenses: []services.License{
			{Name: "License 1"},
			{Name: "License 2"},
		},
	}

	assert.Equal(t, expectedResult, aggregateResult)
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

type TestResult struct {
	Sca     int
	Iac     int
	Secrets int
	Sast    int
}

func TestAuditDiffInPullRequest(t *testing.T) {
	tests := []struct {
		testName       string
		projectName    string
		configPath     string
		expectedIssues TestResult
	}{
		{
			testName:    "Project with Jas issues (issues added removed and not changed)",
			projectName: "jas-diff-proj",
			configPath:  testJasProjConfigPath,
			// source: vcsclient.BranchInfo{Owner: "jfrog", Repository:"jas-diff-proj", Name: testSourceBranchName},
			// target: vcsclient.BranchInfo{Owner: "jfrog", Repository:"jas-diff-proj", Name: testTargetBranchName},
			expectedIssues: TestResult{
				Sca:  1,
				Sast: 1,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.testName, func(t *testing.T) {
			repoConfig, client, cleanUpTest := preparePullRequestTest(t, test.projectName, test.configPath)
			defer cleanUpTest()

			assert.Len(t, repoConfig, 1)

			issuesCollection, _, err := auditPullRequestAndReport(&repoConfig[0], client)
			assert.NoError(t, err)
			assert.NotNil(t, issuesCollection)
			assert.Len(t, issuesCollection.IacVulnerabilities, test.expectedIssues.Iac)
			assert.Len(t, issuesCollection.SecretsVulnerabilities, test.expectedIssues.Secrets)
			assert.Len(t, issuesCollection.SastVulnerabilities, test.expectedIssues.Sast)
			assert.Len(t, issuesCollection.ScaVulnerabilities, test.expectedIssues.Sca)
		})
	}
}

func preparePullRequestTest(t *testing.T, projectName, configPath string) (utils.RepoAggregator, vcsclient.VcsClient, func()) {
	params, restoreEnv := utils.VerifyEnv(t)

	xrayVersion, xscVersion, err := xsc.GetJfrogServicesVersion(&params)
	assert.NoError(t, err)

	// Create mock GitLab server
	owner := "jfrog"
	gitServerParams := GitServerParams{
		RepoOwner: owner,
		RepoName:  projectName,
		prDetails: vcsclient.PullRequestInfo{ID: int64(1),
			Source: vcsclient.BranchInfo{Name: testSourceBranchName, Repository: projectName, Owner: owner},
			Target: vcsclient.BranchInfo{Name: testTargetBranchName, Repository: projectName, Owner: owner},
		},
	}
	server := httptest.NewServer(createGitLabHandler(t, gitServerParams))

	testDir, cleanUp := utils.CopyTestdataProjectsToTemp(t, "scanpullrequest")
	configAggregator, client := prepareConfigAndClient(t, xrayVersion, xscVersion, configPath, server, params, gitServerParams)

	// Renames test git folder to .git
	currentDir := filepath.Join(testDir, projectName)
	restoreDir, err := utils.Chdir(currentDir)
	assert.NoError(t, err)

	return configAggregator, client, func() {
		assert.NoError(t, restoreDir())
		assert.NoError(t, fileutils.RemoveTempDir(currentDir))
		cleanUp()
		server.Close()
		restoreEnv()
	}
}

type GitServerParams struct {
	RepoOwner string
	RepoName  string
	prDetails vcsclient.PullRequestInfo
}

// Create HTTP handler to mock GitLab server
func createGitLabHandler(t *testing.T, params GitServerParams) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		repoInfo := params.RepoOwner + "%2F" + params.RepoName
		switch {
		// Return 200 on ping
		case r.RequestURI == "/api/v4/":
			w.WriteHeader(http.StatusOK)
		// Mimic get pull request by ID
		case r.RequestURI == fmt.Sprintf("/api/v4/projects/%s/merge_requests/%d", repoInfo, params.prDetails.ID):
			w.WriteHeader(http.StatusOK)
			// expectedResponse, err := os.ReadFile(filepath.Join("..", "expectedPullRequestDetailsResponse.json"))
			// assert.NoError(t, err)
			_, err := w.Write([]byte(fmt.Sprintf(`{ "id": %d, "iid": 133, "project_id": 15513260, "title": "Dummy pull request", "description": "this is pr description", "state": "opened", "target_branch": "%s", "source_branch": "%s", "author": {"username": "testuser"}}`, params.prDetails.ID, params.prDetails.Target.Name, params.prDetails.Source.Name)))
			assert.NoError(t, err)
		// Mimic download specific branch to scan
		case r.RequestURI == fmt.Sprintf("/api/v4/projects/%s/repository/archive.tar.gz?sha=%s", repoInfo, params.prDetails.Source.Name):
			w.WriteHeader(http.StatusOK)
			repoFile, err := os.ReadFile(filepath.Join("..", params.RepoName, "sourceBranch.gz"))
			assert.NoError(t, err)
			_, err = w.Write(repoFile)
			assert.NoError(t, err)
		// Download repository mock
		case r.RequestURI == fmt.Sprintf("/api/v4/projects/%s/repository/archive.tar.gz?sha=%s", repoInfo, params.prDetails.Target.Name):
			w.WriteHeader(http.StatusOK)
			repoFile, err := os.ReadFile(filepath.Join("..", params.RepoName, "targetBranch.gz"))
			assert.NoError(t, err)
			_, err = w.Write(repoFile)
			assert.NoError(t, err)
			return
		// clean-test-proj should not include any vulnerabilities so assertion is not needed.
		case r.RequestURI == fmt.Sprintf("/api/v4/projects/%s/merge_requests/133/notes", repoInfo) && r.Method == http.MethodPost:
			w.WriteHeader(http.StatusOK)
			_, err := w.Write([]byte("{}"))
			assert.NoError(t, err)
			return
		case r.RequestURI == fmt.Sprintf("/api/v4/projects/%s/merge_requests/133/notes", repoInfo) && r.Method == http.MethodGet:
			w.WriteHeader(http.StatusOK)
			comments, err := os.ReadFile(filepath.Join("..", "commits.json"))
			assert.NoError(t, err)
			_, err = w.Write(comments)
			assert.NoError(t, err)
		// Return 200 when using the REST that creates the comment
		case r.RequestURI == fmt.Sprintf("/api/v4/projects/%s/merge_requests/133/notes", repoInfo) && r.Method == http.MethodPost:
			buf := new(bytes.Buffer)
			_, err := buf.ReadFrom(r.Body)
			assert.NoError(t, err)
			assert.NotEmpty(t, buf.String())

			var expectedResponse []byte
			if strings.Contains(params.RepoName, "multi-dir") {
				expectedResponse = outputwriter.GetJsonBodyOutputFromFile(t, filepath.Join("..", "expected_response_multi_dir.md"))
			} else {
				expectedResponse = outputwriter.GetJsonBodyOutputFromFile(t, filepath.Join("..", "expected_response.md"))
			}
			assert.NoError(t, err)
			assert.JSONEq(t, string(expectedResponse), buf.String())

			w.WriteHeader(http.StatusOK)
			_, err = w.Write([]byte("{}"))
			assert.NoError(t, err)
		case r.RequestURI == fmt.Sprintf("/api/v4/projects/%s/merge_requests/133/notes", repoInfo) && r.Method == http.MethodGet:
			w.WriteHeader(http.StatusOK)
			comments, err := os.ReadFile(filepath.Join("..", "commits.json"))
			assert.NoError(t, err)
			_, err = w.Write(comments)
			assert.NoError(t, err)
		case r.RequestURI == fmt.Sprintf("/api/v4/projects/%s", repoInfo):
			jsonResponse := `{"id": 3,"visibility": "private","ssh_url_to_repo": "git@example.com:diaspora/diaspora-project-site.git","http_url_to_repo": "https://example.com/diaspora/diaspora-project-site.git"}`
			_, err := w.Write([]byte(jsonResponse))
			assert.NoError(t, err)
		case r.RequestURI == fmt.Sprintf("/api/v4/projects/%s/merge_requests/133/discussions", repoInfo):
			discussions, err := os.ReadFile(filepath.Join("..", "list_merge_request_discussion_items.json"))
			assert.NoError(t, err)
			_, err = w.Write(discussions)
			assert.NoError(t, err)
		}
	}
}
