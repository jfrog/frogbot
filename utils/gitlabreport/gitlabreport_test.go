package gitlabreport

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalizeSeverity(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"critical", "Critical"},
		{"CRITICAL", "Critical"},
		{"high", "High"},
		{"medium", "Medium"},
		{"moderate", "Medium"},
		{"low", "Low"},
		{"info", "Info"},
		{"informational", "Info"},
		{"", "Unknown"},
		{"weird", "Unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.expected, normalizeSeverity(tt.input))
		})
	}
}

func TestManifestFileForTechnology(t *testing.T) {
	tests := []struct {
		tech     techutils.Technology
		expected string
	}{
		{techutils.Npm, "package-lock.json"},
		{techutils.Yarn, "package-lock.json"},
		{techutils.Go, "go.sum"},
		{techutils.Pip, "requirements.txt"},
		{techutils.Pipenv, "requirements.txt"},
		{techutils.Maven, "pom.xml"},
		{techutils.Nuget, "packages.config"},
		{techutils.Technology("unknown"), "manifest"},
	}
	for _, tt := range tests {
		t.Run(string(tt.tech), func(t *testing.T) {
			assert.Equal(t, tt.expected, manifestFileForTechnology(tt.tech))
		})
	}
}

func TestFormatGitLabTime(t *testing.T) {
	loc := time.FixedZone("CST", -6*3600)
	ts := time.Date(2024, 6, 1, 12, 30, 45, 0, loc)
	assert.Equal(t, "2024-06-01T18:30:45", formatGitLabTime(ts))
}

func TestDeterministicVulnID(t *testing.T) {
	id1 := deterministicVulnID("pkg", "1.0.0", "XRAY-1", []formats.CveRow{{Id: "CVE-2024-1"}})
	id2 := deterministicVulnID("pkg", "1.0.0", "XRAY-1", []formats.CveRow{{Id: "CVE-2024-1"}})
	id3 := deterministicVulnID("pkg", "1.0.0", "XRAY-1", []formats.CveRow{{Id: "CVE-2024-2"}})
	assert.Equal(t, id1, id2)
	assert.NotEqual(t, id1, id3)
	assert.Regexp(t, `^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`, id1)
}

func TestMakeAnalyzerScanner(t *testing.T) {
	tests := []struct {
		version string
		wantVer string
	}{
		{"1.2.3", "1.2.3"},
		{"", "0.0.0"},
	}
	for _, tt := range tests {
		t.Run(tt.wantVer, func(t *testing.T) {
			got := makeAnalyzerScanner(tt.version)
			assert.Equal(t, frogbotAnalyzerID, got.ID)
			assert.Equal(t, frogbotAnalyzerName, got.Name)
			assert.Equal(t, tt.wantVer, got.Version)
			assert.Equal(t, frogbotVendorName, got.Vendor.Name)
		})
	}
}

func TestVulnerabilityToReport(t *testing.T) {
	tests := []struct {
		name string
		row  formats.VulnerabilityOrViolationRow
		// spot checks
		wantName        string
		wantSeverity    string
		wantManifest    string
		wantSolution    string
		identifierTypes []string
	}{
		{
			name: "CVE name and link",
			row: formats.VulnerabilityOrViolationRow{
				IssueId: "XRAY-99",
				ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
					ImpactedDependencyName:    "lodash",
					ImpactedDependencyVersion: "4.17.20",
					SeverityDetails:           formats.SeverityDetails{Severity: "high"},
				},
				Cves:          []formats.CveRow{{Id: "CVE-2021-1234"}},
				Summary:       "Test summary",
				Technology:    techutils.Npm,
				FixedVersions: []string{"4.17.21"},
			},
			wantName:        "CVE-2021-1234 (Not Covered)",
			wantSeverity:    "High",
			wantManifest:    "package-lock.json",
			wantSolution:    "Upgrade lodash to version 4.17.21 or later.",
			identifierTypes: []string{"cve", "xray"},
		},
		{
			name: "contextual analysis in reachable detail",
			row: formats.VulnerabilityOrViolationRow{
				IssueId: "XRAY-99",
				ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
					ImpactedDependencyName:    "pkg",
					ImpactedDependencyVersion: "1.0.0",
					SeverityDetails:           formats.SeverityDetails{Severity: "low"},
				},
				Cves: []formats.CveRow{
					{Id: "CVE-2023-1", Applicability: &formats.Applicability{Status: jasutils.Applicable.String()}},
					{Id: "CVE-2023-2", Applicability: &formats.Applicability{Status: jasutils.NotApplicable.String()}},
				},
				Summary:    "Details here",
				Technology: techutils.Npm,
			},
			wantName:        "CVE-2023-1 (Applicable)",
			wantSeverity:    "Low",
			wantManifest:    "package-lock.json",
			identifierTypes: []string{"cve", "cve", "xray"},
		},
		{
			name: "non-CVE issue id adds xray identifier",
			row: formats.VulnerabilityOrViolationRow{
				IssueId: "XRAY-100",
				ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
					ImpactedDependencyName:    "foo",
					ImpactedDependencyVersion: "1.0.0",
					SeverityDetails:           formats.SeverityDetails{Severity: "low"},
				},
				Technology: techutils.Go,
			},
			wantName:        "XRAY-100 (Not Covered)",
			wantSeverity:    "Low",
			wantManifest:    "go.sum",
			identifierTypes: []string{"xray"},
		},
		{
			name: "fallback identifier when no CVE or issue id",
			row: formats.VulnerabilityOrViolationRow{
				ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
					ImpactedDependencyName:    "orphan",
					ImpactedDependencyVersion: "0.0.1",
				},
				Technology: techutils.Maven,
			},
			wantName:        "",
			wantSeverity:    "Unknown",
			wantManifest:    "pom.xml",
			identifierTypes: []string{"other"},
		},
		{
			name: "CVE from issueId when cves slice empty",
			row: formats.VulnerabilityOrViolationRow{
				IssueId: "CVE-2020-9999",
				ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
					ImpactedDependencyName:    "dep",
					ImpactedDependencyVersion: "1.0.0",
					SeverityDetails:           formats.SeverityDetails{Severity: "high"},
				},
				Cves:       nil,
				Summary:    "from issue id only",
				Technology: techutils.Maven,
			},
			wantName:        "CVE-2020-9999 (Not Covered)",
			wantSeverity:    "High",
			wantManifest:    "pom.xml",
			identifierTypes: []string{"cve"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := vulnerabilityToReport(&tt.row)
			assert.Equal(t, tt.wantName, got.Name)
			assert.Equal(t, tt.wantSeverity, got.Severity)
			assert.Equal(t, tt.wantManifest, got.Location.File)
			if tt.name == "CVE name and link" {
				assert.Equal(t, "Test summary", got.Description)
				require.NotNil(t, got.Details)
				assert.Equal(t, "named-list", got.Details.Type)
				item := got.Details.Items["reachable"]
				assert.Equal(t, "Reachable", item.Name)
				assert.Equal(t, "text", item.Type)
				assert.Equal(t, "CVE-2021-1234 (Not Covered).", item.Value)
			}
			if tt.name == "contextual analysis in reachable detail" {
				assert.Equal(t, "Details here", got.Description)
				require.NotNil(t, got.Details)
				item := got.Details.Items["reachable"]
				assert.Equal(t, "CVE-2023-1 (Applicable). CVE-2023-2 (Not Applicable).", item.Value)
			}
			if tt.name == "non-CVE issue id adds xray identifier" {
				assert.Empty(t, got.Description)
				require.NotNil(t, got.Details)
				assert.Equal(t, jasutils.NotCovered.String(), got.Details.Items["reachable"].Value)
			}
			if tt.name == "CVE from issueId when cves slice empty" {
				assert.Equal(t, "from issue id only", got.Description)
				require.NotNil(t, got.Details)
				assert.Equal(t, jasutils.NotCovered.String(), got.Details.Items["reachable"].Value)
			}
			if tt.name == "fallback identifier when no CVE or issue id" {
				assert.Nil(t, got.Details)
			}
			if tt.wantSolution != "" {
				assert.Equal(t, tt.wantSolution, got.Solution)
			}
			require.Len(t, got.Identifiers, len(tt.identifierTypes))
			for i, wantType := range tt.identifierTypes {
				assert.Equal(t, wantType, got.Identifiers[i].Type)
				assert.NotEmpty(t, got.Identifiers[i].Value, "identifier value must be set for GitLab vulnerability report")
				assert.Equal(t, got.Identifiers[i].Value, got.Identifiers[i].Name, "identifier name should match value for GitLab UI")
			}
		})
	}
}

func TestGitLabReportJSON_identifierValueIsCVE(t *testing.T) {
	row := formats.VulnerabilityOrViolationRow{
		IssueId: "XRAY-1",
		ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
			ImpactedDependencyName:    "lib",
			ImpactedDependencyVersion: "1.0.0",
			SeverityDetails:           formats.SeverityDetails{Severity: "high"},
		},
		Cves:       []formats.CveRow{{Id: "CVE-2021-9999"}},
		Technology: techutils.Npm,
	}
	rep := vulnerabilityToReport(&row)
	raw, err := json.Marshal(rep)
	require.NoError(t, err)
	assert.Contains(t, string(raw), `"type":"cve"`)
	assert.Contains(t, string(raw), `"name":"CVE-2021-9999"`)
	assert.Contains(t, string(raw), `"value":"CVE-2021-9999"`)
	assert.Contains(t, string(raw), `"details":`)
	assert.Contains(t, string(raw), `"type":"named-list"`)
	assert.Contains(t, string(raw), `"name":"Reachable"`)
	assert.Contains(t, string(raw), `"value":"CVE-2021-9999 (Not Covered)."`)
}

func scanResultsWithSbomOnly() *results.SecurityCommandResults {
	components := []cyclonedx.Component{
		{BOMRef: "c1", Type: cyclonedx.ComponentTypeLibrary, Name: "express", Version: "4.18.2"},
	}
	bom := cyclonedx.NewBOM()
	bom.Components = &components
	return &results.SecurityCommandResults{
		ResultsMetaData: results.ResultsMetaData{StartTime: time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC)},
		Targets: []*results.TargetResults{{
			ScanTarget: results.ScanTarget{Target: "t1"},
			ScaResults: &results.ScaScanResults{Sbom: bom},
		}},
	}
}

func TestConvertToGitLabDependencyScanningReport(t *testing.T) {
	start := time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC)
	end := time.Date(2024, 1, 15, 10, 35, 0, 0, time.UTC)
	version := "9.9.9"

	t.Run("nil scan results", func(t *testing.T) {
		report, err := ConvertToGitLabDependencyScanningReport(nil, start, end, version)
		require.NoError(t, err)
		require.NotNil(t, report)
		assert.Equal(t, "success", report.Scan.Status)
		assert.Empty(t, report.Vulnerabilities)
		assert.Equal(t, gitLabReportSchemaVersion, report.Version)
		assert.Equal(t, gitLabReportSchemaURL, report.Schema)
		assert.Equal(t, "dependency_scanning", report.Scan.Type)
		assert.Equal(t, formatGitLabTime(start), report.Scan.StartTime)
		assert.Equal(t, formatGitLabTime(end), report.Scan.EndTime)
		assert.Equal(t, version, report.Scan.Analyzer.Version)
	})

	t.Run("scan with SBOM only", func(t *testing.T) {
		report, err := ConvertToGitLabDependencyScanningReport(scanResultsWithSbomOnly(), start, end, version)
		require.NoError(t, err)
		assert.Equal(t, "success", report.Scan.Status)
	})

	t.Run("failure status when GetErrors returns error", func(t *testing.T) {
		sr := scanResultsWithSbomOnly()
		sr.GeneralError = errors.New("scanner failed")
		report, err := ConvertToGitLabDependencyScanningReport(sr, start, end, version)
		require.NoError(t, err)
		assert.Equal(t, "failure", report.Scan.Status)
	})
}

func TestSortVulnerabilityRowsForGitLab(t *testing.T) {
	rows := []formats.VulnerabilityOrViolationRow{
		{
			IssueId: "b-low-na",
			ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
				ImpactedDependencyName: "p1", ImpactedDependencyVersion: "1",
				SeverityDetails: formats.SeverityDetails{Severity: "low"},
			},
			Cves: []formats.CveRow{{Id: "CVE-B", Applicability: &formats.Applicability{Status: jasutils.NotApplicable.String()}}},
		},
		{
			IssueId: "a-high-app",
			ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
				ImpactedDependencyName: "p2", ImpactedDependencyVersion: "1",
				SeverityDetails: formats.SeverityDetails{Severity: "high"},
			},
			Cves: []formats.CveRow{{Id: "CVE-A", Applicability: &formats.Applicability{Status: jasutils.Applicable.String()}}},
		},
		{
			IssueId: "c-low-app",
			ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
				ImpactedDependencyName: "p3", ImpactedDependencyVersion: "1",
				SeverityDetails: formats.SeverityDetails{Severity: "low"},
			},
			Cves: []formats.CveRow{{Id: "CVE-C", Applicability: &formats.Applicability{Status: jasutils.Applicable.String()}}},
		},
	}
	sortVulnerabilityRowsForGitLab(rows)
	assert.Equal(t, "a-high-app", rows[0].IssueId)
	assert.Equal(t, "c-low-app", rows[1].IssueId)
	assert.Equal(t, "b-low-na", rows[2].IssueId)
}

func TestWriteDependencyScanningReport(t *testing.T) {
	t.Run("empty output dir", func(t *testing.T) {
		err := WriteDependencyScanningReport("", &DependencyScanningReport{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "output directory is required")
	})

	t.Run("writes JSON file", func(t *testing.T) {
		dir := t.TempDir()
		report := &DependencyScanningReport{
			Version: gitLabReportSchemaVersion,
			Schema:  gitLabReportSchemaURL,
			Scan: ScanReport{
				Status:    "success",
				Type:      "dependency_scanning",
				StartTime: "2024-01-01T00:00:00",
				EndTime:   "2024-01-01T00:01:00",
				Analyzer:  makeAnalyzerScanner("1.0.0"),
				Scanner:   makeAnalyzerScanner("1.0.0"),
			},
			Vulnerabilities: []VulnerabilityReport{},
		}
		require.NoError(t, WriteDependencyScanningReport(dir, report))
		path := filepath.Join(dir, "gl-dependency-scanning-report.json")
		data, err := os.ReadFile(path)
		require.NoError(t, err)
		var decoded DependencyScanningReport
		require.NoError(t, json.Unmarshal(data, &decoded))
		assert.Equal(t, gitLabReportSchemaVersion, decoded.Version)
		assert.Equal(t, "success", decoded.Scan.Status)
	})
}
