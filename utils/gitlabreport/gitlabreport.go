package gitlabreport

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/results/conversion"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
)

const (
	gitLabReportSchemaVersion = "15.2.4"
	gitLabReportSchemaURL     = "https://gitlab.com/gitlab-org/security-products/security-report-schemas/-/raw/master/dist/dependency-scanning-report-format.json"
	frogbotAnalyzerID         = "frogbot-dependency-scanning"
	frogbotAnalyzerName       = "JFrog Frogbot"
	frogbotVendorName         = "JFrog"
)

type DependencyScanningReport struct {
	Scan            ScanReport            `json:"scan"`
	Schema          string                `json:"schema,omitempty"`
	Version         string                `json:"version"`
	Vulnerabilities []VulnerabilityReport `json:"vulnerabilities"`
}

type ScanReport struct {
	Analyzer  AnalyzerScanner `json:"analyzer"`
	Scanner   AnalyzerScanner `json:"scanner"`
	StartTime string          `json:"start_time"` // ISO8601 UTC yyyy-mm-ddThh:mm:ss
	EndTime   string          `json:"end_time"`
	Status    string          `json:"status"` // "success" or "failure"
	Type      string          `json:"type"`   // "dependency_scanning"
}

type AnalyzerScanner struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Vendor  Vendor `json:"vendor"`
	URL     string `json:"url,omitempty"`
}

type Vendor struct {
	Name string `json:"name"`
}

type VulnerabilityReport struct {
	ID          string       `json:"id"`
	Name        string       `json:"name,omitempty"`
	Description string       `json:"description,omitempty"`
	Severity    string       `json:"severity,omitempty"` // Info, Unknown, Low, Medium, High, Critical
	Solution    string       `json:"solution,omitempty"`
	Identifiers []Identifier `json:"identifiers"`
	Location    Location     `json:"location"`
	Links       []Link       `json:"links,omitempty"`
}

type Identifier struct {
	Type  string `json:"type"`
	Name  string `json:"name"`
	Value string `json:"value"`
	URL   string `json:"url,omitempty"`
}

type Location struct {
	File       string     `json:"file"`
	Dependency Dependency `json:"dependency"`
}

type Dependency struct {
	Package Package `json:"package"`
	Version string  `json:"version"`
	Direct  *bool   `json:"direct,omitempty"`
}

type Package struct {
	Name string `json:"name"`
}

type Link struct {
	Name string `json:"name,omitempty"`
	URL  string `json:"url"`
}

func ConvertToGitLabDependencyScanningReport(scanResults *results.SecurityCommandResults, startTime, endTime time.Time, frogbotVersion string) (*DependencyScanningReport, error) {
	if scanResults == nil {
		return &DependencyScanningReport{
			Scan: ScanReport{
				Analyzer:  makeAnalyzerScanner(frogbotVersion),
				Scanner:   makeAnalyzerScanner(frogbotVersion),
				StartTime: formatGitLabTime(startTime),
				EndTime:   formatGitLabTime(endTime),
				Status:    "success",
				Type:      "dependency_scanning",
			},
			Version:         gitLabReportSchemaVersion,
			Schema:          gitLabReportSchemaURL,
			Vulnerabilities: []VulnerabilityReport{},
		}, nil
	}

	convertor := conversion.NewCommandResultsConvertor(conversion.ResultConvertParams{
		IncludeVulnerabilities: scanResults.IncludesVulnerabilities(),
		HasViolationContext:    scanResults.HasViolationContext(),
	})
	simpleJSON, err := convertor.ConvertToSimpleJson(scanResults)
	if err != nil {
		return nil, fmt.Errorf("convert to simple json: %w", err)
	}

	var vulns []formats.VulnerabilityOrViolationRow
	vulns = append(vulns, simpleJSON.Vulnerabilities...)
	vulns = append(vulns, simpleJSON.SecurityViolations...)

	reports := make([]VulnerabilityReport, 0, len(vulns))
	seen := make(map[string]struct{})

	for i := range vulns {
		v := &vulns[i]
		key := v.ImpactedDependencyName + "|" + v.ImpactedDependencyVersion + "|" + v.IssueId
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}

		report := vulnerabilityToReport(v)
		reports = append(reports, report)
	}

	status := "success"
	if err = scanResults.GetErrors(); err != nil {
		status = "failure"
	}

	return &DependencyScanningReport{
		Scan: ScanReport{
			Analyzer:  makeAnalyzerScanner(frogbotVersion),
			Scanner:   makeAnalyzerScanner(frogbotVersion),
			StartTime: formatGitLabTime(startTime),
			EndTime:   formatGitLabTime(endTime),
			Status:    status,
			Type:      "dependency_scanning",
		},
		Schema:          gitLabReportSchemaURL,
		Version:         gitLabReportSchemaVersion,
		Vulnerabilities: reports,
	}, nil
}

func makeAnalyzerScanner(version string) AnalyzerScanner {
	if version == "" {
		version = "0.0.0"
	}
	return AnalyzerScanner{
		ID:      frogbotAnalyzerID,
		Name:    frogbotAnalyzerName,
		Version: version,
		Vendor:  Vendor{Name: frogbotVendorName},
		URL:     "https://github.com/jfrog/frogbot",
	}
}

func formatGitLabTime(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05")
}

func vulnerabilityToReport(v *formats.VulnerabilityOrViolationRow) VulnerabilityReport {
	id := deterministicVulnID(v.ImpactedDependencyName, v.ImpactedDependencyVersion, v.IssueId, v.Cves)
	identifiers := buildIdentifiers(v)
	location := Location{
		File: manifestFileForTechnology(v.Technology),
		Dependency: Dependency{
			Package: Package{Name: v.ImpactedDependencyName},
			Version: v.ImpactedDependencyVersion,
		},
	}
	severity := normalizeSeverity(getSeverity(v))
	name := v.IssueId
	if len(v.Cves) > 0 {
		name = v.Cves[0].Id
	}
	desc := getSummary(v)
	solution := ""
	if len(v.FixedVersions) > 0 {
		solution = fmt.Sprintf("Upgrade %s to version %s or later.", v.ImpactedDependencyName, v.FixedVersions[0])
	}
	var links []Link
	for _, cve := range v.Cves {
		if cve.Id != "" {
			links = append(links, Link{Name: cve.Id, URL: "https://nvd.nist.gov/vuln/detail/" + cve.Id})
		}
	}
	return VulnerabilityReport{
		ID:          id,
		Name:        name,
		Description: desc,
		Severity:    severity,
		Solution:    solution,
		Identifiers: identifiers,
		Location:    location,
		Links:       links,
	}
}

func deterministicVulnID(pkg, version, issueId string, cves []formats.CveRow) string {
	h := sha256.New()
	h.Write([]byte(pkg))
	h.Write([]byte("|"))
	h.Write([]byte(version))
	h.Write([]byte("|"))
	h.Write([]byte(issueId))
	for _, c := range cves {
		h.Write([]byte(c.Id))
	}
	sum := h.Sum(nil)
	hexStr := hex.EncodeToString(sum)
	// Format as UUID-like 8-4-4-4-12 for compatibility
	if len(hexStr) < 32 {
		hexStr = hexStr + strings.Repeat("0", 32-len(hexStr))
	}
	return hexStr[0:8] + "-" + hexStr[8:12] + "-" + hexStr[12:16] + "-" + hexStr[16:20] + "-" + hexStr[20:32]
}

func buildIdentifiers(v *formats.VulnerabilityOrViolationRow) []Identifier {
	var ids []Identifier
	for _, cve := range v.Cves {
		if cve.Id != "" {
			ids = append(ids, Identifier{
				Type:  "cve",
				Name:  "CVE",
				Value: cve.Id,
				URL:   "https://nvd.nist.gov/vuln/detail/" + cve.Id,
			})
		}
	}
	if v.IssueId != "" && !strings.HasPrefix(strings.ToUpper(v.IssueId), "CVE-") {
		ids = append(ids, Identifier{
			Type:  "xray",
			Name:  "Xray",
			Value: v.IssueId,
		})
	}
	if len(ids) == 0 {
		ids = append(ids, Identifier{
			Type:  "other",
			Name:  "JFrog Xray",
			Value: v.ImpactedDependencyName + "@" + v.ImpactedDependencyVersion,
		})
	}
	return ids
}

func getSeverity(v *formats.VulnerabilityOrViolationRow) string {
	if v.Severity != "" {
		return v.Severity
	}
	if v.ImpactedDependencyDetails.SeverityDetails.Severity != "" {
		return v.ImpactedDependencyDetails.SeverityDetails.Severity
	}
	return ""
}

func getSummary(v *formats.VulnerabilityOrViolationRow) string {
	if v.Summary != "" {
		return v.Summary
	}
	if v.JfrogResearchInformation != nil && v.JfrogResearchInformation.Summary != "" {
		return v.JfrogResearchInformation.Summary
	}
	return ""
}

func normalizeSeverity(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "Critical"
	case "high":
		return "High"
	case "medium", "moderate":
		return "Medium"
	case "low":
		return "Low"
	case "info", "informational":
		return "Info"
	default:
		return "Unknown"
	}
}

func manifestFileForTechnology(tech techutils.Technology) string {
	switch tech {
	case techutils.Npm, techutils.Yarn:
		return "package-lock.json"
	case techutils.Go:
		return "go.sum"
	case techutils.Pip, techutils.Pipenv:
		return "requirements.txt"
	case techutils.Maven:
		return "pom.xml"
	case techutils.Nuget:
		return "packages.config"
	default:
		return "manifest"
	}
}

// WriteDependencyScanningReport writes the GitLab dependency-scanning report to outputDir/gl-dependency-scanning-report.json.
func WriteDependencyScanningReport(outputDir string, report *DependencyScanningReport) error {
	if outputDir == "" {
		return fmt.Errorf("output directory is required")
	}
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}
	path := filepath.Join(outputDir, "gl-dependency-scanning-report.json")
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal report: %w", err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("write report: %w", err)
	}
	log.Info(fmt.Sprintf("GitLab dependency-scanning report written to %s", path))
	return nil
}
