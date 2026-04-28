package gitlabreport

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
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
	ID          string            `json:"id"`
	Name        string            `json:"name,omitempty"`
	Description string            `json:"description,omitempty"`
	Severity    string            `json:"severity,omitempty"` // Info, Unknown, Low, Medium, High, Critical
	Solution    string            `json:"solution,omitempty"`
	Identifiers []Identifier      `json:"identifiers"`
	Location    Location          `json:"location"`
	Links       []Link            `json:"links,omitempty"`
	Details     *DetailsNamedList `json:"details,omitempty"` // e.g. Reachable (contextual analysis); see dependency-scanning schema `details`
}

// DetailsNamedList is GitLab's named-list detail block (security report schema).
type DetailsNamedList struct {
	Type  string                         `json:"type"` // must be "named-list"
	Items map[string]DetailNamedListItem `json:"items"`
}

// DetailNamedListItem merges named_field (name) with a detail payload (e.g. type "text" + value).
type DetailNamedListItem struct {
	Name  string `json:"name"`
	Type  string `json:"type"` // "text"
	Value string `json:"value"`
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

	unique := make([]formats.VulnerabilityOrViolationRow, 0, len(vulns))
	seen := make(map[string]struct{})
	for i := range vulns {
		v := vulns[i]
		key := v.ImpactedDependencyName + "|" + v.ImpactedDependencyVersion + "|" + v.IssueId
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		unique = append(unique, v)
	}
	sortVulnerabilityRowsForGitLab(unique)

	reports := make([]VulnerabilityReport, 0, len(unique))
	for i := range unique {
		report := vulnerabilityToReport(&unique[i])
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
	// GitLab's vulnerability list "Description" column is built from the finding title (name) and
	// manifest path — it does not show the JSON description body in that column. Include
	// contextual analysis in name so it appears in the list; description holds summary only.
	name := buildVulnerabilityNameWithContextualAnalysis(v)
	desc := strings.TrimSpace(getSummary(v))
	reach := contextualAnalysisReachabilityText(v)
	var details *DetailsNamedList
	if strings.TrimSpace(reach) != "" {
		details = buildReachabilityNamedList(reach)
	}
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
		Details:     details,
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
		hexStr += strings.Repeat("0", 32-len(hexStr))
	}
	return hexStr[0:8] + "-" + hexStr[8:12] + "-" + hexStr[12:16] + "-" + hexStr[16:20] + "-" + hexStr[20:32]
}

func buildIdentifiers(v *formats.VulnerabilityOrViolationRow) []Identifier {
	var ids []Identifier
	for _, cve := range v.Cves {
		if cve.Id != "" {
			ids = append(ids, Identifier{
				Type:  "cve",
				Name:  cve.Id,
				Value: cve.Id,
				URL:   "https://nvd.nist.gov/vuln/detail/" + cve.Id,
			})
		}
	}
	if v.IssueId != "" && !strings.HasPrefix(strings.ToUpper(v.IssueId), "CVE-") {
		ids = append(ids, Identifier{
			Type:  "xray",
			Name:  v.IssueId,
			Value: v.IssueId,
		})
	}
	if len(ids) == 0 {
		issue := strings.TrimSpace(v.IssueId)
		if issue != "" && strings.HasPrefix(strings.ToUpper(issue), "CVE-") {
			ids = append(ids, Identifier{
				Type:  "cve",
				Name:  issue,
				Value: issue,
				URL:   "https://nvd.nist.gov/vuln/detail/" + issue,
			})
		} else {
			fallback := v.ImpactedDependencyName + "@" + v.ImpactedDependencyVersion
			ids = append(ids, Identifier{
				Type:  "other",
				Name:  fallback,
				Value: fallback,
			})
		}
	}
	return appendUniqueCWEIdentifiers(ids, v)
}

// appendUniqueCWEIdentifiers adds GitLab dependency-scanning identifiers with type "cwe" from each
// CVE row's Cwe list (Xray simple JSON). GitLab aggregates these for dashboards such as "Top 10 CWEs".
func appendUniqueCWEIdentifiers(ids []Identifier, v *formats.VulnerabilityOrViolationRow) []Identifier {
	seen := make(map[string]struct{})
	for _, id := range ids {
		if id.Type == "cwe" {
			seen[strings.ToUpper(id.Value)] = struct{}{}
		}
	}
	for _, cve := range v.Cves {
		for _, raw := range cve.Cwe {
			canon := normalizeCweID(raw)
			if canon == "" {
				continue
			}
			key := strings.ToUpper(canon)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			id := Identifier{
				Type:  "cwe",
				Name:  canon,
				Value: canon,
			}
			if u := cweMitreDefinitionsURL(canon); u != "" {
				id.URL = u
			}
			ids = append(ids, id)
		}
	}
	return ids
}

func normalizeCweID(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	u := strings.ToUpper(raw)
	if strings.HasPrefix(u, "CWE-") {
		n := strings.TrimPrefix(u, "CWE-")
		n = strings.TrimSpace(n)
		if cweNumericID(n) != "" {
			return "CWE-" + cweNumericID(n)
		}
		return ""
	}
	if cweNumericID(u) != "" {
		return "CWE-" + cweNumericID(u)
	}
	return ""
}

// cweNumericID returns digits-only CWE id, or empty if invalid.
func cweNumericID(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return ""
		}
	}
	return s
}

func cweMitreDefinitionsURL(cweCanon string) string {
	n := cweNumericID(strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(cweCanon)), "CWE-"))
	if n == "" {
		return ""
	}
	return "https://cwe.mitre.org/data/definitions/" + n + ".html"
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

// buildVulnerabilityNameWithContextualAnalysis sets the GitLab finding title to "CVE-ID (status)" using
// aggregated contextual analysis for the row (same aggregation as Frogbot PR comments).
func buildVulnerabilityNameWithContextualAnalysis(v *formats.VulnerabilityOrViolationRow) string {
	base := v.IssueId
	if len(v.Cves) > 0 && v.Cves[0].Id != "" {
		base = v.Cves[0].Id
	}
	if base == "" {
		return ""
	}
	return fmt.Sprintf("%s (%s)", base, aggregatedContextualAnalysisDisplay(v))
}

// aggregatedContextualAnalysisDisplay returns a human-readable status; NotScanned maps to "Not Covered".
func aggregatedContextualAnalysisDisplay(v *formats.VulnerabilityOrViolationRow) string {
	st := rowFinalApplicabilityStatus(v)
	if st == jasutils.NotScanned || st.String() == "" {
		return jasutils.NotCovered.String()
	}
	return st.String()
}

// contextualAnalysisReachabilityText returns contextual analysis (JAS applicability) for the
// Reachable detail field: per-CVE lines when available, otherwise the row-level status when the
// finding has a titled vulnerability.
func contextualAnalysisReachabilityText(v *formats.VulnerabilityOrViolationRow) string {
	if s := contextualAnalysisDescriptionPrefix(v); strings.TrimSpace(s) != "" {
		return strings.TrimSpace(s)
	}
	if buildVulnerabilityNameWithContextualAnalysis(v) == "" {
		return ""
	}
	return aggregatedContextualAnalysisDisplay(v)
}

func buildReachabilityNamedList(reachabilityText string) *DetailsNamedList {
	return &DetailsNamedList{
		Type: "named-list",
		Items: map[string]DetailNamedListItem{
			"reachable": {
				Name:  "Reachable",
				Type:  "text",
				Value: reachabilityText,
			},
		},
	}
}

// contextualAnalysisDescriptionPrefix builds "CVE-2024-1 (Applicable). CVE-2024-2 (Not Applicable)." per CVE row.
// When a CVE has no applicability assessment, status is "Not Covered".
func contextualAnalysisDescriptionPrefix(v *formats.VulnerabilityOrViolationRow) string {
	var b strings.Builder
	for _, cve := range v.Cves {
		if cve.Id == "" {
			continue
		}
		status := jasutils.NotCovered.String()
		if cve.Applicability != nil && cve.Applicability.Status != "" {
			status = cve.Applicability.Status
		}
		if b.Len() > 0 {
			b.WriteString(" ")
		}
		b.WriteString(cve.Id)
		b.WriteString(" (")
		b.WriteString(status)
		b.WriteString(").")
	}
	return b.String()
}

func sortVulnerabilityRowsForGitLab(vulns []formats.VulnerabilityOrViolationRow) {
	sort.SliceStable(vulns, func(i, j int) bool {
		si := normalizeSeverity(getSeverity(&vulns[i]))
		sj := normalizeSeverity(getSeverity(&vulns[j]))
		ri, rj := severitySortRank(si), severitySortRank(sj)
		if ri != rj {
			return ri < rj
		}
		ai := applicabilitySortRank(rowFinalApplicabilityStatus(&vulns[i]))
		aj := applicabilitySortRank(rowFinalApplicabilityStatus(&vulns[j]))
		if ai != aj {
			return ai < aj
		}
		return vulns[i].IssueId < vulns[j].IssueId
	})
}

func severitySortRank(normalized string) int {
	switch normalized {
	case "Critical":
		return 0
	case "High":
		return 1
	case "Medium":
		return 2
	case "Low":
		return 3
	case "Info":
		return 4
	default:
		return 5 // Unknown
	}
}

// rowFinalApplicabilityStatus aggregates per-CVE applicability like Frogbot PR comments.
func rowFinalApplicabilityStatus(v *formats.VulnerabilityOrViolationRow) jasutils.ApplicabilityStatus {
	var statuses []jasutils.ApplicabilityStatus
	for _, cve := range v.Cves {
		if cve.Applicability != nil && cve.Applicability.Status != "" {
			statuses = append(statuses, jasutils.ConvertToApplicabilityStatus(cve.Applicability.Status))
		}
	}
	return results.GetFinalApplicabilityStatus(len(statuses) > 0, statuses)
}

// applicabilitySortRank orders rows within the same severity: Applicable first, Not Applicable last.
func applicabilitySortRank(status jasutils.ApplicabilityStatus) int {
	switch status {
	case jasutils.Applicable:
		return 0
	case jasutils.ApplicabilityUndetermined:
		return 1
	case jasutils.MissingContext:
		return 2
	case jasutils.NotCovered:
		return 3
	case jasutils.NotScanned:
		return 4
	case jasutils.NotApplicable:
		return 5
	default:
		return 6
	}
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
