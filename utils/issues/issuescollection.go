package issues

import (
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/severityutils"
)

// Group issues by scan type
type ScansIssuesCollection struct {
	formats.ScanStatus
	results.ResultContext

	LicensesViolations []formats.LicenseViolationRow

	ScaVulnerabilities []formats.VulnerabilityOrViolationRow
	ScaViolations      []formats.VulnerabilityOrViolationRow

	IacVulnerabilities []formats.SourceCodeRow
	IacViolations      []formats.SourceCodeRow

	SecretsVulnerabilities []formats.SourceCodeRow
	SecretsViolations      []formats.SourceCodeRow

	SastViolations      []formats.SourceCodeRow
	SastVulnerabilities []formats.SourceCodeRow
}

// General methods

func (ic *ScansIssuesCollection) Append(issues *ScansIssuesCollection) {
	if issues == nil {
		return
	}
	// Result context should be the same for all collections
	ic.ResultContext = issues.ResultContext
	// Status
	ic.AppendStatus(issues.ScanStatus)
	// Sca
	if len(issues.ScaVulnerabilities) > 0 {
		ic.ScaVulnerabilities = append(ic.ScaVulnerabilities, issues.ScaVulnerabilities...)
	}
	if len(issues.ScaViolations) > 0 {
		ic.ScaViolations = append(ic.ScaViolations, issues.ScaViolations...)
	}
	if len(issues.LicensesViolations) > 0 {
		ic.LicensesViolations = append(ic.LicensesViolations, issues.LicensesViolations...)
	}
	// Secrets
	if len(issues.SecretsVulnerabilities) > 0 {
		ic.SecretsVulnerabilities = append(ic.SecretsVulnerabilities, issues.SecretsVulnerabilities...)
	}
	if len(issues.SecretsViolations) > 0 {
		ic.SecretsViolations = append(ic.SecretsViolations, issues.SecretsViolations...)
	}
	// Sast
	if len(issues.SastVulnerabilities) > 0 {
		ic.SastVulnerabilities = append(ic.SastVulnerabilities, issues.SastVulnerabilities...)
	}
	if len(issues.SastViolations) > 0 {
		ic.SastViolations = append(ic.SastViolations, issues.SastViolations...)
	}
	// Iac
	if len(issues.IacVulnerabilities) > 0 {
		ic.IacVulnerabilities = append(ic.IacVulnerabilities, issues.IacVulnerabilities...)
	}
	if len(issues.IacViolations) > 0 {
		ic.IacViolations = append(ic.IacViolations, issues.IacViolations...)
	}
}

func (ic *ScansIssuesCollection) AppendStatus(scanStatus formats.ScanStatus) {
	if ic.ScaStatusCode == nil || (*ic.ScaStatusCode == 0 && scanStatus.ScaStatusCode != nil) {
		ic.ScaStatusCode = scanStatus.ScaStatusCode
	}
	if ic.IacStatusCode == nil || (*ic.IacStatusCode == 0 && scanStatus.IacStatusCode != nil) {
		ic.IacStatusCode = scanStatus.IacStatusCode
	}
	if ic.SecretsStatusCode == nil || (*ic.SecretsStatusCode == 0 && scanStatus.SecretsStatusCode != nil) {
		ic.SecretsStatusCode = scanStatus.SecretsStatusCode
	}
	if ic.SastStatusCode == nil || (*ic.SastStatusCode == 0 && scanStatus.SastStatusCode != nil) {
		ic.SastStatusCode = scanStatus.SastStatusCode
	}
	if ic.ApplicabilityStatusCode == nil || (*ic.ApplicabilityStatusCode == 0 && scanStatus.ApplicabilityStatusCode != nil) {
		ic.ApplicabilityStatusCode = scanStatus.ApplicabilityStatusCode
	}
}

func (ic *ScansIssuesCollection) IsScanNotCompleted(scanType utils.SubScanType) bool {
	status := ic.GetScanStatus(scanType)
	// Failed or not performed scans
	return status == nil || *status != 0
}

func (ic *ScansIssuesCollection) GetScanStatus(scanType utils.SubScanType) *int {
	switch scanType {
	case utils.ScaScan:
		return ic.ScaStatusCode
	case utils.IacScan:
		return ic.IacStatusCode
	case utils.SecretsScan:
		return ic.SecretsStatusCode
	case utils.SastScan:
		return ic.SastStatusCode
	case utils.ContextualAnalysisScan:
		return ic.ApplicabilityStatusCode
	}
	return nil
}

// Only if performed and failed
func (ic *ScansIssuesCollection) HasErrors() bool {
	if scaStatus := ic.GetScanStatus(utils.ScaScan); scaStatus != nil && *scaStatus != 0 {
		return true
	}
	if applicabilityStatus := ic.GetScanStatus(utils.ContextualAnalysisScan); applicabilityStatus != nil && *applicabilityStatus != 0 {
		return true
	}
	if iacStatus := ic.GetScanStatus(utils.IacScan); iacStatus != nil && *iacStatus != 0 {
		return true
	}
	if secretsStatus := ic.GetScanStatus(utils.SecretsScan); secretsStatus != nil && *secretsStatus != 0 {
		return true
	}
	if sastStatus := ic.GetScanStatus(utils.SastScan); sastStatus != nil && *sastStatus != 0 {
		return true
	}
	return false
}

func (ic *ScansIssuesCollection) GetScanIssuesSeverityCount(scanType utils.SubScanType, vulnerabilities, violation bool) map[severityutils.Severity]int {
	scanDetails := map[severityutils.Severity]int{}
	if scanType == utils.ScaScan {
		// Count Sca issues only if requested
		if violation {
			for _, violation := range ic.ScaViolations {
				scanDetails[severityutils.GetSeverity(violation.Severity)]++
			}
			for _, violation := range ic.LicensesViolations {
				scanDetails[severityutils.GetSeverity(violation.Severity)]++
			}
		}
		if vulnerabilities {
			for _, vulnerability := range ic.ScaVulnerabilities {
				scanDetails[severityutils.GetSeverity(vulnerability.Severity)]++
			}
		}
		return scanDetails
	}
	jasVulnerabilities := []formats.SourceCodeRow{}
	jasViolations := []formats.SourceCodeRow{}
	switch scanType {
	case utils.IacScan:
		// Count Iac issues only if requested
		if violation {
			jasViolations = ic.IacViolations
		}
		if vulnerabilities {
			jasVulnerabilities = ic.IacVulnerabilities
		}
	case utils.SecretsScan:
		// Count Secrets issues only if requested
		if violation {
			jasViolations = ic.SecretsViolations
		}
		if vulnerabilities {
			jasVulnerabilities = ic.SecretsVulnerabilities
		}
	case utils.SastScan:
		// Count Sast issues only if requested
		if violation {
			jasViolations = ic.SastViolations
		}
		if vulnerabilities {
			jasVulnerabilities = ic.SastVulnerabilities
		}
	}
	// Count the issues
	for _, issue := range jasVulnerabilities {
		scanDetails[severityutils.GetSeverity(issue.Severity)]++
	}
	for _, issue := range jasViolations {
		scanDetails[severityutils.GetSeverity(issue.Severity)]++
	}
	return scanDetails
}

func (ic *ScansIssuesCollection) IssuesExists(includeSecrets bool) bool {
	return ic.ScaIssuesExists() || ic.IacIssuesExists() || ic.SastIssuesExists() || (includeSecrets && ic.SecretsIssuesExists())
}

func (ic *ScansIssuesCollection) ScaIssuesExists() bool {
	return len(ic.ScaVulnerabilities) > 0 || len(ic.ScaViolations) > 0 || len(ic.LicensesViolations) > 0
}

func (ic *ScansIssuesCollection) IacIssuesExists() bool {
	return len(ic.IacVulnerabilities) > 0 || len(ic.IacViolations) > 0
}

func (ic *ScansIssuesCollection) SecretsIssuesExists() bool {
	return len(ic.SecretsVulnerabilities) > 0 || len(ic.SecretsViolations) > 0
}

func (ic *ScansIssuesCollection) SastIssuesExists() bool {
	return len(ic.SastVulnerabilities) > 0 || len(ic.SastViolations) > 0
}

func (ic *ScansIssuesCollection) GetTotalIssues(includeSecrets bool) int {
	return ic.GetTotalVulnerabilities(includeSecrets) + ic.GetTotalViolations(includeSecrets)
}

type ApplicableEvidences struct {
	Evidence                                                                           formats.Evidence
	Severity, ScannerDescription, IssueId, CveSummary, ImpactedDependency, Remediation string
}

func toApplicableEvidences(issue formats.VulnerabilityOrViolationRow, cve formats.CveRow, evidence formats.Evidence) ApplicableEvidences {
	remediation := ""
	if issue.JfrogResearchInformation != nil {
		remediation = issue.JfrogResearchInformation.Remediation
	}
	return ApplicableEvidences{
		Evidence:           evidence,
		Severity:           issue.Severity,
		ScannerDescription: cve.Applicability.ScannerDescription,
		IssueId:            results.GetIssueIdentifier(issue.Cves, issue.IssueId, ", "),
		CveSummary:         issue.Summary,
		ImpactedDependency: results.GetDependencyId(issue.ImpactedDependencyName, issue.ImpactedDependencyVersion),
		Remediation:        remediation,
	}
}

func (ic *ScansIssuesCollection) GetApplicableEvidences() (evidences []ApplicableEvidences) {
	// Collect evidences from Violations
	idToEvidence := map[string]ApplicableEvidences{}
	for _, securityViolation := range ic.ScaViolations {
		for _, cve := range securityViolation.Cves {
			if cve.Applicability != nil && cve.Applicability.Status == jasutils.Applicable.String() {
				// We only want applicable issues
				for _, evidence := range cve.Applicability.Evidence {
					issueId := results.GetIssueIdentifier(securityViolation.Cves, securityViolation.IssueId, "-")
					id := issueId + evidence.Location.ToString()
					if _, exists := idToEvidence[id]; exists {
						// No need to add the same issue twice
						continue
					}
					idToEvidence[id] = toApplicableEvidences(securityViolation, cve, evidence)
				}
			}
		}
	}
	// Collect evidences from Vulnerabilities
	for _, vulnerability := range ic.ScaVulnerabilities {
		for _, cve := range vulnerability.Cves {
			if cve.Applicability != nil && cve.Applicability.Status == jasutils.Applicable.String() {
				// We only want applicable issues
				for _, evidence := range cve.Applicability.Evidence {
					issueId := results.GetIssueIdentifier(vulnerability.Cves, vulnerability.IssueId, "-")
					id := issueId + evidence.Location.ToString()
					if _, exists := idToEvidence[id]; exists {
						// No need to add the same issue twice
						continue
					}
					idToEvidence[id] = toApplicableEvidences(vulnerability, cve, evidence)
				}
			}
		}
	}

	for _, evidence := range idToEvidence {
		evidences = append(evidences, evidence)
	}
	return
}

// Violations

func (ic *ScansIssuesCollection) GetTotalViolations(includeSecrets bool) int {
	total := ic.GetTotalScaViolations() + len(ic.IacViolations) + len(ic.SastViolations)
	if includeSecrets {
		total += len(ic.SecretsViolations)
	}
	return total
}

func (ic *ScansIssuesCollection) GetTotalScaViolations() int {
	return len(ic.ScaViolations) + len(ic.LicensesViolations)
}

// Vulnerabilities

func (ic *ScansIssuesCollection) GetTotalVulnerabilities(includeSecrets bool) int {
	total := len(ic.ScaVulnerabilities) + len(ic.IacVulnerabilities) + len(ic.SastVulnerabilities)
	if includeSecrets {
		total += len(ic.SecretsVulnerabilities)
	}
	return total
}
