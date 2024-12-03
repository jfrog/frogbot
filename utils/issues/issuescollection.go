package issues

import (
	"github.com/jfrog/gofrog/datastructures"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/severityutils"
)

// TODO: after refactor, move this to security-cli as a new formats or remove this and use the existing formats
// Group issues by scan type
type ScansIssuesCollection struct {
	LicensesViolations []formats.LicenseViolationRow

	ScaVulnerabilities []formats.VulnerabilityOrViolationRow
	ScaViolations      []formats.VulnerabilityOrViolationRow
	ScaScanPerformed   bool
	ScaScanStatus      int

	ApplicabilityScanPerformed bool
	ApplicabilityScanStatus    int

	IacVulnerabilities []formats.SourceCodeRow
	IacViolations      []formats.SourceCodeRow
	IacScan            bool
	IacScanStatus      int

	SecretsVulnerabilities []formats.SourceCodeRow
	SecretsViolations      []formats.SourceCodeRow
	SecretsScanPerformed   bool
	SecretsScanStatus      int

	SastViolations      []formats.SourceCodeRow
	SastVulnerabilities []formats.SourceCodeRow
	SastScanPerformed   bool
	SastScanStatus      int
}

func (ic *ScansIssuesCollection) GetTotalViolations() int {
	return len(ic.ScaViolations) + len(ic.IacViolations) + len(ic.SecretsViolations) + len(ic.SastViolations) + len(ic.LicensesViolations)
}

func (ic *ScansIssuesCollection) GetScanDetails(scanType utils.SubScanType, violation bool) map[severityutils.Severity]int {
	scanDetails := map[severityutils.Severity]int{}

	if scanType == utils.ScaScan {
		if violation {
			for _, violation := range ic.ScaViolations {
				scanDetails[severityutils.GetSeverity(violation.Severity)]++
			}
		} else {
			for _, vulnerability := range ic.ScaVulnerabilities {
				scanDetails[severityutils.GetSeverity(vulnerability.Severity)]++
			}
		}
		return scanDetails
	}

	jasIssues := []formats.SourceCodeRow{}
	switch scanType {
	case utils.IacScan:
		if violation {
			jasIssues = ic.IacViolations
		} else {
			jasIssues = ic.IacVulnerabilities
		}
	case utils.SecretsScan:
		if violation {
			jasIssues = ic.SecretsViolations
		} else {
			jasIssues = ic.SecretsVulnerabilities
		}
	case utils.SastScan:
		if violation {
			jasIssues = ic.SastViolations
		} else {
			jasIssues = ic.SastVulnerabilities
		}
	}

	for _, issue := range jasIssues {
		scanDetails[severityutils.GetSeverity(issue.Severity)]++
	}

	return scanDetails
}

func (ic *ScansIssuesCollection) GetScaIssues() (unique []formats.VulnerabilityOrViolationRow) {
	return append(ic.ScaVulnerabilities, ic.ScaViolations...)
}

func (ic *ScansIssuesCollection) ScaIssuesExists() bool {
	return len(ic.ScaVulnerabilities) > 0 || len(ic.ScaViolations) > 0
}

func (ic *ScansIssuesCollection) GetUniqueIacIssues() (unique []formats.SourceCodeRow) {
	return getUniqueJasIssues(ic.IacVulnerabilities, ic.IacViolations)
}

func (ic *ScansIssuesCollection) IacIssuesExists() bool {
	return len(ic.IacVulnerabilities) > 0 || len(ic.IacViolations) > 0
}

func (ic *ScansIssuesCollection) GetUniqueSecretsIssues() (unique []formats.SourceCodeRow) {
	return getUniqueJasIssues(ic.SecretsVulnerabilities, ic.SecretsViolations)
}

func (ic *ScansIssuesCollection) SecretsIssuesExists() bool {
	return len(ic.SecretsVulnerabilities) > 0 || len(ic.SecretsViolations) > 0
}

func (ic *ScansIssuesCollection) GetUniqueSastIssues() (unique []formats.SourceCodeRow) {
	return getUniqueJasIssues(ic.SastVulnerabilities, ic.SastViolations)
}

func getUniqueJasIssues(vulnerabilities, violations []formats.SourceCodeRow) (unique []formats.SourceCodeRow) {
	parsedIssues := datastructures.MakeSet[string]()
	for _, violation := range violations {
		issueId := violation.ToString() + "|" + violation.Finding
		if parsedIssues.Exists(issueId) {
			continue
		}
		parsedIssues.Add(issueId)
		unique = append(unique, violation)
	}
	for _, vulnerability := range vulnerabilities {
		issueId := vulnerability.ToString() + "|" + vulnerability.Finding
		if parsedIssues.Exists(issueId) {
			continue
		}
		parsedIssues.Add(issueId)
		unique = append(unique, vulnerability)
	}
	return
}

func (ic *ScansIssuesCollection) SastIssuesExists() bool {
	return len(ic.SastVulnerabilities) > 0 || len(ic.SastViolations) > 0
}

func (ic *ScansIssuesCollection) LicensesViolationsExists() bool {
	return len(ic.LicensesViolations) > 0
}

func (ic *ScansIssuesCollection) PresentableIssuesExists() bool {
	return ic.ScaIssuesExists() || ic.IacIssuesExists() || ic.LicensesViolationsExists() || ic.SastIssuesExists()
}

func (ic *ScansIssuesCollection) ViolationsExists() bool {
	return len(ic.ScaViolations) > 0 || len(ic.IacViolations) > 0 || len(ic.SecretsViolations) > 0 || len(ic.SastViolations) > 0 || len(ic.LicensesViolations) > 0
}

func (ic *ScansIssuesCollection) Append(issues *ScansIssuesCollection) {
	if issues == nil {
		return
	}
	if len(issues.ScaVulnerabilities) > 0 {
		ic.ScaVulnerabilities = append(ic.ScaVulnerabilities, issues.ScaVulnerabilities...)
	}
	if len(issues.ScaViolations) > 0 {
		ic.ScaViolations = append(ic.ScaViolations, issues.ScaViolations...)

	}

	if len(issues.SecretsVulnerabilities) > 0 {
		ic.SecretsVulnerabilities = append(ic.SecretsVulnerabilities, issues.SecretsVulnerabilities...)
	}
	if len(issues.SecretsViolations) > 0 {
		ic.SecretsViolations = append(ic.SecretsViolations, issues.SecretsViolations...)
	}

	if len(issues.SastVulnerabilities) > 0 {
		ic.SastVulnerabilities = append(ic.SastVulnerabilities, issues.SastVulnerabilities...)
	}
	if len(issues.SastViolations) > 0 {
		ic.SastViolations = append(ic.SastViolations, issues.SastViolations...)
	}

	if len(issues.IacVulnerabilities) > 0 {
		ic.IacVulnerabilities = append(ic.IacVulnerabilities, issues.IacVulnerabilities...)
	}
	if len(issues.IacViolations) > 0 {
		ic.IacViolations = append(ic.IacViolations, issues.IacViolations...)
	}

	if len(issues.LicensesViolations) > 0 {
		ic.LicensesViolations = append(ic.LicensesViolations, issues.LicensesViolations...)
	}
}

func (ic *ScansIssuesCollection) CountIssuesCollectionFindings() int {
	count := 0

	count += len(ic.GetScaIssues())
	count += len(ic.GetUniqueIacIssues())
	count += len(ic.GetUniqueSecretsIssues())
	count += len(ic.GetUniqueSastIssues())
	count += len(ic.LicensesViolations)

	return count
}
