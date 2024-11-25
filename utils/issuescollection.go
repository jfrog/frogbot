package utils

import (
	"github.com/jfrog/gofrog/datastructures"
	"github.com/jfrog/jfrog-cli-security/utils/formats"
)

type IssuesCollection struct {
	ScaVulnerabilities     []formats.VulnerabilityOrViolationRow
	IacVulnerabilities    []formats.SourceCodeRow
	SecretsVulnerabilities []formats.SourceCodeRow
	SastVulnerabilities    []formats.SourceCodeRow

	ScaViolations          []formats.VulnerabilityOrViolationRow
	LicensesViolations     []formats.LicenseRow
	IacViolations         []formats.SourceCodeRow
	SecretsViolations      []formats.SourceCodeRow
	SastViolations         []formats.SourceCodeRow
}

// func (ic *IssuesCollection) GetUniqueScaIssues() (unique []formats.VulnerabilityOrViolationRow) {
// 	parsedIssues := datastructures.MakeSet[string]()
// 	for _, issue := range ic.ScaViolations {
// 		if !parsedIssues.Exists(issue.IssueId + "|" + component.Name + "|" + component.Version) {
// 			unique = append(unique, issue)
// 			parsedIssues.Add(issue.IssueId)
// 		}
// 	}
// 	for _, issue := range ic.ScaVulnerabilities {
// 		if !parsedIssues.Exists(issue.IssueId) {
// 			unique = append(unique, issue)
// 			parsedIssues.Add(issue.IssueId)
// 		}
// 	}
// 	return
// }

func (ic *IssuesCollection) ScaIssuesExists() bool {
	return len(ic.ScaVulnerabilities) > 0 || len(ic.ScaViolations) > 0
}

func (ic *IssuesCollection) IacIssuesExists() bool {
	return len(ic.IacVulnerabilities) > 0 || len(ic.IacViolations) > 0
}

func (ic *IssuesCollection) GetUniqueSecretsIssues() (unique []formats.SourceCodeRow) {
	parsedIssues := datastructures.MakeSet[string]()
	for _, violation := range ic.SecretsViolations {
		issueId := violation.ToString() + "|" + violation.Finding
		if parsedIssues.Exists(issueId) {
			continue
		}
		parsedIssues.Add(issueId)
		unique = append(unique, violation)
	}
	for _, vulnerability := range ic.SecretsVulnerabilities {
		issueId := vulnerability.ToString() + "|" + vulnerability.Finding
		if parsedIssues.Exists(issueId) {
			continue
		}
		parsedIssues.Add(issueId)
		unique = append(unique, vulnerability)
	}
	return
}

func (ic *IssuesCollection) SecretsIssuesExists() bool {
	return len(ic.SecretsVulnerabilities) > 0 || len(ic.SecretsViolations) > 0
}

func (ic *IssuesCollection) SastIssuesExists() bool {
	return len(ic.SastVulnerabilities) > 0 || len(ic.SastViolations) > 0
}

func (ic *IssuesCollection) LicensesViolationsExists() bool {
	return len(ic.LicensesViolations) > 0
}

func (ic *IssuesCollection) PresentableIssuesExists() bool {
	return ic.ScaIssuesExists() || ic.IacIssuesExists() || ic.LicensesViolationsExists() || ic.SastIssuesExists()
}

func (ic *IssuesCollection) Append(issues *IssuesCollection) {
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

func (ic *IssuesCollection) CountIssuesCollectionFindings() int {
	uniqueFindings := datastructures.MakeSet[string]()

	for _, vulnerability := range ic.ScaVulnerabilities {
		for _, component := range vulnerability.Components {
			uniqueFindings.Add(vulnerability.IssueId + "|" + component.Name + "|" + component.Version)
		}
	}
	for _, violations := range ic.ScaViolations {
		for _, component := range violations.Components {
			uniqueFindings.Add(violations.IssueId + "|" + component.Name + "|" + component.Version)
		}
	}
	for _, vulnerability := range ic.IacVulnerabilities {
		uniqueFindings.Add(vulnerability.ToString() + "|" + vulnerability.Finding)
	}
	for _, violations := range ic.IacViolations {
		uniqueFindings.Add(violations.ToString() + "|" + violations.Finding)
	}
	for _, vulnerability := range ic.SecretsVulnerabilities {
		uniqueFindings.Add(vulnerability.ToString() + "|" + vulnerability.Finding)
	}
	for _, violations := range ic.SecretsViolations {
		uniqueFindings.Add(violations.ToString() + "|" + violations.Finding)
	}
	for _, vulnerability := range ic.SastVulnerabilities {
		uniqueFindings.Add(vulnerability.ToString() + "|" + vulnerability.Finding)
	}
	for _, violations := range ic.SastViolations {
		uniqueFindings.Add(violations.ToString() + "|" + violations.Finding)
	}

	return uniqueFindings.Size()
}


