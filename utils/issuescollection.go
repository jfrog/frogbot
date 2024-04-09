package utils

import (
	"github.com/jfrog/gofrog/datastructures"
	"github.com/jfrog/jfrog-cli-security/formats"
)

type IssuesCollection struct {
	Vulnerabilities []formats.VulnerabilityOrViolationRow
	Iacs            []formats.SourceCodeRow
	Secrets         []formats.SourceCodeRow
	Sast            []formats.SourceCodeRow
	Licenses        []formats.LicenseRow
}

func (ic *IssuesCollection) VulnerabilitiesExists() bool {
	return len(ic.Vulnerabilities) > 0
}

func (ic *IssuesCollection) IacExists() bool {
	return len(ic.Iacs) > 0
}

func (ic *IssuesCollection) LicensesExists() bool {
	return len(ic.Licenses) > 0
}

func (ic *IssuesCollection) SecretsExists() bool {
	return len(ic.Secrets) > 0
}

func (ic *IssuesCollection) SastExists() bool {
	return len(ic.Sast) > 0
}

func (ic *IssuesCollection) IssuesExists() bool {
	return ic.VulnerabilitiesExists() || ic.IacExists() || ic.LicensesExists() || ic.SastExists()
}

func (ic *IssuesCollection) Append(issues *IssuesCollection) {
	if issues == nil {
		return
	}
	if len(issues.Vulnerabilities) > 0 {
		ic.Vulnerabilities = append(ic.Vulnerabilities, issues.Vulnerabilities...)
	}
	if len(issues.Secrets) > 0 {
		ic.Secrets = append(ic.Secrets, issues.Secrets...)
	}
	if len(issues.Sast) > 0 {
		ic.Sast = append(ic.Sast, issues.Sast...)
	}
	if len(issues.Iacs) > 0 {
		ic.Iacs = append(ic.Iacs, issues.Iacs...)
	}
	if len(issues.Licenses) > 0 {
		ic.Licenses = append(ic.Licenses, issues.Licenses...)
	}
}

func (ic *IssuesCollection) CountIssuesCollectionFindingsForAnalytics() int {
	uniqueFindings := datastructures.MakeSet[string]()

	var totalFindings int
	for _, vulnerability := range ic.Vulnerabilities {
		for _, component := range vulnerability.Components {
			uniqueFindings.Add(vulnerability.IssueId + "|" + component.Name + "|" + component.Version)
		}
	}
	totalFindings += uniqueFindings.Size()

	totalFindings += len(ic.Iacs)
	totalFindings += len(ic.Sast)
	totalFindings += len(ic.Secrets)
	return totalFindings
}
