package utils

import (
	"github.com/jfrog/jfrog-cli-security/formats"
	xrayutils "github.com/jfrog/jfrog-cli-security/utils"
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

func ConvertResultsToCollection(results *xrayutils.Results, allowedLicenses []string) (*IssuesCollection, error) {
	scanResults := results.ExtendedScanResults
	xraySimpleJson, err := xrayutils.ConvertXrayScanToSimpleJson(results, results.IsMultipleProject(), false, true, allowedLicenses)
	if err != nil {
		return nil, err
	}
	return &IssuesCollection{
		Vulnerabilities: append(xraySimpleJson.Vulnerabilities, xraySimpleJson.SecurityViolations...),
		Iacs:            xrayutils.PrepareIacs(scanResults.IacScanResults),
		Secrets:         xrayutils.PrepareSecrets(scanResults.SecretsScanResults),
		Sast:            xrayutils.PrepareSast(scanResults.SastScanResults),
		Licenses:        xraySimpleJson.LicensesViolations,
	}, nil
}
