package utils

import (
	"fmt"
	"github.com/jfrog/jfrog-cli-core/v2/xray/formats"
	"strings"
)

type StandardOutput struct{}

func (so *StandardOutput) TableRow(vulnerability formats.VulnerabilityOrViolationRow) string {
	var cveId string
	if len(vulnerability.Cves) > 0 {
		cveId = vulnerability.Cves[0].Id
	}

	var directDependencies, directDependenciesVersions strings.Builder
	if len(vulnerability.Components) > 0 {
		for _, dependency := range vulnerability.Components {
			directDependencies.WriteString(fmt.Sprintf("%s<br>", dependency.Name))
			directDependenciesVersions.WriteString(fmt.Sprintf("%s<br>", dependency.Version))
		}
	}

	return fmt.Sprintf("\n| %s%8s | %s | %s | %s | %s | %s | %s ",
		GetSeverityTag(IconName(vulnerability.Severity)),
		vulnerability.Severity,
		strings.TrimSuffix(directDependencies.String(), "<br>"),
		strings.TrimSuffix(directDependenciesVersions.String(), "<br>"),
		vulnerability.ImpactedDependencyName,
		vulnerability.ImpactedDependencyVersion,
		strings.Join(vulnerability.FixedVersions, "<br>"),
		cveId)
}

func (so *StandardOutput) NoVulnerabilitiesTitle() string {
	return GetBanner(NoVulnerabilityBannerSource) + WhatIsFrogbotMd
}

func (so *StandardOutput) VulnerabiltiesTitle() string {
	return GetBanner(VulnerabilitiesBannerSource) + WhatIsFrogbotMd
}

func (so *StandardOutput) TableHeader() string {
	return TableHeader
}

func (smo *StandardOutput) IsFrogbotResultComment(comment string) bool {
	return strings.Contains(comment, GetIconTag(NoVulnerabilityBannerSource)) || strings.Contains(comment, GetIconTag(VulnerabilitiesBannerSource))
}
