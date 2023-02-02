package utils

import (
	"fmt"
	"github.com/jfrog/jfrog-cli-core/v2/xray/formats"
	"strings"
)

type SimplifiedOutput struct{}

func (smo *SimplifiedOutput) TableRow(vulnerability formats.VulnerabilityOrViolationRow) string {
	var cveId string
	if len(vulnerability.Cves) > 0 {
		cveId = vulnerability.Cves[0].Id
	}
	var directDependencies strings.Builder
	if len(vulnerability.Components) > 0 {
		for _, dependency := range vulnerability.Components {
			directDependencies.WriteString(fmt.Sprintf("%s:%s, ", dependency.Name, dependency.Version))
		}
	}
	return fmt.Sprintf("\n| %s | %s | %s | %s | %s | %s |",
		vulnerability.Severity,
		strings.TrimSuffix(directDependencies.String(), ", "),
		vulnerability.ImpactedDependencyName,
		vulnerability.ImpactedDependencyVersion,
		strings.Join(vulnerability.FixedVersions, " "),
		cveId)
}

func (smo *SimplifiedOutput) NoVulnerabilitiesTitle() string {
	return GetSimplifiedTitle(NoVulnerabilityBannerSource) + WhatIsFrogbotMd
}

func (smo *SimplifiedOutput) VulnerabiltiesTitle() string {
	return GetSimplifiedTitle(VulnerabilitiesBannerSource) + WhatIsFrogbotMd
}

func (smo *SimplifiedOutput) TableHeader() string {
	return simplifiedTableHeader
}

func (smo *SimplifiedOutput) IsFrogbotResultComment(comment string) bool {
	return strings.HasPrefix(comment, GetSimplifiedTitle(NoVulnerabilityBannerSource)) || strings.HasPrefix(comment, GetSimplifiedTitle(VulnerabilitiesBannerSource))
}
