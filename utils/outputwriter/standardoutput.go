package outputwriter

import (
	"fmt"
	"strings"

	"github.com/jfrog/froggit-go/vcsutils"
)

type StandardOutput struct {
	showCaColumn   bool
	entitledForJas bool
	vcsProvider    vcsutils.VcsProvider
}

// func (so *StandardOutput) VulnerabilitiesTableRow(vulnerability formats.VulnerabilityOrViolationRow) string {
// 	var directDependencies strings.Builder
// 	for _, dependency := range vulnerability.Components {
// 		directDependencies.WriteString(fmt.Sprintf("%s:%s%s", dependency.Name, dependency.Version, so.Separator()))
// 	}

// 	row := fmt.Sprintf("| %s | ", so.FormattedSeverity(vulnerability.Severity, vulnerability.Applicable))
// 	if so.showCaColumn {
// 		row += vulnerability.Applicable + " | "
// 	}
// 	cves := getTableRowCves(vulnerability, so)
// 	fixedVersions := GetTableRowsFixedVersions(vulnerability, so)
// 	row += fmt.Sprintf("%s | %s | %s | %s |",
// 		strings.TrimSuffix(directDependencies.String(), so.Separator()),
// 		fmt.Sprintf("%s:%s", vulnerability.ImpactedDependencyName, vulnerability.ImpactedDependencyVersion),
// 		fixedVersions,
// 		cves,
// 	)
// 	return row
// }


// func (so *StandardOutput) NoVulnerabilitiesTitle() string {
// 	if so.vcsProvider == vcsutils.GitLab {
// 		return GetBanner(NoVulnerabilityMrBannerSource)
// 	}
// 	return GetBanner(NoVulnerabilityPrBannerSource)
// }

func (so *StandardOutput) VulnerabilitiesTitle(isComment bool) string {
	var banner string
	switch {
	case isComment && so.vcsProvider == vcsutils.GitLab:
		banner = GetBanner(VulnerabilitiesMrBannerSource)
	case isComment && so.vcsProvider != vcsutils.GitLab:
		banner = GetBanner(VulnerabilitiesPrBannerSource)
	case !isComment && so.vcsProvider == vcsutils.GitLab:
		banner = GetBanner(VulnerabilitiesFixMrBannerSource)
	case !isComment && so.vcsProvider != vcsutils.GitLab:
		banner = GetBanner(VulnerabilitiesFixPrBannerSource)
	}
	return banner
}

func (so *StandardOutput) IsFrogbotResultComment(comment string) bool {
	return strings.Contains(comment, string(NoVulnerabilityPrBannerSource)) ||
		strings.Contains(comment, string(VulnerabilitiesPrBannerSource)) ||
		strings.Contains(comment, string(NoVulnerabilityMrBannerSource)) ||
		strings.Contains(comment, string(VulnerabilitiesMrBannerSource))
}

func (so *StandardOutput) SetVcsProvider(provider vcsutils.VcsProvider) {
	so.vcsProvider = provider
}

func (so *StandardOutput) VcsProvider() vcsutils.VcsProvider {
	return so.vcsProvider
}

func (so *StandardOutput) SetJasOutputFlags(entitled, showCaColumn bool) {
	so.entitledForJas = entitled
	so.showCaColumn = showCaColumn
}

func (so *StandardOutput) IsShowingCaColumn() bool {
	return so.showCaColumn
}

func (so *StandardOutput) IsEntitledForJas() bool {
	return so.entitledForJas
}

// func (so *StandardOutput) VulnerabilitiesContent(vulnerabilities []formats.VulnerabilityOrViolationRow) string {
// 	if len(vulnerabilities) == 0 {
// 		return ""
// 	}
// 	var contentBuilder strings.Builder
// 	// Write summary table part
// 	contentBuilder.WriteString(fmt.Sprintf("\n%s\n%s\n%s\n",
// 		so.MarkAsTitle(vulnerableDependenciesTitle, 2),
// 		so.MarkAsTitle(vulnerableDependenciesSummarySubTitle, 3),
// 		so.MarkInCenter(fmt.Sprintf(`%s %s`, getVulnerabilitiesTableHeader(so.showCaColumn), getVulnerabilitiesTableContent(vulnerabilities, so)))),
// 	)
// 	// Write for each vulnerability details part
// 	detailsContent := so.getVulnerabilityDescriptionContent(vulnerabilities)
// 	if strings.TrimSpace(detailsContent) != "" {
// 		if len(vulnerabilities) == 1 {
// 			contentBuilder.WriteString(fmt.Sprintf("\n%s\n%s\n",
// 				so.MarkAsTitle(vulnerableDependenciesResearchDetailsSubTitle, 3),
// 				detailsContent,
// 			))
// 		} else {
// 			contentBuilder.WriteString(fmt.Sprintf("%s\n",
// 				so.MarkAsDetails(vulnerableDependenciesResearchDetailsSubTitle, 3, detailsContent),
// 			))
// 		}
// 	}
// 	return contentBuilder.String()
// }

// func (so *StandardOutput) getVulnerabilityDescriptionContent(vulnerabilities []formats.VulnerabilityOrViolationRow) string {
// 	var descriptionContentBuilder strings.Builder
// 	shouldOutputDescriptionSection := false
// 	for i := range vulnerabilities {
// 		vulDescriptionContent := createVulnerabilityDescription(&vulnerabilities[i])
// 		if strings.TrimSpace(vulDescriptionContent) == "" {
// 			// No content
// 			continue
// 		}
// 		shouldOutputDescriptionSection = true
// 		if len(vulnerabilities) == 1 {
// 			descriptionContentBuilder.WriteString(fmt.Sprintf("\n%s\n", vulDescriptionContent))
// 			break
// 		}
// 		descriptionContentBuilder.WriteString(fmt.Sprintf("%s\n",
// 			so.MarkAsDetails(fmt.Sprintf(`%s%s %s`,
// 				getVulnerabilityDescriptionIdentifier(vulnerabilities[i].Cves, vulnerabilities[i].IssueId),
// 				vulnerabilities[i].ImpactedDependencyName,
// 				vulnerabilities[i].ImpactedDependencyVersion,
// 			), 4, vulDescriptionContent)),
// 		)
// 	}
// 	if !shouldOutputDescriptionSection {
// 		return ""
// 	}
// 	return descriptionContentBuilder.String()
// }

// func (so *StandardOutput) Footer() string {
// 	return fmt.Sprintf("%s%s", SectionDivider(), so.MarkInCenter(CommentGeneratedByFrogbot))
// }

// func (so *StandardOutput) UntitledForJasMsg() string {
// 	msg := ""
// 	if !so.entitledForJas {
// 		msg = fmt.Sprintf("\n---%s\n",
// 			so.MarkInCenter("**Frogbot** also supports **Contextual Analysis, Secret Detection and IaC Vulnerabilities Scanning**. This features are included as part of the [JFrog Advanced Security](https://jfrog.com/xray/) package, which isn't enabled on your system."),
// 		)
// 	}
// 	return msg
// }

// func (so *StandardOutput) LicensesContent(licenses []formats.LicenseRow) string {
// 	if len(licenses) == 0 {
// 		return ""
// 	}
// 	return fmt.Sprintf(`
// %s%s

// `,
// 		violatedLicenseTitle,
// 		so.MarkInCenter(fmt.Sprintf("%s %s", licenseTableHeader, getLicensesTableContent(licenses, so))))
// }






func (so *StandardOutput) Separator() string {
	return "<br>"
}

func (so *StandardOutput) FormattedSeverity(severity, applicability string) string {
	return fmt.Sprintf("%s%8s", getSeverityTag(IconName(severity), applicability), severity)
}

func (so *StandardOutput) Image(source ImageSource) string {
	return GetBanner(source)
}

func (so *StandardOutput) MarkInCenter(content string) string {
	return fmt.Sprintf(`
<div align="center">

%s

</div>`, content)
}

func (so *StandardOutput) MarkAsDetails(summary string, subTitleDepth int, content string) string {
	return fmt.Sprintf(`
<details>
<summary> <b>%s</b> </summary>
<br>
%s

</details>`, summary, content)
}

func (so *StandardOutput) MarkAsTitle(title string, subTitleDepth int) string {
	return fmt.Sprintf("%s %s", strings.Repeat("#", subTitleDepth), title)
}
