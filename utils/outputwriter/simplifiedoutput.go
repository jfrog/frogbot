package outputwriter

import (
	"fmt"
	"strings"

	"github.com/jfrog/froggit-go/vcsutils"
	"github.com/jfrog/jfrog-cli-core/v2/xray/formats"
)

const (
	directDependencyRow        = "|  | %s |  |  |"
	directDependencyRowWithJas = "|  |  | %s |  |  |"
	simpleSeparator       = ", "
)

type SimplifiedOutput struct {
	showCaColumn   bool
	entitledForJas bool
	vcsProvider    vcsutils.VcsProvider
}

func (smo *SimplifiedOutput) VulnerabilitiesTableRow(vulnerability formats.VulnerabilityOrViolationRow) string {
	row := fmt.Sprintf("| %s | ", smo.FormattedSeverity(vulnerability.Severity, vulnerability.Applicable))
	directsRowFmt := directDependencyRow
	if smo.showCaColumn {
		row += vulnerability.Applicable + " |"
		directsRowFmt = directDependencyRowWithJas
	}
	var firstDirectDependency string
	if len(vulnerability.Components) > 0 {
		firstDirectDependency = fmt.Sprintf("%s:%s", vulnerability.Components[0].Name, vulnerability.Components[0].Version)
	}

	cves := getTableRowCves(vulnerability, smo)
	fixedVersions := GetTableRowsFixedVersions(vulnerability, smo)
	row += fmt.Sprintf(" %s | %s | %s | %s |",
		firstDirectDependency,
		fmt.Sprintf("%s:%s", vulnerability.ImpactedDependencyName, vulnerability.ImpactedDependencyVersion),
		fixedVersions,
		cves,
	)
	for i := 1; i < len(vulnerability.Components); i++ {
		currDirect := vulnerability.Components[i]
		row += "\n" + fmt.Sprintf(directsRowFmt, fmt.Sprintf("%s:%s", currDirect.Name, currDirect.Version))
	}
	return row
}

func (smo *SimplifiedOutput) Image(source ImageSource) string {
	return GetSimplifiedTitle(source)
}

func (smo *SimplifiedOutput) NoVulnerabilitiesTitle() string {
	return GetSimplifiedTitle(NoVulnerabilityPrBannerSource)
}

func (smo *SimplifiedOutput) VulnerabilitiesTitle(isComment bool) string {
	if isComment {
		return GetSimplifiedTitle(VulnerabilitiesPrBannerSource)
	}
	return GetSimplifiedTitle(VulnerabilitiesFixPrBannerSource)
}

func (smo *SimplifiedOutput) IsFrogbotResultComment(comment string) bool {
	return strings.HasPrefix(comment, GetSimplifiedTitle(NoVulnerabilityPrBannerSource)) || strings.HasPrefix(comment, GetSimplifiedTitle(VulnerabilitiesPrBannerSource))
}

func (smo *SimplifiedOutput) SetVcsProvider(provider vcsutils.VcsProvider) {
	smo.vcsProvider = provider
}

func (smo *SimplifiedOutput) VcsProvider() vcsutils.VcsProvider {
	return smo.vcsProvider
}

func (smo *SimplifiedOutput) SetJasOutputFlags(entitled, showCaColumn bool) {
	smo.entitledForJas = entitled
	smo.showCaColumn = showCaColumn
}

func (smo *SimplifiedOutput) VulnerabilitiesContent(vulnerabilities []formats.VulnerabilityOrViolationRow) string {
	if len(vulnerabilities) == 0 {
		return ""
	}
	var contentBuilder strings.Builder
	// Write summary table part
	contentBuilder.WriteString(fmt.Sprintf("\n%s\n%s\n%s\n",
		smo.MarkAsTitle(vulnerableDependenciesTitle, 2),
		smo.MarkAsTitle(vulnerableDependenciesSummarySubTitle, 3),
		smo.MarkInCenter(fmt.Sprintf(`%s %s`, getVulnerabilitiesTableHeader(smo.showCaColumn), getVulnerabilitiesTableContent(vulnerabilities, smo)))),
	)
	// Write for each vulnerability details part
	detailsContent := smo.getVulnerabilityDescriptionContent(vulnerabilities)
	if strings.TrimSpace(detailsContent) != "" {
		if len(vulnerabilities) == 1 {
			contentBuilder.WriteString(fmt.Sprintf("\n%s\n%s\n",
				smo.MarkAsTitle(vulnerableDependenciesResearchDetailsSubTitle, 3),
				detailsContent,
			))
		} else {
			contentBuilder.WriteString(fmt.Sprintf("%s\n",
				smo.MarkAsDetails(vulnerableDependenciesResearchDetailsSubTitle, 3, detailsContent),
			))
		}
	}
	return contentBuilder.String()
}

func (smo *SimplifiedOutput) getVulnerabilityDescriptionContent(vulnerabilities []formats.VulnerabilityOrViolationRow) string {
	var descriptionContentBuilder strings.Builder
	shouldOutputDescriptionSection := false
	for i := range vulnerabilities {
		vulDescriptionContent := createVulnerabilityDescription(&vulnerabilities[i])
		if strings.TrimSpace(vulDescriptionContent) == "" {
			// No content
			continue
		}
		shouldOutputDescriptionSection = true
		if len(vulnerabilities) == 1 {
			descriptionContentBuilder.WriteString(fmt.Sprintf("\n%s\n", vulDescriptionContent))
			break
		}
		descriptionContentBuilder.WriteString(fmt.Sprintf("%s\n",
			smo.MarkAsDetails(fmt.Sprintf(`%s%s %s`,
				getVulnerabilityDescriptionIdentifier(vulnerabilities[i].Cves, vulnerabilities[i].IssueId),
				vulnerabilities[i].ImpactedDependencyName,
				vulnerabilities[i].ImpactedDependencyVersion,
			), 4, vulDescriptionContent)),
		)
	}
	if !shouldOutputDescriptionSection {
		return ""
	}
	return descriptionContentBuilder.String()
}

func (smo *SimplifiedOutput) LicensesContent(licenses []formats.LicenseRow) string {
	if len(licenses) == 0 {
		return ""
	}

	return fmt.Sprintf(`
---
%s
---

%s 
%s

`,
		violatedLicenseTitle,
		licenseTableHeader,
		getLicensesTableContent(licenses, smo))
}

func (smo *SimplifiedOutput) Footer() string {
	return fmt.Sprintf("%s%s", SectionDivider(), smo.MarkInCenter(CommentGeneratedByFrogbot))
}

func (smo *SimplifiedOutput) Separator() string {
	return simpleSeparator
}

func (smo *SimplifiedOutput) FormattedSeverity(severity, _ string) string {
	return severity
}

func (smo *SimplifiedOutput) UntitledForJasMsg() string {
	msg := ""
	if !smo.entitledForJas {
		msg = "\n\n---\n**Frogbot** also supports **Contextual Analysis, Secret Detection and IaC Vulnerabilities Scanning**. This features are included as part of the [JFrog Advanced Security](https://jfrog.com/xray/) package, which isn't enabled on your system.\n"
	}
	return msg
}

func (smo *SimplifiedOutput) MarkInCenter(content string) string {
	return fmt.Sprintf("\n%s", content)
}

func (smo *SimplifiedOutput) MarkAsDetails(summary string, subTitleDepth int, content string) string {
	return fmt.Sprintf("%s%s", smo.MarkAsTitle(summary, subTitleDepth), content)
	// return fmt.Sprintf("%s### %s%s%s", SectionDivider(), summary, SectionDivider(), content)
}

// func (smo *SimplifiedOutput) MarkAsDetails(summary, content string) string {
// 	// return fmt.Sprintf("%s%s", smo.MarkAsTitle(summary, 3), content)
// 	return fmt.Sprintf("%s### %s%s%s", SectionDivider(), summary, SectionDivider(), content)
// }

func (smo *SimplifiedOutput) MarkAsTitle(title string, subTitleDepth int) string {
	return fmt.Sprintf("%s%s %s%s", SectionDivider(), strings.Repeat("#", subTitleDepth), title, SectionDivider())
}
