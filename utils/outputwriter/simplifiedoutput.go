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
	contentBuilder.WriteString(fmt.Sprintf(`
---
%s
---

%s

%s %s
`,

		vulnerableDependenciesTitle,
		summaryTitle,
		getVulnerabilitiesTableHeader(smo.showCaColumn),
		getVulnerabilitiesTableContent(vulnerabilities, smo)))

	// Write for each vulnerability details part
	var descriptionContentBuilder strings.Builder
	descriptionContentBuilder.WriteString(fmt.Sprintf(`
---
%s
---

`,
		researchDetailsTitle))

	shouldOutputDescriptionSection := false
	for i := range vulnerabilities {
		vulDescriptionContent := createVulnerabilityDescription(&vulnerabilities[i])
		if strings.TrimSpace(vulDescriptionContent) == "" {
			// No content
			continue
		}
		shouldOutputDescriptionSection = true
		descriptionContentBuilder.WriteString(fmt.Sprintf(`
#### %s%s %s

%s
`,
			getVulnerabilityDescriptionIdentifier(vulnerabilities[i].Cves, vulnerabilities[i].IssueId),
			vulnerabilities[i].ImpactedDependencyName,
			vulnerabilities[i].ImpactedDependencyVersion,
			vulDescriptionContent))
	}

	if shouldOutputDescriptionSection {
		return contentBuilder.String() + descriptionContentBuilder.String()
	}
	return contentBuilder.String()
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
		licenseTitle,
		licenseTableHeader,
		getLicensesTableContent(licenses, smo))
}

func (smo *SimplifiedOutput) Footer() string {
	return fmt.Sprintf("%s%s", SectionDivider(), smo.MarkInCenter(CommentGeneratedByFrogbot))
}

func (smo *SimplifiedOutput) Separator() string {
	return ", "
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

func (smo *SimplifiedOutput) MarkAsDetails(summary, content string) string {
	return fmt.Sprintf("%s### %s%s%s", SectionDivider(), summary, SectionDivider(), content)
}
