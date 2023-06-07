package utils

import (
	"fmt"
	"github.com/jfrog/jfrog-cli-core/v2/xray/formats"
	"strings"
)

type SimplifiedOutput struct {
	entitledForJas bool
}

func (smo *SimplifiedOutput) TableRow(vulnerability formats.VulnerabilityOrViolationRow) string {
	return createTableRow(vulnerability, smo)
}

func (smo *SimplifiedOutput) NoVulnerabilitiesTitle() string {
	return GetSimplifiedTitle(NoVulnerabilityBannerSource)
}

func (smo *SimplifiedOutput) VulnerabiltiesTitle() string {
	return GetSimplifiedTitle(VulnerabilitiesBannerSource)
}

func (smo *SimplifiedOutput) Header() string {
	header := tableHeader
	if smo.entitledForJas {
		header = tableHeaderWithJas
	}
	return header
}

func (smo *SimplifiedOutput) IsFrogbotResultComment(comment string) bool {
	return strings.HasPrefix(comment, GetSimplifiedTitle(NoVulnerabilityBannerSource)) || strings.HasPrefix(comment, GetSimplifiedTitle(VulnerabilitiesBannerSource))
}

func (smo *SimplifiedOutput) SetEntitledForJas(entitledForJas bool) {
	smo.entitledForJas = entitledForJas
}

func (smo *SimplifiedOutput) EntitledForJas() bool {
	return smo.entitledForJas
}

func (smo *SimplifiedOutput) Content(vulnerabilitiesRows []formats.VulnerabilityOrViolationRow) string {
	var contentBuilder strings.Builder
	// Write summary table part
	contentBuilder.WriteString(fmt.Sprintf(`
---
### Summary
---

%s %s

---
### Details
---

`,
		smo.Header(),
		getTableContent(vulnerabilitiesRows, smo)))
	for _, vulnerability := range vulnerabilitiesRows {
		contentBuilder.WriteString(fmt.Sprintf(`
#### %s %s

%s

`,
			vulnerability.ImpactedDependencyName,
			vulnerability.ImpactedDependencyVersion,
			createVulnerabilityDescription(&vulnerability)))
	}

	return contentBuilder.String()
}

func (smo *SimplifiedOutput) Footer() string {
	return fmt.Sprintf("\n\n---\n%s", CommentGeneratedByFrogbot)
}

func (smo *SimplifiedOutput) Seperator() string {
	return ", "
}

func (smo *SimplifiedOutput) FormattedSeverity(severity string) string {
	return severity
}
