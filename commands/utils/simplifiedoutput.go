package utils

import (
	"fmt"
	"github.com/jfrog/froggit-go/vcsutils"
	"github.com/jfrog/jfrog-cli-core/v2/xray/formats"
	"strings"
)

type SimplifiedOutput struct {
	entitledForJas bool
	vcsProvider    vcsutils.VcsProvider
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

func (smo *SimplifiedOutput) SetVcsProvider(provider vcsutils.VcsProvider) {
	smo.vcsProvider = provider
}

func (smo *SimplifiedOutput) VcsProvider() vcsutils.VcsProvider {
	return smo.vcsProvider
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
	for i := range vulnerabilitiesRows {
		contentBuilder.WriteString(fmt.Sprintf(`
#### %s %s

%s

`,
			vulnerabilitiesRows[i].ImpactedDependencyName,
			vulnerabilitiesRows[i].ImpactedDependencyVersion,
			createVulnerabilityDescription(&vulnerabilitiesRows[i], smo.vcsProvider)))
	}

	return contentBuilder.String()
}

func (smo *SimplifiedOutput) Footer() string {
	return fmt.Sprintf("\n\n---\n%s", CommentGeneratedByFrogbot)
}

func (smo *SimplifiedOutput) Seperator() string {
	return ", "
}

func (smo *SimplifiedOutput) FormattedSeverity(severity, _ string) string {
	return severity
}
