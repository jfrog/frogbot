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

func (smo *SimplifiedOutput) VulnerabilitiesTableRow(vulnerability formats.VulnerabilityOrViolationRow) string {
	return createVulnerabilitiesTableRow(vulnerability, smo)
}

func (smo *SimplifiedOutput) NoVulnerabilitiesTitle() string {
	return GetSimplifiedTitle(NoVulnerabilityPrBannerSource)
}

func (smo *SimplifiedOutput) VulnerabiltiesTitle(isComment bool) string {
	if !isComment {
		return GetSimplifiedTitle(VulnerabilitiesFixPrBannerSource)
	}
	return GetSimplifiedTitle(VulnerabilitiesPrBannerSource)
}

func (smo *SimplifiedOutput) VulnerabilitiesTableHeader() string {
	header := vulnerabilitiesTableHeader
	if smo.entitledForJas {
		header = vulnerabilitiesTableHeaderWithJas
	}
	return header
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

func (smo *SimplifiedOutput) SetEntitledForJas(entitledForJas bool) {
	smo.entitledForJas = entitledForJas
}

func (smo *SimplifiedOutput) EntitledForJas() bool {
	return smo.entitledForJas
}

func (smo *SimplifiedOutput) VulnerabilitiesContent(vulnerabilities []formats.VulnerabilityOrViolationRow) string {
	var contentBuilder strings.Builder
	// Write summary table part
	contentBuilder.WriteString(fmt.Sprintf(`
---
## 📦 Vulnerable Dependencies
---

### ✍️ Summary 

%s %s

---
### 👇 Details
---

`,
		smo.VulnerabilitiesTableHeader(),
		getVulnerabilitiesTableContent(vulnerabilities, smo)))
	for i := range vulnerabilities {
		contentBuilder.WriteString(fmt.Sprintf(`
#### %s %s

%s

`,
			vulnerabilities[i].ImpactedDependencyName,
			vulnerabilities[i].ImpactedDependencyVersion,
			createVulnerabilityDescription(&vulnerabilities[i], smo.vcsProvider)))
	}

	return contentBuilder.String()
}

func (smo *SimplifiedOutput) IacContent(iacRows []formats.IacSecretsRow) string {
	if len(iacRows) == 0 {
		return ""
	}

	return fmt.Sprintf(`
## 🛠️ Infrastructure as Code 

%s %s

`,
		iacTableHeader,
		getIacTableContent(iacRows, smo))
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
