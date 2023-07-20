package utils

import (
	"fmt"
	"github.com/jfrog/froggit-go/vcsutils"
	"github.com/jfrog/jfrog-cli-core/v2/xray/formats"
	"strings"
)

const (
	directDependencyRow        = "|  | %s |  |  |"
	directDependencyRowWithJas = "|  |  | %s |  |  |"
)

type SimplifiedOutput struct {
	entitledForJas bool
	vcsProvider    vcsutils.VcsProvider
}

func (smo *SimplifiedOutput) VulnerabilitiesTableRow(vulnerability formats.VulnerabilityOrViolationRow) string {
	row := fmt.Sprintf("| %s | ", smo.FormattedSeverity(vulnerability.Severity, vulnerability.Applicable))
	directsRowFmt := directDependencyRow
	if smo.EntitledForJas() && vulnerability.Technology.ApplicabilityScannable() {
		row += vulnerability.Applicable + " |"
		directsRowFmt = directDependencyRowWithJas
	}
	var firstDirectDependency string
	if len(vulnerability.Components) > 0 {
		firstDirectDependency = fmt.Sprintf("%s:%s", vulnerability.Components[0].Name, vulnerability.Components[0].Version)
	}
	row += fmt.Sprintf(" %s | %s | %s |",
		firstDirectDependency,
		fmt.Sprintf("%s:%s", vulnerability.ImpactedDependencyName, vulnerability.ImpactedDependencyVersion),
		strings.Join(vulnerability.FixedVersions, smo.Seperator()),
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
			createVulnerabilityDescription(&vulnerabilities[i])))
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
	return fmt.Sprintf("\n\n%s", CommentGeneratedByFrogbot)
}

func (smo *SimplifiedOutput) Seperator() string {
	return ", "
}

func (smo *SimplifiedOutput) FormattedSeverity(severity, _ string) string {
	return severity
}

func (smo *SimplifiedOutput) UntitledForJasMsg() string {
	msg := ""
	if !smo.entitledForJas {
		msg = "\n\n**Frogbot** also supports **Contextual Analysis**. This feature is included as part of the [JFrog Advanced Security](https://jfrog.com/xray/) package, which isn't enabled on your system."
	}
	return msg
}
