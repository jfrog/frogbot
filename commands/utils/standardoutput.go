package utils

import (
	"fmt"
	"github.com/jfrog/froggit-go/vcsutils"
	"github.com/jfrog/jfrog-cli-core/v2/xray/formats"
	"strings"
)

type StandardOutput struct {
	entitledForJas bool
	vcsProvider    vcsutils.VcsProvider
}

func (so *StandardOutput) VulnerabilitiesTableRow(vulnerability formats.VulnerabilityOrViolationRow) string {
	return createVulnerabilitiesTableRow(vulnerability, so)
}

func (so *StandardOutput) NoVulnerabilitiesTitle() string {
	if so.vcsProvider == vcsutils.GitLab {
		return GetBanner(NoVulnerabilityMrBannerSource)
	}
	return GetBanner(NoVulnerabilityPrBannerSource)
}

func (so *StandardOutput) VulnerabiltiesTitle(isComment bool) string {
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

func (so *StandardOutput) VulnerabilitiesTableHeader() string {
	if so.entitledForJas {
		return vulnerabilitiesTableHeaderWithJas
	}
	return vulnerabilitiesTableHeader
}

func (so *StandardOutput) IsFrogbotResultComment(comment string) bool {
	return strings.Contains(comment, GetIconTag(NoVulnerabilityPrBannerSource)) || strings.Contains(comment, GetIconTag(VulnerabilitiesPrBannerSource))
}

func (so *StandardOutput) SetVcsProvider(provider vcsutils.VcsProvider) {
	so.vcsProvider = provider
}

func (so *StandardOutput) VcsProvider() vcsutils.VcsProvider {
	return so.vcsProvider
}

func (so *StandardOutput) SetEntitledForJas(entitledForJas bool) {
	so.entitledForJas = entitledForJas
}

func (so *StandardOutput) EntitledForJas() bool {
	return so.entitledForJas
}

func (so *StandardOutput) VulnerabilitiesContent(vulnerabilitiesRows []formats.VulnerabilityOrViolationRow) string {
	var contentBuilder strings.Builder
	// Write summary table part
	contentBuilder.WriteString(fmt.Sprintf(`
## 📦 Vulnerable Dependencies 

### ✍️ Summary

<div align="center">

%s %s

</div>

## 👇 Details

`,
		so.VulnerabilitiesTableHeader(),
		getVulnerabilitiesTableContent(vulnerabilitiesRows, so)))
	// Write details for each vulnerability
	for i := range vulnerabilitiesRows {
		if len(vulnerabilitiesRows) == 1 {
			contentBuilder.WriteString(fmt.Sprintf(`

%s

`, createVulnerabilityDescription(&vulnerabilitiesRows[i], so.vcsProvider)))
			break
		}
		contentBuilder.WriteString(fmt.Sprintf(`
<details>
<summary> <b>%s %s</b> </summary>
<br>
%s

</details>

`,
			vulnerabilitiesRows[i].ImpactedDependencyName,
			vulnerabilitiesRows[i].ImpactedDependencyVersion,
			createVulnerabilityDescription(&vulnerabilitiesRows[i], so.vcsProvider)))
	}
	return contentBuilder.String()
}

func (so *StandardOutput) IacContent(iacRows []formats.IacSecretsRow) string {
	if len(iacRows) == 0 {
		return ""
	}

	return fmt.Sprintf(`
## 🛠️ Infrastructure as Code 

<div align="center">

%s %s

</div>

`,
		iacTableHeader,
		getIacTableContent(iacRows, so))
}

func (so *StandardOutput) Footer() string {
	return fmt.Sprintf(`
<div align="center">

%s

</div>
`, CommentGeneratedByFrogbot)
}

func (so *StandardOutput) Seperator() string {
	return "<br>"
}

func (so *StandardOutput) FormattedSeverity(severity, applicability string) string {
	return fmt.Sprintf("%s%8s", getSeverityTag(IconName(severity), applicability), severity)
}

func (so *StandardOutput) UntitledForJasMsg() string {
	msg := ""
	if !so.entitledForJas {
		msg =
			`
<div align="center">

**Frogbot** also supports **Contextual Analysis**. This feature is included as part of the [JFrog Advanced Security](https://jfrog.com/xray/) package, which isn't enabled on your system.

</div>
`
	}
	return msg
}
