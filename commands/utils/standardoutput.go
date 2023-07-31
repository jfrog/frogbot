package utils

import (
	"fmt"
	"github.com/jfrog/froggit-go/vcsutils"
	"github.com/jfrog/jfrog-cli-core/v2/xray/formats"
	"strings"
)

type StandardOutput struct {
	showCaColumn   bool
	entitledForJas bool
	vcsProvider    vcsutils.VcsProvider
}

func (so *StandardOutput) VulnerabilitiesTableRow(vulnerability formats.VulnerabilityOrViolationRow) string {
	var directDependencies strings.Builder
	for _, dependency := range vulnerability.Components {
		directDependencies.WriteString(fmt.Sprintf("%s:%s%s", dependency.Name, dependency.Version, so.Seperator()))
	}

	row := fmt.Sprintf("| %s | ", so.FormattedSeverity(vulnerability.Severity, vulnerability.Applicable))
	if so.showCaColumn {
		row += vulnerability.Applicable + " |"
	}
	row += fmt.Sprintf("%s | %s | %s |",
		strings.TrimSuffix(directDependencies.String(), so.Seperator()),
		fmt.Sprintf("%s:%s", vulnerability.ImpactedDependencyName, vulnerability.ImpactedDependencyVersion),
		strings.Join(vulnerability.FixedVersions, so.Seperator()),
	)
	return row
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

func (so *StandardOutput) IsFrogbotResultComment(comment string) bool {
	return strings.Contains(comment, GetIconTag(NoVulnerabilityPrBannerSource)) ||
		strings.Contains(comment, GetIconTag(VulnerabilitiesPrBannerSource)) ||
		strings.Contains(comment, GetIconTag(NoVulnerabilityMrBannerSource)) ||
		strings.Contains(comment, GetIconTag(VulnerabilitiesMrBannerSource))
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

func (so *StandardOutput) VulnerabilitiesContent(vulnerabilities []formats.VulnerabilityOrViolationRow) string {
	if len(vulnerabilities) == 0 {
		return ""
	}
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
		getVulnerabilitiesTableHeader(so.showCaColumn),
		getVulnerabilitiesTableContent(vulnerabilities, so)))
	// Write details for each vulnerability
	for i := range vulnerabilities {
		if len(vulnerabilities) == 1 {
			contentBuilder.WriteString(fmt.Sprintf(`

%s

`, createVulnerabilityDescription(&vulnerabilities[i])))
			break
		}
		contentBuilder.WriteString(fmt.Sprintf(`
<details>
<summary> <b>%s %s</b> </summary>
<br>
%s

</details>

`,
			vulnerabilities[i].ImpactedDependencyName,
			vulnerabilities[i].ImpactedDependencyVersion,
			createVulnerabilityDescription(&vulnerabilities[i])))
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
	return "<br><br>"
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

**Frogbot** also supports **Contextual Analysis, Secret Detection and IaC Vulnerabilities Scanning**. This features are included as part of the [JFrog Advanced Security](https://jfrog.com/xray/) package, which isn't enabled on your system.

</div>
`
	}
	return msg
}
