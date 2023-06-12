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

func (so *StandardOutput) TableRow(vulnerability formats.VulnerabilityOrViolationRow) string {
	return createTableRow(vulnerability, so)
}

func (so *StandardOutput) NoVulnerabilitiesTitle() string {
	return GetBanner(NoVulnerabilityBannerSource)
}

func (so *StandardOutput) VulnerabiltiesTitle() string {
	return GetBanner(VulnerabilitiesBannerSource)
}

func (so *StandardOutput) Header() string {
	if so.entitledForJas {
		return tableHeaderWithJas
	}
	return tableHeader
}

func (so *StandardOutput) IsFrogbotResultComment(comment string) bool {
	return strings.Contains(comment, GetIconTag(NoVulnerabilityBannerSource)) || strings.Contains(comment, GetIconTag(VulnerabilitiesBannerSource))
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

func (so *StandardOutput) Content(vulnerabilitiesRows []formats.VulnerabilityOrViolationRow) string {
	var contentBuilder strings.Builder
	// Write summary table part
	contentBuilder.WriteString(fmt.Sprintf(`
## Summary

<div align="center">

%s %s

</div>

## Details

`,
		so.Header(),
		getTableContent(vulnerabilitiesRows, so)))
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

func (so *StandardOutput) Footer() string {
	return fmt.Sprintf(`
---

<div align="center">

%s

</div>
`, CommentGeneratedByFrogbot)
}

func (so *StandardOutput) Seperator() string {
	return "<br>"
}

func (so *StandardOutput) FormattedSeverity(severity string) string {
	return fmt.Sprintf("%s%8s", GetSeverityTag(IconName(severity)), severity)
}
