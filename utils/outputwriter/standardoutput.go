package outputwriter

import (
	"fmt"
	"strings"

	"github.com/jfrog/froggit-go/vcsutils"
	"github.com/jfrog/jfrog-cli-core/v2/xray/formats"
)

type StandardOutput struct {
	showCaColumn   bool
	entitledForJas bool
	vcsProvider    vcsutils.VcsProvider
}

func (so *StandardOutput) VulnerabilitiesTableRow(vulnerability formats.VulnerabilityOrViolationRow) string {
	var directDependencies strings.Builder
	for _, dependency := range vulnerability.Components {
		directDependencies.WriteString(fmt.Sprintf("%s:%s%s", dependency.Name, dependency.Version, so.Separator()))
	}

	row := fmt.Sprintf("| %s | ", so.FormattedSeverity(vulnerability.Severity, vulnerability.Applicable))
	if so.showCaColumn {
		row += vulnerability.Applicable + " | "
	}
	cves := getTableRowCves(vulnerability, so)
	fixedVersions := GetTableRowsFixedVersions(vulnerability, so)
	row += fmt.Sprintf("%s | %s | %s | %s |",
		strings.TrimSuffix(directDependencies.String(), so.Separator()),
		fmt.Sprintf("%s:%s", vulnerability.ImpactedDependencyName, vulnerability.ImpactedDependencyVersion),
		fixedVersions,
		cves,
	)
	return row
}

func (so *StandardOutput) NoVulnerabilitiesTitle() string {
	if so.vcsProvider == vcsutils.GitLab {
		return GetBanner(NoVulnerabilityMrBannerSource)
	}
	return GetBanner(NoVulnerabilityPrBannerSource)
}

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
		cves := getCveIdSliceFromCveRows(vulnerabilities[i].Cves)
		if len(vulnerabilities) == 1 {
			contentBuilder.WriteString(fmt.Sprintf(`

%s

`, createVulnerabilityDescription(&vulnerabilities[i], cves)))
			break
		}
		contentBuilder.WriteString(fmt.Sprintf(`
<details>
<summary> <b>%s%s %s</b> </summary>
<br>
%s

</details>

`,
			getVulnerabilityCvesPrefix(vulnerabilities[i].Cves),
			vulnerabilities[i].ImpactedDependencyName,
			vulnerabilities[i].ImpactedDependencyVersion,
			createVulnerabilityDescription(&vulnerabilities[i], cves)))
	}
	return contentBuilder.String()
}

func (so *StandardOutput) ApplicableCveReviewContent(severity, finding, fullDetails, cve, cveDetails, impactedDependency, remediation string) string {
	var contentBuilder strings.Builder
	contentBuilder.WriteString(fmt.Sprintf(`
## 📦🔍 Contextual Analysis CVE Vulnerability

<div align="center">

%s

</div>

<details>
<summary> <b>Description</b> </summary>
<br>

%s

</details>

<details>
<summary> <b>CVE details</b> </summary>
<br>

%s

</details>

`,
		GetApplicabilityMarkdownDescription(so.FormattedSeverity(severity, "Applicable"), cve, impactedDependency, finding),
		fullDetails,
		cveDetails))
	if len(remediation) > 0 {
		contentBuilder.WriteString(fmt.Sprintf(`
<details>
<summary> <b>Remediation</b> </summary>
<br>

%s

</details>

`,
			remediation))
	}

	return contentBuilder.String()
}

func (so *StandardOutput) IacReviewContent(severity, finding, fullDetails string) string {
	return fmt.Sprintf(`
## 🛠️ Infrastructure as Code (Iac) Vulnerability

<div align="center">

%s

</div>

<details>
<summary> <b>Full description</b> </summary>
<br>

%s

</details>

`,
		GetJasMarkdownDescription(so.FormattedSeverity(severity, "Applicable"), finding),
		fullDetails)
}

func (so *StandardOutput) SastReviewContent(severity, finding, fullDetails string, codeFlows [][]formats.Location) string {
	var contentBuilder strings.Builder
	contentBuilder.WriteString(fmt.Sprintf(`
## 🎯 Static Application Security Testing (SAST) Vulnerability 
	
<div align="center">

%s

</div>

<details>
<summary> <b>Full description</b> </summary>
<br>

%s

</details>

`,
		GetJasMarkdownDescription(so.FormattedSeverity(severity, "Applicable"), finding),
		fullDetails,
	))

	if len(codeFlows) > 0 {
		contentBuilder.WriteString(`

<details>
<summary><b>Code Flows</b> </summary>

`)
		for _, flow := range codeFlows {
			contentBuilder.WriteString(`

<details>
<summary><b>Vulnerable data flow analysis result</b> </summary>
<br>
`)
			for _, location := range flow {
				contentBuilder.WriteString(fmt.Sprintf(`
%s %s (at %s line %d)
`,
					"↘️",
					MarkAsQuote(location.Snippet),
					location.File,
					location.StartLine,
				))
			}

			contentBuilder.WriteString(`

</details>

`,
			)
		}
		contentBuilder.WriteString(`

</details>

`,
		)
	}
	return contentBuilder.String()
}

func (so *StandardOutput) IacTableContent(iacRows []formats.SourceCodeRow) string {
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
---
<div align="center">

%s

</div>
`, CommentGeneratedByFrogbot)
}

func (so *StandardOutput) Separator() string {
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
