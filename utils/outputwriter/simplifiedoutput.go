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
	row := fmt.Sprintf("| %s | ", smo.FormattedSeverity(vulnerability.Severity, vulnerability.Applicable, true))
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
## 📦 Vulnerable Dependencies
---

### ✍️ Summary 

%s %s

---
### 👇 Details
---

`,
		getVulnerabilitiesTableHeader(smo.showCaColumn),
		getVulnerabilitiesTableContent(vulnerabilities, smo)))
	for i := range vulnerabilities {
		contentBuilder.WriteString(fmt.Sprintf(`
#### %s%s %s

%s
`,
			getVulnerabilityCvesPrefix(vulnerabilities[i].Cves),
			vulnerabilities[i].ImpactedDependencyName,
			vulnerabilities[i].ImpactedDependencyVersion,
			createVulnerabilityDescription(&vulnerabilities[i])))
	}

	return contentBuilder.String()
}

func (smo *SimplifiedOutput) ApplicableCveReviewContent(severity, finding, fullDetails, cveDetails, remediation string) string {
	var contentBuilder strings.Builder
	contentBuilder.WriteString(fmt.Sprintf(`
## 📦🔍 Contextual Analysis CVE Vulnerability
	
%s

### Description
	
%s	

### CVE details

%s

`,
		GetJasMarkdownDescription(smo.FormattedSeverity(severity, "Applicable", false), finding),
		fullDetails,
		cveDetails))

	if len(remediation) > 0 {
		contentBuilder.WriteString(fmt.Sprintf(`
### Remediation
	
%s	

`,
			remediation))
	}
	return contentBuilder.String()
}

func (smo *SimplifiedOutput) IacReviewContent(severity, finding, fullDetails string) string {
	return fmt.Sprintf(`
## 🛠️ Infrastructure as Code (Iac) Vulnerability
	
%s

### 👇 Details

%s	

`,
		GetJasMarkdownDescription(smo.FormattedSeverity(severity, "Applicable", false), finding),
		fullDetails)
}

func (smo *SimplifiedOutput) SastReviewContent(severity, finding, fullDetails string, codeFlows [][]formats.Location) string {
	var contentBuilder strings.Builder
	contentBuilder.WriteString(fmt.Sprintf(`
## 🎯 Static Application Security Testing (SAST) Vulnerability
	
%s

---
### Full description

%s

---
### Code Flows

`,
		GetJasMarkdownDescription(smo.FormattedSeverity(severity, "Applicable", false), finding),
		fullDetails,
	))

	if len(codeFlows) > 0 {
		for _, flow := range codeFlows {
			contentBuilder.WriteString(`

---
Vulnerable data flow analysis result:
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

---

`,
			)
		}
	}
	return contentBuilder.String()
}

func (smo *SimplifiedOutput) IacTableContent(iacRows []formats.SourceCodeRow) string {
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
	return fmt.Sprintf("\n%s", CommentGeneratedByFrogbot)
}

func (smo *SimplifiedOutput) Separator() string {
	return ", "
}

func (smo *SimplifiedOutput) FormattedSeverity(severity, _ string, _ bool) string {
	return severity
}

func (smo *SimplifiedOutput) UntitledForJasMsg() string {
	msg := ""
	if !smo.entitledForJas {
		msg = "\n\n**Frogbot** also supports **Contextual Analysis, Secret Detection and IaC Vulnerabilities Scanning**. This features are included as part of the [JFrog Advanced Security](https://jfrog.com/xray/) package, which isn't enabled on your system.\n"
	}
	return msg
}
