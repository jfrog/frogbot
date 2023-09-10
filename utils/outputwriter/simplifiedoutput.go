package outputwriter

import (
	"fmt"
	"strings"

	"github.com/jfrog/froggit-go/vcsutils"
	"github.com/jfrog/jfrog-cli-core/v2/xray/formats"
	xrayutils "github.com/jfrog/jfrog-cli-core/v2/xray/utils"
	"github.com/owenrumney/go-sarif/v2/sarif"
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
	row += fmt.Sprintf(" %s | %s | %s |",
		firstDirectDependency,
		fmt.Sprintf("%s:%s", vulnerability.ImpactedDependencyName, vulnerability.ImpactedDependencyVersion),
		strings.Join(vulnerability.FixedVersions, smo.Separator()),
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
		cves := getCveIdSliceFromCveRows(vulnerabilities[i].Cves)
		contentBuilder.WriteString(fmt.Sprintf(`
#### %s%s %s

%s

`,
			getDescriptionBulletCveTitle(cves),
			vulnerabilities[i].ImpactedDependencyName,
			vulnerabilities[i].ImpactedDependencyVersion,
			createVulnerabilityDescription(&vulnerabilities[i], cves)))
	}

	return contentBuilder.String()
}

func (smo *SimplifiedOutput) JasResultSummary(applicability, iac, sast *sarif.Run) string {
	if len(applicability.Results) == 0 && len(iac.Results) == 0 && len(sast.Results) == 0 {
		return ""
	}
	var contentBuilder strings.Builder
	contentBuilder.WriteString(`
	## JFrog Advanced Security Finding:
	
	`)
	if len(applicability.Results) > 0 {
		contentBuilder.WriteString(getSummaryRowContent(applicability, "📦🔍", "Applicable Cve Vulnerability"))
	}
	if len(iac.Results) > 0 {
		contentBuilder.WriteString(getSummaryRowContent(iac, "🛠️", "Infrastructure as Code Vulnerability"))
	}
	if len(sast.Results) > 0 {
		contentBuilder.WriteString(getSummaryRowContent(sast, "🔐", "Static Application Security Testing (SAST) Vulnerability"))
	}

	return contentBuilder.String()
}

func (smo *SimplifiedOutput) ApplicableCveReviewContent(severity, finding, fullDetails, cveDetails string) string {
	return fmt.Sprintf(`
## 📦🔍 Applicable dependency CVE Vulnerability %s
	
Finding: %s

### 👇 Details

#### Description
	
%s	

#### Cve details

%s

`,
		smo.FormattedSeverity(severity, "Applicable"),
		finding,
		fullDetails,
		cveDetails)
}

func (smo *SimplifiedOutput) IacReviewContent(severity, finding, fullDetails string) string {
	return fmt.Sprintf(`
## 🛠️ Infrastructure as Code Vulnerability %s
	
Finding: %s

### 👇 Details

%s	

`,
		smo.FormattedSeverity(severity, "Applicable"),
		finding,
		fullDetails)
}

func (smo *SimplifiedOutput) SastReviewContent(severity, finding, fullDetails string, codeFlows []*sarif.CodeFlow) string {
	var contentBuilder strings.Builder
	contentBuilder.WriteString(fmt.Sprintf(`
## 🔐 Static Application Security Testing (SAST) Vulnerability %s
	
Finding: %s

### 👇 Details

---
#### Full description

%s

---
#### Vulnerable data flows

`,
		smo.FormattedSeverity(severity, "Applicable"),
		finding,
		fullDetails,
	))

	if len(codeFlows) > 0 {
		dataFlowId := 1
		for _, codeFlow := range codeFlows {
			for _, threadFlow := range codeFlow.ThreadFlows {
				contentBuilder.WriteString(fmt.Sprintf(`

---
%d. Vulnerable data flow analysis result:
`,
					dataFlowId,
				))

				for i, threadFlowLocation := range threadFlow.Locations {
					contentBuilder.WriteString(fmt.Sprintf(`
	%d. %s (at %s line %d)
`,
						i+1,
						xrayutils.GetLocationSnippet(threadFlowLocation.Location),
						xrayutils.GetLocationFileName(threadFlowLocation.Location),
						xrayutils.GetLocationStartLine(threadFlowLocation.Location),
					))
				}

				contentBuilder.WriteString(`


---

`,
				)
				dataFlowId = dataFlowId + 1
			}
		}
	}
	return contentBuilder.String()
}

func (smo *SimplifiedOutput) IacContent(iacRows []formats.SourceCodeRow) string {
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

func (smo *SimplifiedOutput) Separator() string {
	return ", "
}

func (smo *SimplifiedOutput) FormattedSeverity(severity, _ string) string {
	return severity
}

func (smo *SimplifiedOutput) UntitledForJasMsg() string {
	msg := ""
	if !smo.entitledForJas {
		msg = "\n\n**Frogbot** also supports **Contextual Analysis, Secret Detection and IaC Vulnerabilities Scanning**. This features are included as part of the [JFrog Advanced Security](https://jfrog.com/xray/) package, which isn't enabled on your system."
	}
	return msg
}
