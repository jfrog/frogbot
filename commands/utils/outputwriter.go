package utils

import (
	"fmt"
	"github.com/jfrog/froggit-go/vcsutils"
	"github.com/jfrog/jfrog-cli-core/v2/xray/formats"
	"github.com/jfrog/jfrog-cli-core/v2/xray/utils"
	"strings"
)

const vulnerabilityDetailsComment = `
- **Severity:** %s %s
- **Package Name:** %s
- **Current Version:** %s
- **Fixed Version:** %s
- **CVEs:** %s

**Description:**

%s
`
const vulnerabilityDetailsCommentWithJas = `
- **Severity:** %s %s
- **Contextual Analysis:** %s
- **Package Name:** %s
- **Current Version:** %s
- **Fixed Version:** %s
- **CVEs:** %s

**Description:**

%s

**Remediation:**
%s
`

// The OutputWriter interface allows Frogbot output to be written in an appropriate way for each git provider.
// Some git providers support markdown only partially, whereas others support it fully.
type OutputWriter interface {
	TableRow(vulnerability formats.VulnerabilityOrViolationRow) string
	NoVulnerabilitiesTitle() string
	VulnerabiltiesTitle() string
	Header() string
	Content(vulnerabilitiesRows []formats.VulnerabilityOrViolationRow) string
	Footer() string
	IsFrogbotResultComment(comment string) bool
	SetEntitledForJas(entitled bool)
	EntitledForJas() bool
}

func GetCompatibleOutputWriter(provider vcsutils.VcsProvider) OutputWriter {
	if provider == vcsutils.BitbucketServer {
		return &SimplifiedOutput{}
	}
	return &StandardOutput{}
}

func JasMsg(entitled bool) string {
	msg := ""
	if !entitled {
		msg = "\n* **Frogbot** also supports the [‘Contextual Analysis’](https://jfrog.com/security-and-compliance/) feature, which is included as part of the ‘Advanced Security’ package.\nThis package isn't enabled on your system."
	}
	return msg
}

func createVulnerabilityDescription(vulnerabilityDetails *formats.VulnerabilityOrViolationRow) string {
	var cves []string
	for _, cve := range vulnerabilityDetails.Cves {
		cves = append(cves, cve.Id)
	}
	if vulnerabilityDetails.Applicable != "" {
		return fmt.Sprintf(vulnerabilityDetailsCommentWithJas,
			utils.GetSeverity(vulnerabilityDetails.Severity, vulnerabilityDetails.Applicable).Emoji(),
			vulnerabilityDetails.Severity,
			vulnerabilityDetails.Applicable,
			vulnerabilityDetails.ImpactedDependencyName,
			vulnerabilityDetails.ImpactedDependencyVersion,
			strings.Join(vulnerabilityDetails.FixedVersions, ","),
			strings.Join(cves, ", "),
			vulnerabilityDetails.JfrogResearchInformation.Details,
			vulnerabilityDetails.JfrogResearchInformation.Remediation)
	}
	return fmt.Sprintf(vulnerabilityDetailsComment,
		// When JAS isn't enabled, we want the Emoji that is related to applicable vulnerabilities.
		utils.GetSeverity(vulnerabilityDetails.Severity, utils.ApplicableStringValue).Emoji(),
		vulnerabilityDetails.Severity,
		vulnerabilityDetails.ImpactedDependencyName,
		vulnerabilityDetails.ImpactedDependencyVersion,
		strings.Join(vulnerabilityDetails.FixedVersions, ","),
		strings.Join(cves, ", "),
		vulnerabilityDetails.JfrogResearchInformation.Details)
}

func createTableRow(vulnerability formats.VulnerabilityOrViolationRow, seperator string, entitledForJas bool) string {
	var directDependencies strings.Builder
	if len(vulnerability.Components) > 0 {
		for _, dependency := range vulnerability.Components {
			directDependencies.WriteString(fmt.Sprintf("%s:%s%s", dependency.Name, dependency.Version, seperator))
		}
	}

	row := fmt.Sprintf("| %s%8s | ", GetSeverityTag(IconName(vulnerability.Severity)), vulnerability.Severity)
	if entitledForJas {
		row += vulnerability.Applicable + " "
	}
	row += fmt.Sprintf("| %s | %s | %s |",
		strings.TrimSuffix(directDependencies.String(), seperator),
		fmt.Sprintf("%s:%s", vulnerability.ImpactedDependencyName, vulnerability.ImpactedDependencyVersion),
		strings.Join(vulnerability.FixedVersions, seperator),
	)
	return row
}

func getTableContent(vulnerabilitiesRows []formats.VulnerabilityOrViolationRow, writer OutputWriter) string {
	var tableContent string
	for _, vulnerability := range vulnerabilitiesRows {
		tableContent += writer.TableRow(vulnerability)
	}
	return tableContent
}
