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

var applicabilityColorMap = map[string]string{
	"applicable":     "#FF7377",
	"not applicable": "#3CB371",
	"undetermined":   "orange",
}

// The OutputWriter interface allows Frogbot output to be written in an appropriate way for each git provider.
// Some git providers support markdown only partially, whereas others support it fully.
type OutputWriter interface {
	TableRow(vulnerability formats.VulnerabilityOrViolationRow) string
	NoVulnerabilitiesTitle() string
	VulnerabiltiesTitle() string
	Header() string
	Content(vulnerabilitiesRows []formats.VulnerabilityOrViolationRow) string
	Footer() string
	Seperator() string
	FormattedSeverity(severity string) string
	IsFrogbotResultComment(comment string) bool
	EntitledForJas() bool
	SetEntitledForJas(entitled bool)
	VcsProvider() vcsutils.VcsProvider
	SetVcsProvider(provider vcsutils.VcsProvider)
}

func GetCompatibleOutputWriter(provider vcsutils.VcsProvider) OutputWriter {
	switch provider {
	case vcsutils.BitbucketServer:
		return &SimplifiedOutput{vcsProvider: provider}
	default:
		return &StandardOutput{vcsProvider: provider}
	}
}

func JasMsg(entitled bool) string {
	msg := ""
	if !entitled {
		msg = "\n\n--- \n* **Frogbot** also supports the [‘Contextual Analysis’](https://jfrog.com/security-and-compliance/) feature, which is included as part of the ‘Advanced Security’ package.\nThis package isn't enabled on your system."
	}
	return msg
}

func createVulnerabilityDescription(vulnerabilityDetails *formats.VulnerabilityOrViolationRow, provider vcsutils.VcsProvider) string {
	var cves []string
	for _, cve := range vulnerabilityDetails.Cves {
		cves = append(cves, cve.Id)
	}
	if vulnerabilityDetails.JfrogResearchInformation == nil {
		vulnerabilityDetails.JfrogResearchInformation = &formats.JfrogResearchInformation{Details: vulnerabilityDetails.Summary}
	}
	if vulnerabilityDetails.Applicable != "" && vulnerabilityDetails.Applicable != "Undetermined" {
		return fmt.Sprintf(vulnerabilityDetailsCommentWithJas,
			utils.GetSeverity(vulnerabilityDetails.Severity, vulnerabilityDetails.Applicable).Emoji(),
			vulnerabilityDetails.Severity,
			formattedApplicabilityText(vulnerabilityDetails.Applicable, provider),
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

func createTableRow(vulnerability formats.VulnerabilityOrViolationRow, writer OutputWriter) string {
	var directDependencies strings.Builder
	if len(vulnerability.Components) > 0 {
		for _, dependency := range vulnerability.Components {
			directDependencies.WriteString(fmt.Sprintf("%s:%s%s", dependency.Name, dependency.Version, writer.Seperator()))
		}
	}

	row := fmt.Sprintf("| %s | ", writer.FormattedSeverity(vulnerability.Severity))
	if writer.EntitledForJas() {
		row += formattedApplicabilityText(vulnerability.Applicable, writer.VcsProvider()) + " |"
	}
	row += fmt.Sprintf("%s | %s | %s |",
		strings.TrimSuffix(directDependencies.String(), writer.Seperator()),
		fmt.Sprintf("%s:%s", vulnerability.ImpactedDependencyName, vulnerability.ImpactedDependencyVersion),
		strings.Join(vulnerability.FixedVersions, writer.Seperator()),
	)
	return row
}

func getTableContent(vulnerabilitiesRows []formats.VulnerabilityOrViolationRow, writer OutputWriter) string {
	var tableContent string
	for _, vulnerability := range vulnerabilitiesRows {
		tableContent += "\n" + writer.TableRow(vulnerability)
	}
	return tableContent
}

func formattedApplicabilityText(text string, provider vcsutils.VcsProvider) string {
	applicabilityColor := applicabilityColorMap[strings.ToLower(text)]
	var formattedText string
	switch provider {
	case vcsutils.GitHub, vcsutils.GitLab:
		formattedText = fmt.Sprintf("$\\color{%s}{\\textsf{%s}}$", applicabilityColor, text)
	case vcsutils.AzureRepos:
		formattedText = fmt.Sprintf("<span style=\"color: %s;\">%s</span>", applicabilityColor, text)
	default:
		formattedText = strings.ToUpper(fmt.Sprintf("**%s**", text))
	}
	return formattedText
}
