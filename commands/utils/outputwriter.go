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
	"undetermined":   "",
}

// The OutputWriter interface allows Frogbot output to be written in an appropriate way for each git provider.
// Some git providers support markdown only partially, whereas others support it fully.
type OutputWriter interface {
	VulnerabilitiesTableRow(vulnerability formats.VulnerabilityOrViolationRow) string
	NoVulnerabilitiesTitle() string
	VulnerabiltiesTitle(isComment bool) string
	VulnerabilitiesTableHeader() string
	VulnerabilitiesContent(vulnerabilities []formats.VulnerabilityOrViolationRow) string
	IacContent(iacRows []formats.IacSecretsRow) string
	Footer() string
	Seperator() string
	FormattedSeverity(severity, applicability string) string
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
		msg = "\n\n--- \n* **Frogbot** also supports **Contextual Analysis, Infrastructure as Code Scanning and Secrets Detection**. These features are included as part of the [JFrog Advanced Security](https://jfrog.com/xray/) package, which isn't enabled on your system."
	}
	return msg
}

func createVulnerabilityDescription(vulnerability *formats.VulnerabilityOrViolationRow, provider vcsutils.VcsProvider) string {
	var cves []string
	for _, cve := range vulnerability.Cves {
		cves = append(cves, cve.Id)
	}

	if vulnerability.JfrogResearchInformation == nil {
		vulnerability.JfrogResearchInformation = &formats.JfrogResearchInformation{Details: vulnerability.Summary}
	}
	if vulnerability.Applicable != "" && vulnerability.Applicable != "Undetermined" {
		return fmt.Sprintf(vulnerabilityDetailsCommentWithJas,
			utils.GetSeverity(vulnerability.Severity, utils.ApplicableStringValue).Emoji(),
			vulnerability.Severity,
			formattedApplicabilityText(vulnerability.Applicable, provider),
			vulnerability.ImpactedDependencyName,
			vulnerability.ImpactedDependencyVersion,
			strings.Join(vulnerability.FixedVersions, ","),
			strings.Join(cves, ", "),
			vulnerability.JfrogResearchInformation.Details,
			vulnerability.JfrogResearchInformation.Remediation)
	}
	return fmt.Sprintf(vulnerabilityDetailsComment,
		utils.GetSeverity(vulnerability.Severity, utils.ApplicableStringValue).Emoji(),
		vulnerability.Severity,
		vulnerability.ImpactedDependencyName,
		vulnerability.ImpactedDependencyVersion,
		strings.Join(vulnerability.FixedVersions, ","),
		strings.Join(cves, ", "),
		vulnerability.JfrogResearchInformation.Details)
}

func getVulnerabilitiesTableContent(vulnerabilities []formats.VulnerabilityOrViolationRow, writer OutputWriter) string {
	var tableContent string
	for _, vulnerability := range vulnerabilities {
		tableContent += "\n" + writer.VulnerabilitiesTableRow(vulnerability)
	}
	return tableContent
}

func createVulnerabilitiesTableRow(vulnerability formats.VulnerabilityOrViolationRow, writer OutputWriter) string {
	var directDependencies strings.Builder
	if len(vulnerability.Components) > 0 {
		for _, dependency := range vulnerability.Components {
			directDependencies.WriteString(fmt.Sprintf("%s:%s%s", dependency.Name, dependency.Version, writer.Seperator()))
		}
	}

	row := fmt.Sprintf("| %s | ", writer.FormattedSeverity(vulnerability.Severity, vulnerability.Applicable))
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

func getIacTableContent(iacRows []formats.IacSecretsRow, writer OutputWriter) string {
	var tableContent string
	for _, iac := range iacRows {
		tableContent += fmt.Sprintf("\n| %s | %s | %s | %s |", writer.FormattedSeverity(iac.Severity, utils.ApplicableStringValue), iac.File, iac.LineColumn, iac.Text)
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

func MarkdownComment(text string) string {
	return fmt.Sprintf("\n[comment]: <> (%s)\n", text)
}
