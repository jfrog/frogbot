package utils

import (
	"fmt"
	"github.com/jfrog/froggit-go/vcsutils"
	"github.com/jfrog/jfrog-cli-core/v2/xray/formats"
	"github.com/jfrog/jfrog-cli-core/v2/xray/utils"
	"strings"
)

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
	VulnerabilitiesContent(vulnerabilitiesRows []formats.VulnerabilityOrViolationRow) string
	IacContent(iacRows []formats.IacSecretsRow) string
	Footer() string
	Seperator() string
	FormattedSeverity(severity, applicability string) string
	IsFrogbotResultComment(comment string) bool
	EntitledForJas() bool
	SetEntitledForJas(entitled bool)
	VcsProvider() vcsutils.VcsProvider
	SetVcsProvider(provider vcsutils.VcsProvider)
	UntitledForJasMsg() string
}

func GetCompatibleOutputWriter(provider vcsutils.VcsProvider) OutputWriter {
	switch provider {
	case vcsutils.BitbucketServer:
		return &SimplifiedOutput{vcsProvider: provider}
	default:
		return &StandardOutput{vcsProvider: provider}
	}
}

type descriptionBullet struct {
	title string
	value string
}

func createVulnerabilityDescription(vulnerabilityDetails *formats.VulnerabilityOrViolationRow, provider vcsutils.VcsProvider) string {
	var cves []string
	for _, cve := range vulnerabilityDetails.Cves {
		cves = append(cves, cve.Id)
	}
	if vulnerabilityDetails.JfrogResearchInformation == nil {
		vulnerabilityDetails.JfrogResearchInformation = &formats.JfrogResearchInformation{Details: vulnerabilityDetails.Summary}
	}

	descriptionBullets := []descriptionBullet{
		{title: "**Severity**", value: fmt.Sprintf("%s %s", utils.GetSeverity(vulnerabilityDetails.Severity, utils.ApplicableStringValue).Emoji(), vulnerabilityDetails.Severity)},
		{title: "**Contextual Analysis:**", value: formattedApplicabilityText(vulnerabilityDetails.Applicable, provider)},
		{title: "**Package Name:**", value: vulnerabilityDetails.ImpactedDependencyName},
		{title: "**Current Version:**", value: vulnerabilityDetails.ImpactedDependencyVersion},
		{title: "**Fixed Version:**", value: strings.Join(vulnerabilityDetails.FixedVersions, ",")},
		{title: "**CVEs:**", value: strings.Join(cves, ", ")},
	}

	var descriptionBuilder strings.Builder
	descriptionBuilder.WriteString("\n")
	// Write the bullets of the description
	for _, bullet := range descriptionBullets {
		if strings.TrimSpace(bullet.value) != "" {
			descriptionBuilder.WriteString(fmt.Sprintf("- %s %s\n", bullet.title, bullet.value))
		}
	}

	// Write description if exists:
	if vulnerabilityDetails.JfrogResearchInformation.Details != "" {
		descriptionBuilder.WriteString(fmt.Sprintf("\n**Description:**\n\n%s\n\n", vulnerabilityDetails.JfrogResearchInformation.Details))
	}

	// Write remediation if exists
	if vulnerabilityDetails.JfrogResearchInformation.Remediation != "" {
		descriptionBuilder.WriteString(fmt.Sprintf("**Remediation:**\n\n%s\n\n", vulnerabilityDetails.JfrogResearchInformation.Remediation))
	}

	return descriptionBuilder.String()
}

func getVulnerabilitiesTableContent(vulnerabilitiesRows []formats.VulnerabilityOrViolationRow, writer OutputWriter) string {
	var tableContent string
	for _, vulnerability := range vulnerabilitiesRows {
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
	if text == "" {
		return ""
	}
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
