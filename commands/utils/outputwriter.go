package utils

import (
	"fmt"
	"github.com/jfrog/froggit-go/vcsutils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-core/v2/xray/formats"
	"github.com/jfrog/jfrog-cli-core/v2/xray/utils"
	"strings"
)

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

func createVulnerabilityDescription(vulnerability *formats.VulnerabilityOrViolationRow) string {
	var cves []string
	for _, cve := range vulnerability.Cves {
		cves = append(cves, cve.Id)
	}

	if vulnerability.JfrogResearchInformation == nil {
		vulnerability.JfrogResearchInformation = &formats.JfrogResearchInformation{Details: vulnerability.Summary}
	}

	cvesTitle := "**CVE:**"
	if len(cves) > 1 {
		cvesTitle = "**CVEs:**"
	}

	fixedVersionsTitle := "**Fixed Version:**"
	if len(vulnerability.FixedVersions) > 1 {
		fixedVersionsTitle = "**Fixed Versions:**"
	}

	descriptionBullets := []descriptionBullet{
		{title: "**Severity**", value: fmt.Sprintf("%s %s", utils.GetSeverity(vulnerability.Severity, utils.ApplicableStringValue).Emoji(), vulnerability.Severity)},
		{title: "**Contextual Analysis:**", value: vulnerability.Applicable},
		{title: "**Package Name:**", value: vulnerability.ImpactedDependencyName},
		{title: "**Current Version:**", value: vulnerability.ImpactedDependencyVersion},
		{title: fixedVersionsTitle, value: strings.Join(vulnerability.FixedVersions, ",")},
		{title: cvesTitle, value: strings.Join(cves, ", ")},
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
	if vulnerability.JfrogResearchInformation.Details != "" {
		descriptionBuilder.WriteString(fmt.Sprintf("\n**Description:**\n\n%s\n\n", vulnerability.JfrogResearchInformation.Details))
	}

	// Write remediation if exists
	if vulnerability.JfrogResearchInformation.Remediation != "" {
		descriptionBuilder.WriteString(fmt.Sprintf("**Remediation:**\n\n%s\n\n", vulnerability.JfrogResearchInformation.Remediation))
	}

	return descriptionBuilder.String()
}

func getVulnerabilitiesTableContent(vulnerabilities []formats.VulnerabilityOrViolationRow, writer OutputWriter) string {
	var tableContent string
	for _, vulnerability := range vulnerabilities {
		tableContent += "\n" + writer.VulnerabilitiesTableRow(vulnerability)
	}
	return tableContent
}

func getIacTableContent(iacRows []formats.IacSecretsRow, writer OutputWriter) string {
	var tableContent string
	for _, iac := range iacRows {
		tableContent += fmt.Sprintf("\n| %s | %s | %s | %s |", writer.FormattedSeverity(iac.Severity, utils.ApplicableStringValue), iac.File, iac.LineColumn, iac.Text)
	}
	return tableContent
}

func MarkdownComment(text string) string {
	return fmt.Sprintf("\n[comment]: <> (%s)\n", text)
}

func GetAggregatedPullRequestTitle(tech coreutils.Technology) string {
	if tech.ToString() == "" {
		return FrogbotPullRequestTitlePrefix + " Update dependencies"
	}
	return fmt.Sprintf("%s Update %s dependencies", FrogbotPullRequestTitlePrefix, tech.ToFormal())
}
