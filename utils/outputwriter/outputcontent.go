package outputwriter

import (
	"fmt"
	"strings"

	"github.com/jfrog/froggit-go/vcsutils"
	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
)

const (
	FrogbotTitlePrefix      = "[🐸 Frogbot]"
	FrogbotRepoUrl          = "https://github.com/jfrog/frogbot"
	FrogbotDocumentationUrl = "https://docs.jfrog-applications.jfrog.io/jfrog-applications/frogbot"
	ReviewCommentId         = "FrogbotReviewComment"

	vulnerableDependenciesTitle                   = "📦 Vulnerable Dependencies"
	vulnerableDependenciesResearchDetailsSubTitle = "🔬 Research Details"

	contextualAnalysisTitle = "📦🔍 Contextual Analysis CVE Vulnerability"
	//#nosec G101 -- not a secret
	secretsTitle = "🗝️ Secret Detected"
	iacTitle     = "🛠️ Infrastructure as Code Vulnerability"
	sastTitle    = "🎯 Static Application Security Testing (SAST) Vulnerability"
)

var (
	CommentGeneratedByFrogbot    = MarkAsLink("🐸 JFrog Frogbot", FrogbotDocumentationUrl)
	jasFeaturesMsgWhenNotEnabled = MarkAsBold("Frogbot") + " also supports " + MarkAsBold("Contextual Analysis, Secret Detection, IaC and SAST Vulnerabilities Scanning") + ". This features are included as part of the " + MarkAsLink("JFrog Advanced Security", "https://jfrog.com/advanced-security") + " package, which isn't enabled on your system."
)

// Adding markdown prefix to identify Frogbot comment and a footer with the link to the documentation
func GetFrogbotCommentBaseDecorator(writer OutputWriter) CommentDecorator {
	return func(_ int, content string) string {
		comment := strings.Builder{}
		comment.WriteString(MarkdownComment(ReviewCommentId))
		WriteContent(&comment, content, footer(writer))
		return comment.String()
	}
}

// Adding a banner, custom title and untitled Jas message to the content
func GetPRSummaryMainCommentDecorator(issuesExists, isComment bool, writer OutputWriter) CommentDecorator {
	return func(_ int, content string) string {
		comment := strings.Builder{}
		comment.WriteString(writer.Image(getPRSummaryBanner(issuesExists, isComment, writer.VcsProvider())))
		customCommentTitle := writer.PullRequestCommentTitle()
		if customCommentTitle != "" {
			WriteContent(&comment, writer.MarkAsTitle(MarkAsBold(customCommentTitle), 2))
		}
		if issuesExists {
			WriteContent(&comment, content)
		}
		WriteContent(&comment, untitledForJasMsg(writer))
		return comment.String()
	}
}

func GetPRSummaryContent(contentForComments []string, issuesExists, isComment bool, writer OutputWriter) (comments []string) {
	return ConvertContentToComments(contentForComments, writer, func(commentCount int, content string) string {
		if commentCount == 0 {
			content = GetPRSummaryMainCommentDecorator(issuesExists, isComment, writer)(commentCount, content)
		}
		return GetFrogbotCommentBaseDecorator(writer)(commentCount, content)
	})
}

func getPRSummaryBanner(issuesExists, isComment bool, provider vcsutils.VcsProvider) ImageSource {
	if !isComment {
		return fixCVETitleSrc(provider)
	}
	if !issuesExists {
		return NoIssuesTitleSrc(provider)
	}
	return PRSummaryCommentTitleSrc(provider)
}

// TODO: remove this at the next release, it's not used anymore and replaced by adding ReviewCommentId comment to the content
func IsFrogbotSummaryComment(writer OutputWriter, content string) bool {
	client := writer.VcsProvider()
	return strings.Contains(content, GetBanner(NoIssuesTitleSrc(client))) ||
		strings.Contains(content, GetSimplifiedTitle(NoIssuesTitleSrc(client))) ||
		strings.Contains(content, GetBanner(PRSummaryCommentTitleSrc(client))) ||
		strings.Contains(content, GetSimplifiedTitle(PRSummaryCommentTitleSrc(client)))
}

func NoIssuesTitleSrc(vcsProvider vcsutils.VcsProvider) ImageSource {
	if vcsProvider == vcsutils.GitLab {
		return NoVulnerabilityMrBannerSource
	}
	return NoVulnerabilityPrBannerSource
}

func PRSummaryCommentTitleSrc(vcsProvider vcsutils.VcsProvider) ImageSource {
	if vcsProvider == vcsutils.GitLab {
		return VulnerabilitiesMrBannerSource
	}
	return VulnerabilitiesPrBannerSource
}

func fixCVETitleSrc(vcsProvider vcsutils.VcsProvider) ImageSource {
	if vcsProvider == vcsutils.GitLab {
		return VulnerabilitiesFixMrBannerSource
	}
	return VulnerabilitiesFixPrBannerSource
}

func untitledForJasMsg(writer OutputWriter) string {
	if writer.AvoidExtraMessages() || writer.IsEntitledForJas() {
		return ""
	}
	return writer.MarkAsDetails("Note:", 0, fmt.Sprintf("%s\n%s", SectionDivider(), writer.MarkInCenter(jasFeaturesMsgWhenNotEnabled)))
}

func footer(writer OutputWriter) string {
	return fmt.Sprintf("%s\n%s", SectionDivider(), writer.MarkInCenter(CommentGeneratedByFrogbot))
}

func VulnerabilitiesContent(vulnerabilities []formats.VulnerabilityOrViolationRow, writer OutputWriter) (content []string) {
	if len(vulnerabilities) == 0 {
		return []string{}
	}
	content = append(content, writer.MarkAsTitle(vulnerableDependenciesTitle, 2))
	content = append(content, vulnerabilitiesSummaryContent(vulnerabilities, writer))
	content = append(content, vulnerabilityDetailsContent(vulnerabilities, writer)...)
	return
}

func vulnerabilitiesSummaryContent(vulnerabilities []formats.VulnerabilityOrViolationRow, writer OutputWriter) string {
	var contentBuilder strings.Builder
	WriteContent(&contentBuilder,
		writer.MarkAsTitle("✍️ Summary", 3),
		writer.MarkInCenter(getVulnerabilitiesSummaryTable(vulnerabilities, writer)),
	)
	return contentBuilder.String()
}

func getVulnerabilitiesSummaryTable(vulnerabilities []formats.VulnerabilityOrViolationRow, writer OutputWriter) string {
	// Construct table
	columns := []string{"SEVERITY"}
	if writer.IsShowingCaColumn() {
		columns = append(columns, "CONTEXTUAL ANALYSIS")
	}
	columns = append(columns, "DIRECT DEPENDENCIES", "IMPACTED DEPENDENCY", "FIXED VERSIONS", "CVES")
	table := NewMarkdownTable(columns...).SetDelimiter(writer.Separator())
	if _, ok := writer.(*SimplifiedOutput); ok {
		// The values in this cell can be potentially large, since SimplifiedOutput does not support tags, we need to show each value in a separate row.
		// It means that the first row will show the full details, and the following rows will show only the direct dependency.
		// It makes it easier to read the table and less crowded with text in a single cell that could be potentially large.
		table.GetColumnInfo("DIRECT DEPENDENCIES").ColumnType = MultiRowColumn
	}
	// Construct rows
	for _, vulnerability := range vulnerabilities {
		row := []CellData{{writer.FormattedSeverity(vulnerability.Severity, vulnerability.Applicable)}}
		if writer.IsShowingCaColumn() {
			row = append(row, NewCellData(vulnerability.Applicable))
		}
		row = append(row,
			getDirectDependenciesCellData("%s:%s", vulnerability.Components),
			NewCellData(fmt.Sprintf("%s %s", vulnerability.ImpactedDependencyName, vulnerability.ImpactedDependencyVersion)),
			NewCellData(vulnerability.FixedVersions...),
			getCveIdsCellData(vulnerability.Cves),
		)
		table.AddRowWithCellData(row...)
	}
	return table.Build()
}

func getDirectDependenciesCellData(format string, components []formats.ComponentRow) (dependencies CellData) {
	if len(components) == 0 {
		return NewCellData()
	}
	for _, component := range components {
		dependencies = append(dependencies, fmt.Sprintf(format, component.Name, component.Version))
	}
	return
}

func getCveIdsCellData(cveRows []formats.CveRow) (ids CellData) {
	if len(cveRows) == 0 {
		return NewCellData()
	}
	for _, cve := range cveRows {
		ids = append(ids, cve.Id)
	}
	return
}

type vulnerabilityOrViolationDetails struct {
	details           string
	title             string
	dependencyName    string
	dependencyVersion string
}

func vulnerabilityDetailsContent(vulnerabilities []formats.VulnerabilityOrViolationRow, writer OutputWriter) (content []string) {
	vulnerabilitiesWithDetails := getVulnerabilityWithDetails(vulnerabilities)
	if len(vulnerabilitiesWithDetails) == 0 {
		return
	}
	// Prepare content for each vulnerability details
	for i := range vulnerabilitiesWithDetails {
		if len(vulnerabilitiesWithDetails) == 1 {
			content = append(content, vulnerabilitiesWithDetails[i].details)
		} else {
			content = append(content, writer.MarkAsDetails(
				fmt.Sprintf(`%s %s %s`, vulnerabilitiesWithDetails[i].title,
					vulnerabilitiesWithDetails[i].dependencyName,
					vulnerabilitiesWithDetails[i].dependencyVersion),
				4, vulnerabilitiesWithDetails[i].details,
			))
		}
	}
	// Split content if it exceeds the size limit and decorate it with title
	return ConvertContentToComments(content, writer, func(commentCount int, detailsContent string) string {
		contentBuilder := strings.Builder{}
		WriteContent(&contentBuilder, writer.MarkAsTitle(vulnerableDependenciesResearchDetailsSubTitle, 3))
		WriteContent(&contentBuilder, detailsContent)
		return contentBuilder.String()
	})
}

func getVulnerabilityWithDetails(vulnerabilities []formats.VulnerabilityOrViolationRow) (vulnerabilitiesWithDetails []vulnerabilityOrViolationDetails) {
	for i := range vulnerabilities {
		vulDescriptionContent := createVulnerabilityResearchDescription(&vulnerabilities[i])
		if vulDescriptionContent == "" {
			// No content
			continue
		}
		vulnerabilitiesWithDetails = append(vulnerabilitiesWithDetails, vulnerabilityOrViolationDetails{
			details:           vulDescriptionContent,
			title:             getVulnerabilityDescriptionIdentifier(vulnerabilities[i].Cves, vulnerabilities[i].IssueId),
			dependencyName:    vulnerabilities[i].ImpactedDependencyName,
			dependencyVersion: vulnerabilities[i].ImpactedDependencyVersion,
		})
	}
	return
}

func createVulnerabilityResearchDescription(vulnerability *formats.VulnerabilityOrViolationRow) string {
	var descriptionBuilder strings.Builder
	vulnResearch := vulnerability.JfrogResearchInformation
	if vulnResearch == nil {
		vulnResearch = &formats.JfrogResearchInformation{Details: vulnerability.Summary}
	} else if vulnResearch.Details == "" {
		vulnResearch.Details = vulnerability.Summary
	}

	if vulnResearch.Details != "" {
		WriteContent(&descriptionBuilder, MarkAsBold("Description:"), vulnResearch.Details)
	}
	if vulnResearch.Remediation != "" {
		if vulnResearch.Details != "" {
			WriteNewLine(&descriptionBuilder)
		}
		WriteContent(&descriptionBuilder, MarkAsBold("Remediation:"), vulnResearch.Remediation)
	}
	return descriptionBuilder.String()
}

func getVulnerabilityDescriptionIdentifier(cveRows []formats.CveRow, xrayId string) string {
	identifier := results.GetIssueIdentifier(cveRows, xrayId, ", ")
	if identifier == "" {
		return ""
	}
	return fmt.Sprintf("[ %s ]", identifier)
}

func LicensesContent(licenses []formats.LicenseRow, writer OutputWriter) string {
	if len(licenses) == 0 {
		return ""
	}
	// Title
	var contentBuilder strings.Builder
	WriteContent(&contentBuilder, writer.MarkAsTitle("⚖️ Violated Licenses", 2))
	// Content
	table := NewMarkdownTable("SEVERITY", "LICENSE", "DIRECT DEPENDENCIES", "IMPACTED DEPENDENCY").SetDelimiter(writer.Separator())
	for _, license := range licenses {
		table.AddRowWithCellData(
			NewCellData(license.Severity),
			NewCellData(license.LicenseKey),
			getDirectDependenciesCellData("%s %s", license.Components),
			NewCellData(fmt.Sprintf("%s %s", license.ImpactedDependencyName, license.ImpactedDependencyVersion)),
		)
	}
	WriteContent(&contentBuilder, writer.MarkInCenter(table.Build()))
	return contentBuilder.String()
}

// For review comment Frogbot creates on Scan PR
func GenerateReviewCommentContent(content string, writer OutputWriter) string {
	var contentBuilder strings.Builder
	contentBuilder.WriteString(MarkdownComment(ReviewCommentId))
	customCommentTitle := writer.PullRequestCommentTitle()
	if customCommentTitle != "" {
		WriteContent(&contentBuilder, writer.MarkAsTitle(MarkAsBold(customCommentTitle), 2))
	}
	WriteContent(&contentBuilder, content, footer(writer))
	return contentBuilder.String()
}

// When can't create review comment, create a fallback comment by adding the location description to the content as a prefix
func GetFallbackReviewCommentContent(content string, location formats.Location, writer OutputWriter) string {
	var contentBuilder strings.Builder
	contentBuilder.WriteString(MarkdownComment(ReviewCommentId))
	WriteContent(&contentBuilder, getFallbackCommentLocationDescription(location), content)
	return contentBuilder.String()
}

func IsFrogbotComment(content string) bool {
	return strings.Contains(content, ReviewCommentId)
}

func getFallbackCommentLocationDescription(location formats.Location) string {
	return fmt.Sprintf("%s\nat %s (line %d)", MarkAsCodeSnippet(location.Snippet), MarkAsQuote(location.File), location.StartLine)
}

func GetApplicabilityDescriptionTable(severity, cve, impactedDependency, finding string, writer OutputWriter) string {
	table := NewMarkdownTable("Severity", "Impacted Dependency", "Finding", "CVE").AddRow(writer.FormattedSeverity(severity, "Applicable"), impactedDependency, finding, cve)
	return table.Build()
}

func ApplicableCveReviewContent(severity, finding, fullDetails, cve, cveDetails, impactedDependency, remediation string, writer OutputWriter) string {
	var contentBuilder strings.Builder
	WriteContent(&contentBuilder,
		writer.MarkAsTitle(contextualAnalysisTitle, 2),
		writer.MarkInCenter(GetApplicabilityDescriptionTable(severity, cve, impactedDependency, finding, writer)),
		writer.MarkAsDetails("Description", 3, fullDetails),
		writer.MarkAsDetails("CVE details", 3, cveDetails),
	)

	if len(remediation) > 0 {
		WriteContent(&contentBuilder, writer.MarkAsDetails("Remediation", 3, remediation))
	}
	return contentBuilder.String()
}

func getJasDescriptionTable(severity, finding string, writer OutputWriter) string {
	return NewMarkdownTable("Severity", "Finding").AddRow(writer.FormattedSeverity(severity, jasutils.Applicable.String()), finding).Build()
}

func getSecretsDescriptionTable(severity, finding, status string, writer OutputWriter) string {
	columns := []string{"Severity", "Finding"}
	applicability := jasutils.Applicable.String()
	if status != "" {
		columns = append(columns, "Status")
		if status == jasutils.Inactive.String() {
			applicability = jasutils.NotApplicable.String()
		}
		return NewMarkdownTable(columns...).AddRow(writer.FormattedSeverity(severity, applicability), finding, status).Build()
	}
	return NewMarkdownTable(columns...).AddRow(writer.FormattedSeverity(severity, applicability), finding).Build()
}

func SecretReviewContent(severity, finding, fullDetails, applicability string, writer OutputWriter) string {
	var contentBuilder strings.Builder
	WriteContent(&contentBuilder,
		writer.MarkAsTitle(secretsTitle, 2),
		writer.MarkInCenter(getSecretsDescriptionTable(severity, finding, applicability, writer)),
		writer.MarkAsDetails("Full description", 3, fullDetails),
	)
	return contentBuilder.String()
}

func IacReviewContent(severity, finding, fullDetails string, writer OutputWriter) string {
	var contentBuilder strings.Builder
	WriteContent(&contentBuilder,
		writer.MarkAsTitle(iacTitle, 2),
		writer.MarkInCenter(getJasDescriptionTable(severity, finding, writer)),
		writer.MarkAsDetails("Full description", 3, fullDetails),
	)
	return contentBuilder.String()
}

func SastReviewContent(severity, finding, fullDetails string, codeFlows [][]formats.Location, writer OutputWriter) string {
	var contentBuilder strings.Builder
	WriteContent(&contentBuilder,
		writer.MarkAsTitle(sastTitle, 2),
		writer.MarkInCenter(getJasDescriptionTable(severity, finding, writer)),
		writer.MarkAsDetails("Full description", 3, fullDetails),
	)

	if len(codeFlows) > 0 {
		WriteContent(&contentBuilder, writer.MarkAsDetails("Code Flows", 3, sastCodeFlowsReviewContent(codeFlows, writer)))
	}
	return contentBuilder.String()
}

func sastCodeFlowsReviewContent(codeFlows [][]formats.Location, writer OutputWriter) string {
	var contentBuilder strings.Builder
	for _, flow := range codeFlows {
		WriteContent(&contentBuilder, writer.MarkAsDetails("Vulnerable data flow analysis result", 4, sastDataFlowLocationsReviewContent(flow)))
	}
	return contentBuilder.String()
}

func sastDataFlowLocationsReviewContent(flow []formats.Location) string {
	var contentBuilder strings.Builder
	for _, location := range flow {
		WriteContent(&contentBuilder, fmt.Sprintf("%s %s (at %s line %d)\n", "↘️", MarkAsQuote(location.Snippet), location.File, location.StartLine))
	}
	return contentBuilder.String()
}
