package outputwriter

import (
	"fmt"
	"strings"

	"github.com/jfrog/frogbot/v2/utils/issues"
	"github.com/jfrog/froggit-go/vcsutils"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/severityutils"
)

const (
	FrogbotTitlePrefix      = "[🐸 Frogbot]"
	FrogbotRepoUrl          = "https://github.com/jfrog/frogbot"
	FrogbotDocumentationUrl = "https://docs.jfrog-applications.jfrog.io/jfrog-applications/frogbot"
	JfrogSupportUrl         = "https://jfrog.com/support/"
	ReviewCommentId         = "FrogbotReviewComment"

	scanSummaryTitle             = "📗 Scan Summary"
	issuesDetailsSubTitle        = "🔖 Details"
	jfrogResearchDetailsSubTitle = "🔬 JFrog Research Details"

	policyViolationTitle   = "🚥 Policy Violations"
	securityViolationTitle = "🚨 Security Violations"
	licenseViolationTitle  = "⚖️ License Violations"

	vulnerableDependenciesTitle = "📦 Vulnerable Dependencies"

	//#nosec G101 -- not a secret
	secretsTitle            = "🤫 Secret"
	contextualAnalysisTitle = "📦🔍 Contextual Analysis CVE"
	iacTitle                = "🛠️ Infrastructure as Code"
	sastTitle               = "🎯 Static Application Security Testing (SAST)"
)

var (
	CommentGeneratedByFrogbot    = MarkAsLink("🐸 JFrog Frogbot", FrogbotDocumentationUrl)
	jasFeaturesMsgWhenNotEnabled = MarkAsBold("Frogbot") + " also supports " + MarkAsBold("Contextual Analysis, Secret Detection, IaC and SAST Vulnerabilities Scanning") + ". This features are included as part of the " + MarkAsLink("JFrog Advanced Security", "https://jfrog.com/advanced-security") + " package, which isn't enabled on your system."
)

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
func GetFallbackReviewCommentContent(content string, location formats.Location) string {
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

// Summary comment, including banner, footer wrapping the content with a decorator
func GetMainCommentContent(contentForComments []string, issuesExists, isComment bool, writer OutputWriter) (comments []string) {
	return ConvertContentToComments(contentForComments, writer, func(commentCount int, content string) string {
		if commentCount == 0 {
			content = GetPRSummaryMainCommentDecorator(issuesExists, isComment, writer)(commentCount, content)
		}
		return GetFrogbotCommentBaseDecorator(writer)(commentCount, content)
	})
}

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

func getPRSummaryBanner(issuesExists, isComment bool, provider vcsutils.VcsProvider) ImageSource {
	if !isComment {
		return fixCVETitleSrc(provider)
	}
	if !issuesExists {
		return NoIssuesTitleSrc(provider)
	}
	return PRSummaryCommentTitleSrc(provider)
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
	return writer.MarkAsDetails("Note", 0, fmt.Sprintf("\n%s\n%s", SectionDivider(), writer.MarkInCenter(jasFeaturesMsgWhenNotEnabled)))
}

func footer(writer OutputWriter) string {
	return fmt.Sprintf("%s\n%s", SectionDivider(), writer.MarkInCenter(CommentGeneratedByFrogbot))
}

// func GetFrogbotErrorCommentContent(contentForComments []string, err error, writer OutputWriter) (comments []string) {
// 	// First decorate with error suffix, then wrap content with the base decorator
// 	return ConvertContentToComments(contentForComments, writer, getFrogbotErrorSuffixDecorator(writer, err), GetFrogbotCommentBaseDecorator(writer))
// }

// Adding markdown suffix to show the error details and next steps
// func getFrogbotErrorSuffixDecorator(writer OutputWriter, err error) CommentDecorator {
// 	return func(_ int, content string) string {
// 		var comment strings.Builder
// 		WriteNewLine(&comment)
// 		// Error
// 		WriteContent(&comment, writer.MarkAsTitle("Error:", 4), err.Error())
// 		WriteNewLine(&comment)
// 		// Action steps
// 		WriteContent(&comment,
// 			writer.MarkAsTitle("Next Steps:", 4),
// 			"1. Please try to rerun the scan.",
// 			fmt.Sprintf("2. If the issue persists, consider checking the %s for troubleshooting tips.", MarkAsLink("Frogbot documentation", FrogbotDocumentationUrl)),
// 			fmt.Sprintf("3. If you still need assistance, feel free to reach out to %s.", MarkAsLink("JFrog Support", JfrogSupportUrl)),
// 		)
// 		WriteNewLine(&comment)
// 		WriteContent(&comment, "Thank you for your understanding!")
// 		return content + "\n" + writer.MarkAsDetails(jobErrorTitle, 3, comment.String())
// 	}
// }

// Summary content

func ScanSummaryContent(issues issues.ScansIssuesCollection, context results.ResultContext, includeSecrets bool, writer OutputWriter) string {
	if !issues.IssuesExists(includeSecrets) && !issues.HasErrors() {
		return ""
	}
	var contentBuilder strings.Builder
	totalIssues := 0
	if issues.HasViolationContext() {
		totalIssues += issues.GetTotalViolations(includeSecrets)
	}
	if issues.IncludeVulnerabilities {
		totalIssues += issues.GetTotalVulnerabilities(includeSecrets)
	}
	// Title
	WriteContent(&contentBuilder, writer.MarkAsTitle(scanSummaryTitle, 2))
	if issues.HasErrors() {
		WriteContent(&contentBuilder, MarkAsBullet(fmt.Sprintf("Frogbot attempted to scan for %s but encountered an error.", getResultsContextString(context))))
		return contentBuilder.String()
	} else {
		WriteContent(&contentBuilder, MarkAsBullet(fmt.Sprintf("Frogbot scanned for %s and found %d issues", getResultsContextString(context), totalIssues)))
	}
	WriteNewLine(&contentBuilder)
	// Create table, a row for each sub scans summary
	secretsDetails := ""
	if includeSecrets {
		secretsDetails = getScanSecurityIssuesDetails(issues, context, utils.SecretsScan, writer)
	}
	table := NewMarkdownTableWithColumns(
		NewMarkdownTableSingleValueColumn("Scan Category", "⚠️", false),
		NewMarkdownTableSingleValueColumn("Status", "⚠️", true),
		NewMarkdownTableSingleValueColumn("Security Issues", "-", false),
	)
	table.AddRow(MarkAsBold("Software Composition Analysis"), getSubScanResultStatus(issues.GetScanStatus(utils.ScaScan)), getScanSecurityIssuesDetails(issues, context, utils.ScaScan, writer))
	table.AddRow(MarkAsBold("Contextual Analysis"), getSubScanResultStatus(issues.GetScanStatus(utils.ContextualAnalysisScan)), "")
	table.AddRow(MarkAsBold("Static Application Security Testing (SAST)"), getSubScanResultStatus(issues.GetScanStatus(utils.SastScan)), getScanSecurityIssuesDetails(issues, context, utils.SastScan, writer))
	table.AddRow(MarkAsBold("Secrets"), getSubScanResultStatus(issues.GetScanStatus(utils.SecretsScan)), secretsDetails)
	table.AddRow(MarkAsBold("Infrastructure as Code (IaC)"), getSubScanResultStatus(issues.GetScanStatus(utils.IacScan)), getScanSecurityIssuesDetails(issues, context, utils.IacScan, writer))
	WriteContent(&contentBuilder, table.Build())
	return contentBuilder.String()
}

func getResultsContextString(context results.ResultContext) string {
	out := ""
	if context.HasViolationContext() {
		out += "violations"
	}
	if context.IncludeVulnerabilities {
		if out != "" {
			out += " and "
		}
		out += "vulnerabilities"
	}
	return out
}

func getSubScanResultStatus(scanStatusCode *int) string {
	if scanStatusCode == nil {
		return "ℹ️ Not Scanned"
	}
	if *scanStatusCode == 0 {
		return "✅ Done"
	}
	return "❌ Failed"
}

func getScanSecurityIssuesDetails(issues issues.ScansIssuesCollection, context results.ResultContext, scanType utils.SubScanType, writer OutputWriter) string {
	if issues.HasErrors() || issues.IsScanNotCompleted(scanType) {
		// Failed/Not scanned, no need to show the details
		return ""
	}
	var severityCountMap map[severityutils.Severity]int
	countViolations := context.HasViolationContext()
	countVulnerabilities := context.IncludeVulnerabilities
	switch scanType {
	case utils.ScaScan:
		severityCountMap = issues.GetScanIssuesSeverityCount(utils.ScaScan, countVulnerabilities, countViolations)
	case utils.SastScan:
		severityCountMap = issues.GetScanIssuesSeverityCount(utils.SastScan, countVulnerabilities, countViolations)
	case utils.SecretsScan:
		severityCountMap = issues.GetScanIssuesSeverityCount(utils.SecretsScan, countVulnerabilities, countViolations)
	case utils.IacScan:
		severityCountMap = issues.GetScanIssuesSeverityCount(utils.IacScan, countVulnerabilities, countViolations)
	}
	totalIssues := getTotalIssues(severityCountMap)
	if totalIssues == 0 {
		// No Issues
		return "Not Found"
	}
	var contentBuilder strings.Builder
	WriteContent(&contentBuilder, writer.MarkAsDetails(fmt.Sprintf("%d Issues Found", totalIssues), 0, toSeverityDetails(severityCountMap, writer)))
	return contentBuilder.String()
}

func getTotalIssues(severities map[severityutils.Severity]int) (total int) {
	for _, count := range severities {
		total += count
	}
	return
}

func toSeverityDetails(severities map[severityutils.Severity]int, writer OutputWriter) string {
	var contentBuilder strings.Builder
	sortedSeverities := []severityutils.Severity{severityutils.Critical, severityutils.High, severityutils.Medium, severityutils.Low, severityutils.Unknown}
	for _, severity := range sortedSeverities {
		if count, ok := severities[severity]; ok && count > 0 {
			if contentBuilder.Len() > 0 {
				contentBuilder.WriteString(writer.Separator())
			}
			contentBuilder.WriteString(fmt.Sprintf("%s %d %s", writer.SeverityIcon(severity), count, severity.String()))
		}
	}
	return contentBuilder.String()
}

// SCA (Policy) Violations

// Summary content for the security violations that we can't yet have location on (SCA, License)
func PolicyViolationsContent(issues issues.ScansIssuesCollection, writer OutputWriter) (policyViolationContent []string) {
	if issues.GetTotalScaViolations() == 0 {
		return []string{}
	}
	policyViolationContent = append(policyViolationContent, getSecurityViolationsContent(issues, writer)...)
	policyViolationContent = append(policyViolationContent, getLicenseViolationsContent(issues, writer)...)
	return ConvertContentToComments(policyViolationContent, writer, getDecoratorWithPolicyViolationTitle(writer))
}

func getDecoratorWithPolicyViolationTitle(writer OutputWriter) CommentDecorator {
	return func(commentCount int, content string) string {
		contentBuilder := strings.Builder{}
		// Decorate each part of the split content with a title as prefix and return the content
		WriteContent(&contentBuilder, writer.MarkAsTitle(policyViolationTitle, 2))
		WriteContent(&contentBuilder, content)
		return contentBuilder.String()
	}
}

// Security Violations

func getSecurityViolationsContent(issues issues.ScansIssuesCollection, writer OutputWriter) (content []string) {
	if len(issues.ScaViolations) == 0 {
		return []string{}
	}
	content = append(content, getSecurityViolationsSummaryTable(issues.ScaViolations, writer))
	content = append(content, getScaSecurityIssueDetailsContent(issues.ScaViolations, true, writer)...)
	return ConvertContentToComments(content, writer, getDecoratorWithSecurityViolationTitle(writer))
}

func getDecoratorWithSecurityViolationTitle(writer OutputWriter) CommentDecorator {
	return func(commentCount int, content string) string {
		contentBuilder := strings.Builder{}
		// Decorate each part of the split content with a title as prefix and return the content
		WriteContent(&contentBuilder, writer.MarkAsTitle(securityViolationTitle, 3))
		WriteContent(&contentBuilder, content)
		return contentBuilder.String()
	}
}

func getSecurityViolationsSummaryTable(violations []formats.VulnerabilityOrViolationRow, writer OutputWriter) string {
	// Construct table
	columns := []string{"Severity", "ID"}
	if writer.IsShowingCaColumn() {
		columns = append(columns, "Contextual Analysis")
	}
	table := NewMarkdownTable(append(columns, "Direct Dependencies", "Impacted Dependency", "Watch Name")...).SetDelimiter(writer.Separator())
	if _, ok := writer.(*SimplifiedOutput); ok {
		// The values in this cell can be potentially large, since SimplifiedOutput does not support tags, we need to show each value in a separate row.
		// It means that the first row will show the full details, and the following rows will show only the direct dependency.
		// It makes it easier to read the table and less crowded with text in a single cell that could be potentially large.
		table.GetColumnInfo("Direct Dependencies").ColumnType = MultiRowColumn
	}
	// Construct rows
	for _, violation := range violations {
		row := []CellData{{writer.FormattedSeverity(violation.Severity, violation.Applicable)}, getCveIdsCellData(violation.Cves, violation.IssueId)}
		if writer.IsShowingCaColumn() {
			row = append(row, NewCellData(violation.Applicable))
		}
		row = append(row,
			getDirectDependenciesCellData(violation.Components),
			NewCellData(results.GetDependencyId(violation.ImpactedDependencyName, violation.ImpactedDependencyVersion)),
			NewCellData(violation.Watch),
		)
		table.AddRowWithCellData(row...)
	}
	return writer.MarkInCenter(table.Build())
}

// License violations

func getLicenseViolationsContent(issues issues.ScansIssuesCollection, writer OutputWriter) (content []string) {
	if len(issues.LicensesViolations) == 0 {
		return []string{}
	}
	content = append(content, getLicenseViolationsSummaryTable(issues.LicensesViolations, writer))
	content = append(content, getLicenseViolationsDetailsContent(issues.LicensesViolations, writer)...)
	return ConvertContentToComments(content, writer, getDecoratorWithLicenseViolationTitle(writer))
}

func getDecoratorWithLicenseViolationTitle(writer OutputWriter) CommentDecorator {
	return func(commentCount int, content string) string {
		contentBuilder := strings.Builder{}
		// Decorate each part of the split content with a title as prefix and return the content
		WriteContent(&contentBuilder, writer.MarkAsTitle(licenseViolationTitle, 3))
		WriteContent(&contentBuilder, content)
		return contentBuilder.String()
	}
}

func getLicenseViolationsSummaryTable(licenses []formats.LicenseViolationRow, writer OutputWriter) string {
	table := NewMarkdownTable("Severity", "License", "Direct Dependencies", "Impacted Dependency", "Watch Name").SetDelimiter(writer.Separator())
	if _, ok := writer.(*SimplifiedOutput); ok {
		// The values in this cell can be potentially large, since SimplifiedOutput does not support tags, we need to show each value in a separate row.
		// It means that the first row will show the full details, and the following rows will show only the direct dependency.
		// It makes it easier to read the table and less crowded with text in a single cell that could be potentially large.
		table.GetColumnInfo("Direct Dependencies").ColumnType = MultiRowColumn
	}
	for _, license := range licenses {
		table.AddRowWithCellData(
			NewCellData(writer.FormattedSeverity(license.Severity, "Applicable")),
			NewCellData(license.LicenseKey),
			getDirectDependenciesCellData(license.Components),
			NewCellData(results.GetDependencyId(license.ImpactedDependencyName, license.ImpactedDependencyVersion)),
			NewCellData(license.Watch),
		)
	}
	return writer.MarkInCenter(table.Build())
}

func getLicenseViolationsDetailsContent(licenseViolations []formats.LicenseViolationRow, writer OutputWriter) (content []string) {
	if len(licenseViolations) == 0 {
		return
	}
	for _, violation := range licenseViolations {
		if len(licenseViolations) == 1 {
			content = append(content, getScaLicenseViolationDetails(violation, writer))
		} else {
			content = append(content, "\n"+writer.MarkAsDetails(
				getComponentIssueIdentifier(violation.LicenseKey, violation.ImpactedDependencyName, violation.ImpactedDependencyVersion, violation.Watch), 4,
				getScaLicenseViolationDetails(violation, writer),
			))
		}
	}
	// Split content if it exceeds the size limit and decorate it with title
	return ConvertContentToComments(content, writer, func(commentCount int, detailsContent string) string {
		contentBuilder := strings.Builder{}
		WriteContent(&contentBuilder, writer.MarkAsTitle(issuesDetailsSubTitle, 3))
		WriteContent(&contentBuilder, detailsContent)
		return contentBuilder.String()
	})
}

func getScaLicenseViolationDetails(violation formats.LicenseViolationRow, writer OutputWriter) (content string) {
	var contentBuilder strings.Builder
	// Title
	WriteNewLine(&contentBuilder)
	WriteContent(&contentBuilder, writer.MarkAsTitle("Violation Details", 3))
	// Details Table
	directComponent := []string{}
	for _, component := range violation.ImpactedDependencyDetails.Components {
		directComponent = append(directComponent, results.GetDependencyId(component.Name, component.Version))
	}
	noHeaderTable := NewNoHeaderMarkdownTable(2, false)

	noHeaderTable.AddRowWithCellData(NewCellData(MarkAsBold("Policies:")), NewCellData(violation.Policies...))
	noHeaderTable.AddRow(MarkAsBold("Watch Name:"), violation.Watch)
	noHeaderTable.AddRowWithCellData(NewCellData(MarkAsBold("Direct Dependencies:")), NewCellData(directComponent...))
	noHeaderTable.AddRow(MarkAsBold("Impacted Dependency:"), results.GetDependencyId(violation.ImpactedDependencyName, violation.ImpactedDependencyVersion))
	noHeaderTable.AddRow(MarkAsBold("Full Name:"), violation.LicenseName)

	WriteContent(&contentBuilder, noHeaderTable.Build(), "\n")
	return contentBuilder.String()
}

// Sca Vulnerabilities

func GetVulnerabilitiesContent(vulnerabilities []formats.VulnerabilityOrViolationRow, writer OutputWriter) (content []string) {
	if len(vulnerabilities) == 0 {
		return []string{}
	}
	content = append(content, writer.MarkInCenter(getVulnerabilitiesSummaryTable(vulnerabilities, writer)))
	content = append(content, getScaSecurityIssueDetailsContent(vulnerabilities, false, writer)...)
	return ConvertContentToComments(content, writer, getDecoratorWithScaVulnerabilitiesTitle(writer))
}

func getDecoratorWithScaVulnerabilitiesTitle(writer OutputWriter) CommentDecorator {
	return func(commentCount int, content string) string {
		contentBuilder := strings.Builder{}
		// Decorate each part of the split content with a title as prefix and return the content
		WriteContent(&contentBuilder, writer.MarkAsTitle(vulnerableDependenciesTitle, 3))
		WriteContent(&contentBuilder, content)
		return contentBuilder.String()
	}
}

func getVulnerabilitiesSummaryTable(vulnerabilities []formats.VulnerabilityOrViolationRow, writer OutputWriter) string {
	// Construct table
	columns := []string{"Severity", "ID"}
	if writer.IsShowingCaColumn() {
		columns = append(columns, "Contextual Analysis")
	}
	columns = append(columns, "Direct Dependencies", "Impacted Dependency", "Fixed Versions")
	table := NewMarkdownTable(columns...).SetDelimiter(writer.Separator())
	if _, ok := writer.(*SimplifiedOutput); ok {
		// The values in this cell can be potentially large, since SimplifiedOutput does not support tags, we need to show each value in a separate row.
		// It means that the first row will show the full details, and the following rows will show only the direct dependency.
		// It makes it easier to read the table and less crowded with text in a single cell that could be potentially large.
		table.GetColumnInfo("Direct Dependencies").ColumnType = MultiRowColumn
	}
	// Construct rows
	for _, vulnerability := range vulnerabilities {
		row := []CellData{{writer.FormattedSeverity(vulnerability.Severity, vulnerability.Applicable)}, getCveIdsCellData(vulnerability.Cves, vulnerability.IssueId)}
		if writer.IsShowingCaColumn() {
			row = append(row, NewCellData(vulnerability.Applicable))
		}
		row = append(row,
			getDirectDependenciesCellData(vulnerability.Components),
			NewCellData(fmt.Sprintf("%s %s", vulnerability.ImpactedDependencyName, vulnerability.ImpactedDependencyVersion)),
			NewCellData(vulnerability.FixedVersions...),
		)
		table.AddRowWithCellData(row...)
	}
	return table.Build()
}

// Applicable CVE Evidence

func ApplicableCveReviewContent(issue issues.ApplicableEvidences, writer OutputWriter) string {
	var contentBuilder strings.Builder
	WriteContent(&contentBuilder,
		writer.MarkAsTitle(contextualAnalysisTitle, 2),
		writer.MarkInCenter(GetApplicabilityDescriptionTable(issue.Severity, issue.IssueId, issue.ImpactedDependency, issue.Evidence.Reason, writer)),
		writer.MarkAsDetails("Description", 3, "\n"+issue.ScannerDescription+"\n"),
		writer.MarkAsDetails("CVE details", 3, "\n"+issue.CveSummary+"\n"),
	)
	if len(issue.Remediation) > 0 {
		WriteContent(&contentBuilder, writer.MarkAsDetails("Remediation", 3, "\n\n"+issue.Remediation+"\n\n"))
	}
	return contentBuilder.String()
}

func GetApplicabilityDescriptionTable(severity, issueId, impactedDependency, finding string, writer OutputWriter) string {
	table := NewMarkdownTable("Severity", "ID", "Impacted Dependency", "Finding").AddRow(writer.FormattedSeverity(severity, "Applicable"), issueId, impactedDependency, finding)
	return table.Build()
}

// JAS

func IacReviewContent(violation bool, writer OutputWriter, issues ...formats.SourceCodeRow) string {
	var contentBuilder strings.Builder
	WriteContent(&contentBuilder,
		writer.MarkAsTitle(fmt.Sprintf("%s %s", iacTitle, getIssueType(violation)), 2),
		writer.MarkInCenter(getJasIssueDescriptionTable(writer, issues...)),
		getJasFullDescription(violation, writer, getBaseJasDetailsTable, issues...),
	)
	return contentBuilder.String()
}

func SastReviewContent(violation bool, writer OutputWriter, issues ...formats.SourceCodeRow) string {
	var contentBuilder strings.Builder
	WriteContent(&contentBuilder,
		writer.MarkAsTitle(fmt.Sprintf("%s %s", sastTitle, getIssueType(violation)), 2),
		writer.MarkInCenter(getJasIssueDescriptionTable(writer, issues...)),
		getJasFullDescription(violation, writer, getSastRuleFullDescriptionTable, issues...),
	)
	return contentBuilder.String()
}

func getSastRuleFullDescriptionTable(info formats.ScannerInfo, writer OutputWriter) *MarkdownTableBuilder {
	table := getBaseJasDetailsTable(info, writer)
	table.AddRow(MarkAsBold("Rule ID:"), info.RuleId)
	return table
}

func SecretReviewContent(violation bool, writer OutputWriter, issues ...formats.SourceCodeRow) string {
	var contentBuilder strings.Builder
	WriteContent(&contentBuilder,
		writer.MarkAsTitle(fmt.Sprintf("%s %s", secretsTitle, getIssueType(violation)), 2),
		writer.MarkInCenter(getSecretsDescriptionTable(writer, issues...)),
		getJasFullDescription(violation, writer, getSecretsRuleFullDescriptionTable, issues...),
	)
	return contentBuilder.String()
}

func getSecretsDescriptionTable(writer OutputWriter, issues ...formats.SourceCodeRow) string {
	// Construct table
	table := NewMarkdownTable("Severity", "ID", "Status", "Finding", "Watch Name", "Policies").SetDelimiter(writer.Separator())
	// Hide optional columns if all empty (violations/no status)
	table.GetColumnInfo("ID").OmitEmpty = true
	table.GetColumnInfo("Status").OmitEmpty = true
	table.GetColumnInfo("Watch Name").OmitEmpty = true
	table.GetColumnInfo("Policies").OmitEmpty = true
	// Construct rows
	for _, issue := range issues {
		// Determine the issue applicable status
		applicability := jasutils.Applicable.String()
		status := ""
		if issue.Applicability != nil && issue.Applicability.Status != "" {
			status = issue.Applicability.Status
			if status == jasutils.Inactive.String() {
				// Update the applicability status to Not Applicable for Inactive
				applicability = jasutils.NotApplicable.String()
			}
		}
		table.AddRowWithCellData(
			NewCellData(writer.FormattedSeverity(issue.Severity, applicability)),
			NewCellData(issue.IssueId),
			NewCellData(status),
			NewCellData(issue.Finding),
			NewCellData(issue.Watch),
			NewCellData(issue.Policies...),
		)
	}
	return table.Build()
}

func getSecretsRuleFullDescriptionTable(info formats.ScannerInfo, writer OutputWriter) *MarkdownTableBuilder {
	table := getBaseJasDetailsTable(info, writer)
	table.AddRow(MarkAsBold("Abbreviation:"), info.RuleId)
	return table
}

// Utilities

func getIssueType(violation bool) string {
	if violation {
		return "Violation"
	}
	return "Vulnerability"
}

func getDirectDependenciesCellData(components []formats.ComponentRow) (dependencies CellData) {
	if len(components) == 0 {
		return NewCellData()
	}
	for _, component := range components {
		dependencies = append(dependencies, results.GetDependencyId(component.Name, component.Version))
	}
	return
}

func getCveIdsCellData(cveRows []formats.CveRow, issueId string) (ids CellData) {
	if len(cveRows) == 0 {
		return NewCellData(issueId)
	}
	for _, cve := range cveRows {
		ids = append(ids, cve.Id)
	}
	return
}

func getScaSecurityIssueDetailsContent(issues []formats.VulnerabilityOrViolationRow, violations bool, writer OutputWriter) (content []string) {
	issuesWithDetails := getIssuesWithDetails(issues)
	if len(issuesWithDetails) == 0 {
		return
	}
	for _, issue := range issuesWithDetails {
		if len(issues) == 1 {
			content = append(content, getScaSecurityIssueDetails(issue, violations, writer))
		} else {
			content = append(content, "\n"+writer.MarkAsDetails(
				getComponentIssueIdentifier(results.GetIssueIdentifier(issue.Cves, issue.IssueId, ", "), issue.ImpactedDependencyName, issue.ImpactedDependencyVersion, issue.Watch), 4,
				getScaSecurityIssueDetails(issue, violations, writer),
			))
		}
	}
	// Split content if it exceeds the size limit and decorate it with title
	return ConvertContentToComments(content, writer, func(commentCount int, detailsContent string) string {
		contentBuilder := strings.Builder{}
		WriteContent(&contentBuilder, writer.MarkAsTitle(issuesDetailsSubTitle, 3))
		WriteContent(&contentBuilder, detailsContent)
		return contentBuilder.String()
	})
}

func getIssuesWithDetails(issues []formats.VulnerabilityOrViolationRow) (filter []formats.VulnerabilityOrViolationRow) {
	for i := range issues {
		if issues[i].JfrogResearchInformation != nil || issues[i].Summary != "" {
			filter = append(filter, issues[i])
		}
	}
	return
}

func getComponentIssueIdentifier(key, compName, version, watch string) (id string) {
	parts := []string{}
	if key != "" {
		parts = append(parts, fmt.Sprintf("[ %s ]", key))
	}
	parts = append(parts, compName, version)
	if watch != "" {
		parts = append(parts, fmt.Sprintf("(%s)", watch))
	}
	return strings.Join(parts, " ")
}

func getScaSecurityIssueDetails(issue formats.VulnerabilityOrViolationRow, violations bool, writer OutputWriter) (content string) {
	var contentBuilder strings.Builder
	// Title
	WriteNewLine(&contentBuilder)
	WriteContent(&contentBuilder, writer.MarkAsTitle(fmt.Sprintf("%s Details", getIssueType(violations)), 3))
	// Details Table
	directComponent := []string{}
	for _, component := range issue.ImpactedDependencyDetails.Components {
		directComponent = append(directComponent, results.GetDependencyId(component.Name, component.Version))
	}
	noHeaderTable := NewNoHeaderMarkdownTable(2, false)
	if len(issue.Policies) > 0 {
		noHeaderTable.AddRowWithCellData(NewCellData(MarkAsBold("Policies:")), NewCellData(issue.Policies...))
	}
	if issue.Watch != "" {
		noHeaderTable.AddRow(MarkAsBold("Watch Name:"), issue.Watch)
	}
	if issue.JfrogResearchInformation != nil && issue.JfrogResearchInformation.Severity != "" {
		severity := severityutils.Severity(issue.JfrogResearchInformation.Severity)
		noHeaderTable.AddRow(MarkAsBold("Jfrog Research Severity:"), fmt.Sprintf("%s %s", writer.SeverityIcon(severity), severity.String()))
	}
	if issue.Applicable != "" {
		noHeaderTable.AddRow(MarkAsBold("Contextual Analysis:"), issue.Applicable)
	}
	noHeaderTable.AddRowWithCellData(NewCellData(MarkAsBold("Direct Dependencies:")), NewCellData(directComponent...))
	noHeaderTable.AddRow(MarkAsBold("Impacted Dependency:"), results.GetDependencyId(issue.ImpactedDependencyName, issue.ImpactedDependencyVersion))
	noHeaderTable.AddRowWithCellData(NewCellData(MarkAsBold("Fixed Versions:")), NewCellData(issue.FixedVersions...))

	cvss := []string{}
	for _, cve := range issue.Cves {
		cvss = append(cvss, cve.CvssV3)
	}
	noHeaderTable.AddRowWithCellData(NewCellData(MarkAsBold("CVSS V3:")), NewCellData(cvss...))
	WriteContent(&contentBuilder, noHeaderTable.Build())

	// Summary
	summary := issue.Summary
	if issue.JfrogResearchInformation != nil && issue.JfrogResearchInformation.Summary != "" {
		summary = issue.JfrogResearchInformation.Summary
	}
	if summary != "" {
		WriteNewLine(&contentBuilder)
		WriteContent(&contentBuilder, summary)
	}

	// Jfrog Research Details
	if issue.JfrogResearchInformation == nil || (issue.JfrogResearchInformation.Details == "" && issue.JfrogResearchInformation.Remediation == "") {
		return contentBuilder.String()
	}
	WriteNewLine(&contentBuilder)
	WriteContent(&contentBuilder, writer.MarkAsTitle(jfrogResearchDetailsSubTitle, 3))

	if issue.JfrogResearchInformation.Details != "" {
		WriteNewLine(&contentBuilder)
		WriteContent(&contentBuilder, MarkAsBold("Description:"), issue.JfrogResearchInformation.Details)
	}
	if issue.JfrogResearchInformation.Remediation != "" {
		WriteNewLine(&contentBuilder)
		WriteContent(&contentBuilder, MarkAsBold("Remediation:"), issue.JfrogResearchInformation.Remediation)
	}

	return contentBuilder.String() + "\n"
}

func getJasIssueDescriptionTable(writer OutputWriter, issues ...formats.SourceCodeRow) string {
	// Construct table
	table := NewMarkdownTable("Severity", "ID", "Finding", "Watch Name", "Policies").SetDelimiter(writer.Separator())
	// Hide optional columns if all empty (not violations)
	table.GetColumnInfo("ID").OmitEmpty = true
	table.GetColumnInfo("Watch Name").OmitEmpty = true
	table.GetColumnInfo("Policies").OmitEmpty = true
	// Construct rows
	for _, issue := range issues {
		table.AddRowWithCellData(
			NewCellData(writer.FormattedSeverity(issue.Severity, "Applicable")),
			NewCellData(issue.IssueId),
			NewCellData(issue.Finding),
			NewCellData(issue.Watch),
			NewCellData(issue.Policies...),
		)
	}
	return table.Build()
}

// For Jas we show description for each unique rule
func getJasFullDescription(violations bool, writer OutputWriter, generateRuleTable func(formats.ScannerInfo, OutputWriter) *MarkdownTableBuilder, issues ...formats.SourceCodeRow) string {
	// Group by scanner info
	rulesInfo := map[string]formats.ScannerInfo{}
	codeFlows := map[string][][]formats.Location{}
	for _, issue := range issues {
		if _, ok := rulesInfo[issue.RuleId]; ok {
			codeFlows[issue.RuleId] = append(codeFlows[issue.RuleId], issue.CodeFlow...)
			continue
		}
		rulesInfo[issue.RuleId] = issue.ScannerInfo
		codeFlows[issue.RuleId] = issue.CodeFlow
	}
	// Write the details for each rule
	var contentBuilder strings.Builder
	for _, info := range rulesInfo {
		var scannerCodeFlows [][]formats.Location
		if v, ok := codeFlows[info.RuleId]; ok {
			scannerCodeFlows = v
		}
		if len(rulesInfo) == 1 {
			WriteContent(&contentBuilder,
				writer.MarkAsDetails("Full description", 3, getJasRuleFullDescription(violations, info.ScannerDescription, generateRuleTable(info, writer), writer)),
				codeFlowsReviewContent(scannerCodeFlows, writer),
			)
			break
		}
		WriteContent(&contentBuilder, writer.MarkAsDetails(getJasDetailsIdentifier(info), 3, getJasRuleFullDescription(violations, info.ScannerDescription, generateRuleTable(info, writer), writer, scannerCodeFlows...)))
	}
	return contentBuilder.String()
}

func getJasDetailsIdentifier(info formats.ScannerInfo) string {
	id := info.RuleId
	if info.ScannerShortDescription != "" {
		id = info.ScannerShortDescription
	}
	return fmt.Sprintf("[ %s ]", id)
}

func getJasRuleFullDescription(violation bool, scannerDescription string, issueDescTable *MarkdownTableBuilder, writer OutputWriter, codeFlows ...[]formats.Location) string {
	var contentBuilder strings.Builder
	// Separator
	WriteNewLine(&contentBuilder)
	// Write the vulnerability/violation details
	WriteContent(&contentBuilder, writer.MarkAsTitle(fmt.Sprintf("%s Details", getIssueType(violation)), 3))
	if issueDescTable != nil && issueDescTable.HasContent() {
		WriteContent(&contentBuilder, issueDescTable.Build())
		// Separator
		WriteNewLine(&contentBuilder)
	}
	// Write the description
	WriteContent(&contentBuilder, scannerDescription, "\n")
	// Write the code flows if exists
	if len(codeFlows) > 0 {
		WriteContent(&contentBuilder, codeFlowsReviewContent(codeFlows, writer))
	}
	return contentBuilder.String()
}

func codeFlowsReviewContent(codeFlows [][]formats.Location, writer OutputWriter) string {
	if len(codeFlows) == 0 {
		return ""
	}
	var contentBuilder strings.Builder
	for _, flow := range codeFlows {
		WriteContent(&contentBuilder, writer.MarkAsDetails("Vulnerable data flow analysis result", 4, dataFlowLocationsReviewContent(flow)))
	}
	return writer.MarkAsDetails("Code Flows", 3, contentBuilder.String())
}

func dataFlowLocationsReviewContent(flow []formats.Location) string {
	var contentBuilder strings.Builder
	for i, location := range flow {
		if i == 0 {
			WriteNewLine(&contentBuilder)
		}
		WriteContent(&contentBuilder, fmt.Sprintf("%s %s (at %s line %d)\n", "↘️", MarkAsQuote(location.Snippet), location.File, location.StartLine))
	}
	return contentBuilder.String()
}

func getBaseJasDetailsTable(ruleInfo formats.ScannerInfo, writer OutputWriter) *MarkdownTableBuilder {
	noHeaderTable := NewNoHeaderMarkdownTable(2, false).SetDelimiter(writer.Separator())
	// General CWE attribute if exists
	if len(ruleInfo.Cwe) > 0 {
		noHeaderTable.AddRowWithCellData(NewCellData(MarkAsBold("CWE:")), NewCellData(ruleInfo.Cwe...))
	}
	return noHeaderTable
}
