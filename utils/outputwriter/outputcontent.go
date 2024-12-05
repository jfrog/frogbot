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
	return writer.MarkAsDetails("Note:", 0, fmt.Sprintf("%s\n%s", SectionDivider(), writer.MarkInCenter(jasFeaturesMsgWhenNotEnabled)))
}

func footer(writer OutputWriter) string {
	return fmt.Sprintf("%s\n%s", SectionDivider(), writer.MarkInCenter(CommentGeneratedByFrogbot))
}

// Summary content

func ScanSummaryContent(issues issues.ScansIssuesCollection, violationContext string, includeSecrets bool, writer OutputWriter) string {
	if !issues.IssuesExists(includeSecrets) {
		return ""
	}
	var contentBuilder strings.Builder
	totalIssues := issues.GetTotalVulnerabilities(includeSecrets)
	violations := false
	if violationContext != "" {
		totalIssues = issues.GetTotalViolations(includeSecrets)
		violations = true
	}
	// Title
	WriteContent(&contentBuilder,
		writer.MarkAsTitle(scanSummaryTitle, 2),
		MarkAsBullet(fmt.Sprintf("Frogbot scanned for %s and found %d issues", getIssueType(violations), totalIssues)),
	)
	// Create table, a row for each sub scans summary
	secretsDetails := ""
	if includeSecrets {
		secretsDetails = getScanSecurityIssuesDetails(issues, utils.SecretsScan, violations, writer)
	}
	table := NewMarkdownTable("Scan Category", "Status", "Security Issues")
	table.AddRow(MarkAsBold("Software Composition Analysis"), getSubScanResultStatus(issues.GetScanStatus(utils.ScaScan)), getScanSecurityIssuesDetails(issues, utils.ScaScan, violations, writer))
	table.AddRow(MarkAsBold("Contextual Analysis"), getSubScanResultStatus(issues.GetScanStatus(utils.ContextualAnalysisScan)), "")
	table.AddRow(MarkAsBold("Static Application Security Testing (SAST)"), getSubScanResultStatus(issues.GetScanStatus(utils.ScaScan)), getScanSecurityIssuesDetails(issues, utils.SastScan, violations, writer))
	table.AddRow(MarkAsBold("Secrets"), getSubScanResultStatus(issues.GetScanStatus(utils.SecretsScan)), secretsDetails)
	table.AddRow(MarkAsBold("Infrastructure as Code (IaC)"), getSubScanResultStatus(issues.GetScanStatus(utils.IacScan)), getScanSecurityIssuesDetails(issues, utils.IacScan, violations, writer))
	WriteContent(&contentBuilder, writer.MarkInCenter(table.Build()))
	return contentBuilder.String()
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

func getScanSecurityIssuesDetails(issues issues.ScansIssuesCollection, scanType utils.SubScanType, violation bool, writer OutputWriter) string {
	if issues.IsScanNotCompleted(scanType) {
		// Failed/Not scanned, no need to show the details
		return ""
	}
	var severityCountMap map[severityutils.Severity]int
	switch scanType {
	case utils.ScaScan:
		severityCountMap = issues.GetScanDetails(utils.ScaScan, violation)
	case utils.SastScan:
		severityCountMap = issues.GetScanDetails(utils.SastScan, violation)
	case utils.SecretsScan:
		severityCountMap = issues.GetScanDetails(utils.SecretsScan, violation)
	case utils.IacScan:
		severityCountMap = issues.GetScanDetails(utils.IacScan, violation)
	}
	if len(severityCountMap) == 0 {
		// No Issues
		return "Not Found"
	}
	var contentBuilder strings.Builder
	WriteContent(&contentBuilder, writer.MarkAsDetails(fmt.Sprintf("%d Issues Found", getTotalIssues(severityCountMap)), 3, toSeverityDetails(severityCountMap)))
	return contentBuilder.String()
}

func getTotalIssues(severities map[severityutils.Severity]int) (total int) {
	for _, count := range severities {
		total += count
	}
	return
}

func toSeverityDetails(severities map[severityutils.Severity]int) string {
	var contentBuilder strings.Builder
	// Get severities with values and write them sorted (Critical, High, Medium, Low, Unknown)
	if count, ok := severities[severityutils.Critical]; ok && count > 0 {
		WriteContent(&contentBuilder, fmt.Sprintf("%s %d %s", severityutils.GetSeverityIcon(severityutils.Critical), count, severityutils.Critical.String()))
	}
	if count, ok := severities[severityutils.High]; ok && count > 0 {
		WriteContent(&contentBuilder, fmt.Sprintf("%s %d %s", severityutils.GetSeverityIcon(severityutils.High), count, severityutils.High.String()))
	}
	if count, ok := severities[severityutils.Medium]; ok && count > 0 {
		WriteContent(&contentBuilder, fmt.Sprintf("%s %d %s", severityutils.GetSeverityIcon(severityutils.Medium), count, severityutils.Medium.String()))
	}
	if count, ok := severities[severityutils.Low]; ok && count > 0 {
		WriteContent(&contentBuilder, fmt.Sprintf("%s %d %s", severityutils.GetSeverityIcon(severityutils.Low), count, severityutils.Low.String()))
	}
	if count, ok := severities[severityutils.Unknown]; ok && count > 0 {
		WriteContent(&contentBuilder, fmt.Sprintf("%s %d %s", severityutils.GetSeverityIcon(severityutils.Unknown), count, severityutils.Unknown.String()))
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

func getDecoratorWithPolicyViolationTitle(writer OutputWriter) func(int, string) string {
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

func getDecoratorWithSecurityViolationTitle(writer OutputWriter) func(int, string) string {
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
	columns := []string{"Severity/Risk", "ID"}
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
		row := []CellData{{writer.FormattedSeverity(violation.Severity, violation.Applicable, false)}, getCveIdsCellData(violation.Cves, violation.IssueId)}
		if writer.IsShowingCaColumn() {
			row = append(row, NewCellData(violation.Applicable))
		}
		row = append(row,
			getDirectDependenciesCellData(violation.Components),
			NewCellData(fmt.Sprintf("%s:%s", violation.ImpactedDependencyName, violation.ImpactedDependencyVersion)),
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

func getDecoratorWithLicenseViolationTitle(writer OutputWriter) func(int, string) string {
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
			NewCellData(writer.FormattedSeverity(license.Severity, "Applicable", false)),
			NewCellData(license.LicenseKey),
			getDirectDependenciesCellData(license.Components),
			NewCellData(fmt.Sprintf("%s:%s", license.ImpactedDependencyName, license.ImpactedDependencyVersion)),
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
			content = append(content, writer.MarkAsDetails(
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
	noHeaderTable := NewMarkdownTable("", "")

	if len(violation.Policies) > 0 {
		noHeaderTable.AddRowWithCellData(NewCellData(MarkAsBold("Policies:")), NewCellData(violation.Policies...))
	}
	noHeaderTable.AddRow(MarkAsBold("Full Name:"), violation.LicenseName)

	return noHeaderTable.Build()
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

func getDecoratorWithScaVulnerabilitiesTitle(writer OutputWriter) func(int, string) string {
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
		row := []CellData{{writer.FormattedSeverity(vulnerability.Severity, vulnerability.Applicable, false)}, getCveIdsCellData(vulnerability.Cves, vulnerability.IssueId)}
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

func GetApplicabilityDescriptionTable(severity, cve, impactedDependency, finding string, writer OutputWriter) string {
	table := NewMarkdownTable("Severity", "Impacted Dependency", "Finding", "CVE").AddRow(writer.FormattedSeverity(severity, "Applicable", false), impactedDependency, finding, cve)
	return table.Build()
}

// JAS

func getJasIssueDescriptionTable(issue formats.SourceCodeRow, writer OutputWriter) string {
	columns := []string{"Severity"}
	rowData := []string{writer.FormattedSeverity(issue.Severity, "Applicable", false)}
	// Optional issueId column (as stored at the platform)
	if issue.IssueId != "" {
		columns = append(columns, "ID")
		rowData = append(rowData, issue.IssueId)
	}
	columns = append(columns, "Finding")
	rowData = append(rowData, issue.Finding)
	return NewMarkdownTable(columns...).AddRow(rowData...).Build()
}

func getJasFullDescription(issue formats.SourceCodeRow, violation bool, issueDescTable string, writer OutputWriter) string {
	var contentBuilder strings.Builder
	// Write the vulnerability/violation details
	WriteContent(&contentBuilder, writer.MarkAsDetails(fmt.Sprintf("%s Details", getIssueType(violation)), 4, issueDescTable))
	// Separator
	WriteNewLine(&contentBuilder)
	// Write the description
	WriteContent(&contentBuilder, issue.ScannerDescription)
	return contentBuilder.String()
}

func getBaseJasDetailsTable(watch string, policies, cwe []string, writer OutputWriter) *MarkdownTableBuilder {
	noHeaderTable := NewMarkdownTable("", "").SetDelimiter(writer.Separator())
	// For Violations
	if len(policies) > 0 {
		noHeaderTable.AddRowWithCellData(NewCellData(MarkAsBold("Policies:")), NewCellData(policies...))
	}
	if watch != "" {
		noHeaderTable.AddRow(MarkAsBold("Watch Name:"), watch)
	}
	// General CWE attribute if exists
	if len(cwe) > 0 {
		noHeaderTable.AddRowWithCellData(NewCellData(MarkAsBold("CWE:")), NewCellData(cwe...))
	}
	return noHeaderTable
}

func IacReviewContent(issue formats.SourceCodeRow, violation bool, writer OutputWriter) string {
	var contentBuilder strings.Builder
	WriteContent(&contentBuilder,
		writer.MarkAsTitle(fmt.Sprintf("%s %s", iacTitle, getIssueType(violation)), 2),
		writer.MarkInCenter(getJasIssueDescriptionTable(issue, writer)),
		writer.MarkAsDetails("Full description", 3, getIacFullDescription(issue, violation, writer)),
	)
	return contentBuilder.String()
}

func getIacFullDescription(issue formats.SourceCodeRow, violation bool, writer OutputWriter) string {
	return getJasFullDescription(issue, violation, getBaseJasDetailsTable(issue.Watch, issue.Policies, issue.CWE, writer).Build(), writer)
}

func SastReviewContent(issue formats.SourceCodeRow, violation bool, writer OutputWriter) string {
	var contentBuilder strings.Builder
	WriteContent(&contentBuilder,
		writer.MarkAsTitle(fmt.Sprintf("%s %s", sastTitle, getIssueType(violation)), 2),
		writer.MarkInCenter(getJasIssueDescriptionTable(issue, writer)),
		writer.MarkAsDetails("Full description", 3, getSastFullDescription(issue, violation, writer)),
	)
	if len(issue.CodeFlow) > 0 {
		WriteContent(&contentBuilder, writer.MarkAsDetails("Code Flows", 3, sastCodeFlowsReviewContent(issue.CodeFlow, writer)))
	}
	return contentBuilder.String()
}

func getSastFullDescription(issue formats.SourceCodeRow, violation bool, writer OutputWriter) string {
	table := getBaseJasDetailsTable(issue.Watch, issue.Policies, issue.CWE, writer)
	table.AddRow(MarkAsBold("Rule ID:"), issue.RuleId)
	return getJasFullDescription(issue, violation, table.Build(), writer)
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

func SecretReviewContent(issue formats.SourceCodeRow, violation bool, writer OutputWriter) string {
	applicability := ""
	if issue.Applicability != nil {
		applicability = issue.Applicability.Status
	}
	var contentBuilder strings.Builder
	WriteContent(&contentBuilder,
		writer.MarkAsTitle(fmt.Sprintf("%s %s", secretsTitle, getIssueType(violation)), 2),
		writer.MarkInCenter(getSecretsDescriptionTable(issue.Severity, issue.IssueId, issue.Finding, applicability, writer)),
		writer.MarkAsDetails("Full description", 3, getSecretsFullDescription(issue, violation, writer)),
	)
	return contentBuilder.String()
}

func getSecretsDescriptionTable(severity, issueId, finding, status string, writer OutputWriter) string {
	// Determine the issue applicable status
	applicability := jasutils.Applicable.String()
	if status != "" {
		if status == jasutils.Inactive.String() {
			applicability = jasutils.NotApplicable.String()
		}
	}
	columns := []string{"Severity"}
	rowData := []string{writer.FormattedSeverity(severity, applicability, false)}
	// Determine if issueId is provided
	if issueId != "" {
		columns = append(columns, "ID")
		rowData = append(rowData, issueId)
	}
	columns = append(columns, "Finding")
	rowData = append(rowData, finding)
	// Determine if status is provided
	if status != "" {
		columns = append(columns, "Status")
		rowData = append(rowData, status)
	}
	return NewMarkdownTable(columns...).AddRow(rowData...).Build()
}

func getSecretsFullDescription(issue formats.SourceCodeRow, violation bool, writer OutputWriter) string {
	table := getBaseJasDetailsTable(issue.Watch, issue.Policies, issue.CWE, writer)
	table.AddRow(MarkAsBold("Abbreviation:"), issue.RuleId)
	return getJasFullDescription(issue, violation, table.Build(), writer)
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
		dependencies = append(dependencies, fmt.Sprintf("%s:%s", component.Name, component.Version))
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
			content = append(content, writer.MarkAsDetails(
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
	WriteContent(&contentBuilder, writer.MarkAsTitle(fmt.Sprintf("%s Details", getIssueType(violations)), 3))
	// Details Table
	directComponent := []string{}
	for _, component := range issue.ImpactedDependencyDetails.Components {
		directComponent = append(directComponent, fmt.Sprintf("%s:%s", component.Name, component.Version))
	}
	noHeaderTable := NewMarkdownTable("", "")
	if len(issue.Policies) > 0 {
		noHeaderTable.AddRowWithCellData(NewCellData(MarkAsBold("Policies:")), NewCellData(issue.Policies...))
	}
	if issue.Watch != "" {
		noHeaderTable.AddRow(MarkAsBold("Watch Name:"), issue.Watch)
	}
	if issue.JfrogResearchInformation != nil && issue.JfrogResearchInformation.Severity != "" {
		noHeaderTable.AddRow(MarkAsBold("Jfrog Research Severity:"), writer.FormattedSeverity(issue.JfrogResearchInformation.Severity, "Applicable", true))
	}
	if issue.Applicable != "" {
		noHeaderTable.AddRow(MarkAsBold("Contextual Analysis:"), issue.Applicable)
	}
	noHeaderTable.AddRowWithCellData(NewCellData(MarkAsBold("Direct Dependencies:")), NewCellData(directComponent...))
	noHeaderTable.AddRow(MarkAsBold("Impacted Dependency:"), fmt.Sprintf("%s:%s", issue.ImpactedDependencyName, issue.ImpactedDependencyVersion))
	noHeaderTable.AddRowWithCellData(NewCellData(MarkAsBold("Fixed Versions:")), NewCellData(issue.FixedVersions...))

	cvss := []string{}
	for _, cve := range issue.Cves {
		cvss = append(cvss, cve.CvssV3)
	}
	noHeaderTable.AddRowWithCellData(NewCellData(MarkAsBold("CVSS V3:")), NewCellData(cvss...))
	WriteContent(&contentBuilder, noHeaderTable.Build())

	// Summary
	if issue.Summary != "" {
		WriteContent(&contentBuilder, issue.Summary)
	}

	// Jfrog Research Details
	if issue.JfrogResearchInformation == nil {
		return contentBuilder.String()
	}
	WriteContent(&contentBuilder, writer.MarkAsTitle(jfrogResearchDetailsSubTitle, 3))

	if issue.JfrogResearchInformation.Details != "" {
		WriteNewLine(&contentBuilder)
		WriteContent(&contentBuilder, MarkAsBold("Description:"), issue.JfrogResearchInformation.Details)
	}
	if issue.JfrogResearchInformation.Remediation != "" {
		WriteNewLine(&contentBuilder)
		WriteContent(&contentBuilder, MarkAsBold("Remediation:"), issue.JfrogResearchInformation.Remediation)
	}

	return contentBuilder.String()
}

// TODO: DELETE

// func VulnerabilitiesContent(vulnerabilities []formats.VulnerabilityOrViolationRow, writer OutputWriter) (content []string) {
// 	if len(vulnerabilities) == 0 {
// 		return []string{}
// 	}
// 	content = append(content, writer.MarkAsTitle(vulnerableDependenciesTitle, 2))
// 	content = append(content, vulnerabilitiesSummaryContent(vulnerabilities, writer))
// 	content = append(content, vulnerabilityDetailsContent(vulnerabilities, writer)...)
// 	return
// }

// func vulnerabilitiesSummaryContent(vulnerabilities []formats.VulnerabilityOrViolationRow, writer OutputWriter) string {
// 	var contentBuilder strings.Builder
// 	WriteContent(&contentBuilder,
// 		writer.MarkAsTitle("✍️ Summary", 3),
// 		writer.MarkInCenter(getVulnerabilitiesSummaryTable(vulnerabilities, writer)),
// 	)
// 	return contentBuilder.String()
// }

// type vulnerabilityOrViolationDetails struct {
// 	details           string
// 	title             string
// 	dependencyName    string
// 	dependencyVersion string
// }

// func vulnerabilityDetailsContent(vulnerabilities []formats.VulnerabilityOrViolationRow, writer OutputWriter) (content []string) {
// 	vulnerabilitiesWithDetails := getVulnerabilityWithDetails(vulnerabilities)
// 	if len(vulnerabilitiesWithDetails) == 0 {
// 		return
// 	}
// 	// Prepare content for each vulnerability details
// 	for i := range vulnerabilitiesWithDetails {
// 		if len(vulnerabilitiesWithDetails) == 1 {
// 			content = append(content, vulnerabilitiesWithDetails[i].details)
// 		} else {
// 			content = append(content, writer.MarkAsDetails(
// 				fmt.Sprintf(`%s %s %s`, vulnerabilitiesWithDetails[i].title,
// 					vulnerabilitiesWithDetails[i].dependencyName,
// 					vulnerabilitiesWithDetails[i].dependencyVersion),
// 				4, vulnerabilitiesWithDetails[i].details,
// 			))
// 		}
// 	}
// 	// Split content if it exceeds the size limit and decorate it with title
// 	return ConvertContentToComments(content, writer, func(commentCount int, detailsContent string) string {
// 		contentBuilder := strings.Builder{}
// 		WriteContent(&contentBuilder, writer.MarkAsTitle(jfrogResearchDetailsSubTitle, 3))
// 		WriteContent(&contentBuilder, detailsContent)
// 		return contentBuilder.String()
// 	})
// }

// func getVulnerabilityWithDetails(vulnerabilities []formats.VulnerabilityOrViolationRow) (vulnerabilitiesWithDetails []vulnerabilityOrViolationDetails) {
// 	for i := range vulnerabilities {
// 		vulDescriptionContent := createVulnerabilityResearchDescription(&vulnerabilities[i])
// 		if vulDescriptionContent == "" {
// 			// No content
// 			continue
// 		}
// 		vulnerabilitiesWithDetails = append(vulnerabilitiesWithDetails, vulnerabilityOrViolationDetails{
// 			details:           vulDescriptionContent,
// 			title:             getScaCveIdentifier(vulnerabilities[i].Cves, vulnerabilities[i].IssueId),
// 			dependencyName:    vulnerabilities[i].ImpactedDependencyName,
// 			dependencyVersion: vulnerabilities[i].ImpactedDependencyVersion,
// 		})
// 	}
// 	return
// }

// func getScaCveIdentifier(cveRows []formats.CveRow, xrayId string) string {
// 	identifier := results.GetIssueIdentifier(cveRows, xrayId, ", ")
// 	if identifier == "" {
// 		return ""
// 	}
// 	return fmt.Sprintf("[ %s ]", identifier)
// }

// func createVulnerabilityResearchDescription(vulnerability *formats.VulnerabilityOrViolationRow) string {
// 	var descriptionBuilder strings.Builder
// 	vulnResearch := vulnerability.JfrogResearchInformation
// 	if vulnResearch == nil {
// 		vulnResearch = &formats.JfrogResearchInformation{Details: vulnerability.Summary}
// 	} else if vulnResearch.Details == "" {
// 		vulnResearch.Details = vulnerability.Summary
// 	}

// 	if vulnResearch.Details != "" {
// 		WriteContent(&descriptionBuilder, MarkAsBold("Description:"), vulnResearch.Details)
// 	}
// 	if vulnResearch.Remediation != "" {
// 		if vulnResearch.Details != "" {
// 			WriteNewLine(&descriptionBuilder)
// 		}
// 		WriteContent(&descriptionBuilder, MarkAsBold("Remediation:"), vulnResearch.Remediation)
// 	}
// 	return descriptionBuilder.String()
// }
