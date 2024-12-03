package outputwriter

import (
	"fmt"
	"strings"

	"github.com/jfrog/frogbot/v2/utils/issues"
	"github.com/jfrog/froggit-go/vcsutils"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/severityutils"
)

const (
	FrogbotTitlePrefix      = "[🐸 Frogbot]"
	FrogbotRepoUrl          = "https://github.com/jfrog/frogbot"
	FrogbotDocumentationUrl = "https://docs.jfrog-applications.jfrog.io/jfrog-applications/frogbot"
	ReviewCommentId         = "FrogbotReviewComment"

	scanSummaryTitle = "📊 Scan Summary"

	policyViolationTitle      = "🚥 Policy Violations"
	securityViolationTitle    = "🚨 Security Violations"
	licenseViolationTitle     = "📜 License Violations"
	violationsDetailsSubTitle = "🔖 Details"

	vulnerableDependenciesTitle                   = "📦 Vulnerable Dependencies"
	vulnerableDependenciesResearchDetailsSubTitle = "🔬 Research Details"

	contextualAnalysisTitle = "📦🔍 Contextual Analysis CVE"
	iacTitle                = "🛠️ Infrastructure as Code"
	sastTitle               = "🎯 Static Application Security Testing (SAST) Vulnerability"
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

// Summary content

func scanSummaryContent(issues issues.ScansIssuesCollection, violations bool, writer OutputWriter) string {
	var contentBuilder strings.Builder
	issueType := "vulnerabilities"
	if violations {
		issueType = "violations"
	}
	// Title
	WriteContent(&contentBuilder,
		writer.MarkAsTitle(scanSummaryTitle, 2),
		fmt.Sprintf("▶️ Frogbot scanned for %s and found %d issues", issueType, issues.GetTotalViolations()),
	)
	// Summary
	scaStatus, scaFailed := getSubScanResultStatus(issues.ScaScanPerformed, issues.ScaScanStatus)
	applicabilityStatus, _ := getSubScanResultStatus(issues.ApplicabilityScanPerformed, issues.ApplicabilityScanStatus)
	sastStatus, sastFailed := getSubScanResultStatus(issues.SastScanPerformed, issues.SastScanStatus)
	secretsStatus, secretsFailed := getSubScanResultStatus(issues.SecretsScanPerformed, issues.SecretsScanStatus)
	iacStatus, iacFailed := getSubScanResultStatus(issues.IacScan, issues.IacScanStatus)
	// Create table, a row for each sub scans summary
	table := NewMarkdownTable("Scan Category", "Result", "Security Issues")
	table.AddRow(MarkAsBold("Software Composition Analysis"), scaStatus, getScanSecurityIssuesDetails(issues, utils.ScaScan, scaFailed, violations, writer))
	table.AddRow(MarkAsBold("Contextual Analysis"), applicabilityStatus, "")
	table.AddRow(MarkAsBold("Static Application Security Testing (SAST)"), sastStatus, getScanSecurityIssuesDetails(issues, utils.SastScan, sastFailed, violations, writer))
	table.AddRow(MarkAsBold("Secrets"), secretsStatus, getScanSecurityIssuesDetails(issues, utils.SecretsScan, secretsFailed, violations, writer))
	table.AddRow(MarkAsBold("Infrastructure as Code (IaC)"), iacStatus, getScanSecurityIssuesDetails(issues, utils.IacScan, iacFailed, violations, writer))
	WriteContent(&contentBuilder, writer.MarkInCenter(table.Build()))
	// link to the scan results in JFrog
	// WriteNewLine(&contentBuilder)
	// WriteContent(&contentBuilder, writer.MarkInCenter(MarkAsLink("See the results of the scan in JFrog", "an-url")))
	return contentBuilder.String()
}

func getSubScanResultStatus(scanPerformed bool, statusCode int) (string, bool) {
	if !scanPerformed {
		return "ℹ️ Not Scanned", false
	}
	if statusCode == 0 {
		return "✅ Done", false
	}
	return "❌ Failed", true
}

func getScanSecurityIssuesDetails(issues issues.ScansIssuesCollection, scanType utils.SubScanType, failed, violation bool, writer OutputWriter) string {
	if failed || (scanType == utils.ScaScan && !issues.ScaScanPerformed) || (scanType == utils.SastScan && !issues.SastScanPerformed) || (scanType == utils.SecretsScan && !issues.SecretsScanPerformed) || (scanType == utils.IacScan && !issues.IacScan) {
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
	WriteContent(&contentBuilder, writer.MarkAsDetails(fmt.Sprintf("%d Issues Found", getTotalIssues(severityCountMap)), 3, toSeverityDetails(severityCountMap, writer)))
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

// Policy Violations

// Summary content for the security violations that we can't yet have location on (SCA, License)
func SecurityViolationsContent(issues issues.ScansIssuesCollection, writer OutputWriter) (content []string) {
	if issues.GetTotalViolations() == 0 {
		return []string{}
	}
	// Violations Summary
	content = append(content, scanSummaryContent(issues, true, writer))
	// Policy Violations Content
	policyViolationContent := append(getSecurityViolationsContent(issues, writer), getLicenseViolationsContent(issues, writer)...)
	return append(content, ConvertContentToComments(policyViolationContent, writer, getDecoratorWithPolicyViolationTitle(writer))...)
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
	content = append(content, getSecurityViolationsSummaryTable(issues.ScaViolations, writer))
	content = append(content, getSecurityViolationsDetailsContent(issues.ScaViolations, writer)...)
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
		row := []CellData{{writer.FormattedSeverity(violation.Severity, violation.Applicable)}}
		if writer.IsShowingCaColumn() {
			row = append(row, NewCellData(violation.Applicable))
		}
		row = append(row,
			getDirectDependenciesCellData("%s:%s", violation.Components),
			NewCellData(fmt.Sprintf("%s %s", violation.ImpactedDependencyName, violation.ImpactedDependencyVersion)),
			NewCellData(violation.FixedVersions...),
			getCveIdsCellData(violation.Cves, violation.IssueId),
		)
		table.AddRowWithCellData(row...)
	}
	return writer.MarkInCenter(table.Build())
}

func getImpactedComponentLocationIfDirectDependency(impactedComponent formats.ImpactedDependencyDetails) string {
	component := getComponentIfDirect(impactedComponent)
	if component != nil && component.Location != nil {
		return component.Location.File
	}
	return ""
}

func getComponentIfDirect(impactedComponent formats.ImpactedDependencyDetails) (component *formats.ComponentRow) {
	for _, c := range impactedComponent.Components {
		// Check if the impacted component is a direct dependency
		if c.Name == impactedComponent.ImpactedDependencyName && c.Version == impactedComponent.ImpactedDependencyVersion {
			return &c
		}
	}
	return
}

func getSecurityViolationsDetailsContent(violations []formats.VulnerabilityOrViolationRow, writer OutputWriter) (content []string) {
	if len(violations) == 0 {
		return
	}
	for _, violation := range violations {
		if len(violations) == 1 {
			content = append(content, getScaSecurityViolationDetails(violation, writer))
		} else {
			content = append(content, writer.MarkAsDetails(getViolationDescriptionIdentifier(violation), 5, getScaSecurityViolationDetails(violation, writer)))
		}
	}
	// Split content if it exceeds the size limit and decorate it with title
	return ConvertContentToComments(content, writer, func(commentCount int, detailsContent string) string {
		contentBuilder := strings.Builder{}
		WriteContent(&contentBuilder, writer.MarkAsTitle(violationsDetailsSubTitle, 4))
		WriteContent(&contentBuilder, detailsContent)
		return contentBuilder.String()
	})
}

func getViolationDescriptionIdentifier(violation formats.VulnerabilityOrViolationRow) string {
	return fmt.Sprintf(`%s %s %s (%s)`, getVulnerabilityDescriptionIdentifier(violation.Cves, violation.IssueId), violation.ImpactedDependencyName, violation.ImpactedDependencyVersion, violation.Watch)
}

func getScaSecurityViolationDetails(violation formats.VulnerabilityOrViolationRow, writer OutputWriter) (content string) {
	directComponent := []string{}
	for _, component := range violation.ImpactedDependencyDetails.Components {
		directComponent = append(directComponent, fmt.Sprintf("%s:%s", component.Name, component.Version))
	}
	table := getBaseDependencyViolationDetailsTable(
		directComponent,
		fmt.Sprintf("%s:%s", violation.ImpactedDependencyName, violation.ImpactedDependencyVersion),
		violation.Severity,
		"Security",
		violation.Watch,
		violation.Policies,
		writer,
	)
	if writer.IsShowingCaColumn() {
		table.AddRow(MarkAsBold("Contextual Analysis:"), violation.Applicable)
	}
	if violation.JfrogResearchInformation != nil {
		table.AddRow(MarkAsBold("Jfrog Research Severity:"), violation.JfrogResearchInformation.Severity)
	}
	if len(violation.FixedVersions) > 0 {
		table.AddRow(MarkAsBold("Fixed Versions:"), strings.Join(violation.FixedVersions, ", "))
	}
	if len(violation.Cves) > 0 {
		cvssV3 := []string{}
		for _, cve := range violation.Cves {
			cvssV3 = append(cvssV3, cve.CvssV3)
		}
		table.AddRow(MarkAsBold("CVSS V3:"), strings.Join(cvssV3, ", "))
	}
	var contentBuilder strings.Builder
	WriteContent(&contentBuilder, table.Build(), fmt.Sprintf("%s: %s", MarkAsBold("Description"), violation.Summary))
	return contentBuilder.String()
}

// License violations

func getLicenseViolationsContent(issues issues.ScansIssuesCollection, writer OutputWriter) (content []string) {
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
	if len(licenses) == 0 {
		return ""
	}
	// Title
	var contentBuilder strings.Builder
	WriteContent(&contentBuilder, writer.MarkAsTitle("⚖️ Violated Licenses", 2))
	// Content
	table := NewMarkdownTable("Severity", "ID", "Direct Dependencies", "Impacted Dependency", "Watch Name").SetDelimiter(writer.Separator())
	if _, ok := writer.(*SimplifiedOutput); ok {
		// The values in this cell can be potentially large, since SimplifiedOutput does not support tags, we need to show each value in a separate row.
		// It means that the first row will show the full details, and the following rows will show only the direct dependency.
		// It makes it easier to read the table and less crowded with text in a single cell that could be potentially large.
		table.GetColumnInfo("Direct Dependencies").ColumnType = MultiRowColumn
	}
	for _, license := range licenses {
		table.AddRowWithCellData(
			NewCellData(license.Severity),
			NewCellData(license.LicenseKey),
			getDirectDependenciesCellData("%s %s", license.Components),
			NewCellData(fmt.Sprintf("%s %s", license.ImpactedDependencyName, license.ImpactedDependencyVersion)),
			NewCellData(license.Watch),
		)
	}
	WriteContent(&contentBuilder, writer.MarkInCenter(table.Build()))
	return contentBuilder.String()
}

func getLicenseViolationsDetailsContent(licenseViolations []formats.LicenseViolationRow, writer OutputWriter) (content []string) {
	if len(licenseViolations) == 0 {
		return
	}
	// for _, violation := range licenseViolations {
	// 	if len(licenseViolations) == 1 {
	// 		content = append(content, getScaLicenseViolationDetails(violation, writer))
	// 	} else {
	// 		content = append(content, writer.MarkAsDetails(getViolationDescriptionIdentifier(violation), 5, getScaLicenseViolationDetails(violation, writer)))
	// 	}
	// }
	// Split content if it exceeds the size limit and decorate it with title
	return ConvertContentToComments(content, writer, func(commentCount int, detailsContent string) string {
		contentBuilder := strings.Builder{}
		WriteContent(&contentBuilder, writer.MarkAsTitle(violationsDetailsSubTitle, 4))
		WriteContent(&contentBuilder, detailsContent)
		return contentBuilder.String()
	})
}

func getJasSecurityViolationDetails(severity, violationType, watch string, policies []string, writer OutputWriter) string {
	table := getBaseViolationDetailsTable(severity, violationType, watch, policies, writer)

	return table.Build()
}

func getSecretsSecurityViolationDetails(severity, violationType, watch string, policies []string, writer OutputWriter) string {
	// table := getBaseDependencyViolationDetailsTable(severity, violationType, watch, policies, writer)

	// return table.Build()
	return ""
}

func getBaseViolationDetailsTable(severity, violationType, watch string, policies []string, writer OutputWriter) *MarkdownTableBuilder {
	noHeaderTable := NewMarkdownTable("", "")

	noHeaderTable.AddRow(MarkAsBold("Violation Severity:"), severity)
	noHeaderTable.AddRow(MarkAsBold("Type:"), violationType)
	noHeaderTable.AddRow(MarkAsBold("Policies:"), strings.Join(policies, ", "))
	noHeaderTable.AddRow(MarkAsBold("Watch name:"), watch)

	return noHeaderTable
}

func getBaseDependencyViolationDetailsTable(direct []string, impacted, severity, violationType, watch string, policies []string, writer OutputWriter) *MarkdownTableBuilder {
	noHeaderTable := getBaseViolationDetailsTable(severity, violationType, watch, policies, writer)

	noHeaderTable.AddRow(MarkAsBold("Direct Dependency:"), strings.Join(direct, ", "))
	noHeaderTable.AddRow(MarkAsBold("Impacted Dependency:"), impacted)

	return noHeaderTable
}

// func getBaseJasViolationDetailsTable(ruleId, file, line, severity, violationType, watch string, policies []string, writer OutputWriter) *MarkdownTableBuilder {
// 	noHeaderTable := getBaseViolationDetailsTable(severity, violationType, watch, policies, writer)

// 	noHeaderTable.AddRow(MarkAsBold("Rule ID:"), ruleId)
// 	noHeaderTable.AddRow(MarkAsBold("File Path:"), file)
// 	noHeaderTable.AddRow(MarkAsBold("Line:"), line)

// 	return noHeaderTable
// }

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
			getCveIdsCellData(vulnerability.Cves, vulnerability.IssueId),
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

func getCveIdsCellData(cveRows []formats.CveRow, issueId string) (ids CellData) {
	if len(cveRows) == 0 {
		return NewCellData(issueId)
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

func LicensesContent(licenses []formats.LicenseViolationRow, writer OutputWriter) string {
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

// JAS

func getJasDescriptionTable(severity, finding string, writer OutputWriter) string {
	return NewMarkdownTable("Severity", "Finding").AddRow(writer.FormattedSeverity(severity, "Applicable"), finding).Build()
}

func IacReviewContent(severity, finding, fullDetails string, writer OutputWriter) string {
	var contentBuilder strings.Builder
	WriteContent(&contentBuilder,
		writer.MarkAsTitle(fmt.Sprintf("%s Vulnerability", iacTitle), 2),
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

// Jas Violation

func getJasViolationFullDescription(issue formats.SourceCodeRow, tableDetailsContent string, writer OutputWriter) string {
	var contentBuilder strings.Builder
	// Write the violation details
	WriteContent(&contentBuilder, writer.MarkAsDetails("Violation Details", 4, tableDetailsContent))
	// Separator
	WriteNewLine(&contentBuilder)
	// Write the description
	WriteContent(&contentBuilder, issue.ScannerDescription)
	return contentBuilder.String()
}

func IacViolationReviewContent(issue formats.SourceCodeRow, writer OutputWriter) string {
	var contentBuilder strings.Builder
	WriteContent(&contentBuilder,
		writer.MarkAsTitle(fmt.Sprintf("%s Violation", iacTitle), 2),
		writer.MarkInCenter(getJasIssueDescriptionTable(issue, writer)),
		writer.MarkAsDetails("Full description", 3, getIacViolationFullDescription(issue, writer)),
	)
	return contentBuilder.String()
}

func getJasIssueDescriptionTable(issue formats.SourceCodeRow, writer OutputWriter) string {
	columns := []string{"Severity"}
	rowData := []string{writer.FormattedSeverity(issue.Severity, "Applicable")}
	// Optional ID column
	if issue.IssueId != "" {
		columns = append(columns, "ID")
		rowData = append(rowData, issue.IssueId)
	}
	columns = append(columns, "Finding")
	rowData = append(rowData, issue.Finding)
	return NewMarkdownTable(columns...).AddRow(rowData...).Build()
}

func getIacViolationFullDescription(issue formats.SourceCodeRow, writer OutputWriter) string {
	return getJasViolationFullDescription(issue, getBaseJasViolationDetailsTable(issue.Watch, issue.Policies, []string{issue.CWE}, writer).Build(), writer)
}

func getBaseJasViolationDetailsTable(watch string, policies, cwe []string, writer OutputWriter) *MarkdownTableBuilder {
	noHeaderTable := NewMarkdownTable("", "").SetDelimiter(writer.Separator())
	if len(policies) > 0 {
		noHeaderTable.AddRowWithCellData(NewCellData(MarkAsBold("Policies:")), NewCellData(policies...))
	}
	if watch != "" {
		noHeaderTable.AddRow(MarkAsBold("Watch Name:"), watch)
	}
	if len(cwe) > 0 {
		noHeaderTable.AddRowWithCellData(NewCellData(MarkAsBold("CWE:")), NewCellData(cwe...))
	}
	return noHeaderTable
}

func SastViolationReviewContent(issue formats.SourceCodeRow, writer OutputWriter) string {
	var contentBuilder strings.Builder
	WriteContent(&contentBuilder,
		writer.MarkAsTitle(fmt.Sprintf("%s Violation", sastTitle), 2),
		writer.MarkInCenter(getJasIssueDescriptionTable(issue, writer)),
		writer.MarkAsDetails("Full description", 3, getSastViolationFullDescription(issue, writer)),
	)

	if len(issue.CodeFlow) > 0 {
		WriteContent(&contentBuilder, writer.MarkAsDetails("Code Flows", 3, sastCodeFlowsReviewContent(issue.CodeFlow, writer)))
	}

	return contentBuilder.String()
}

func getSastViolationFullDescription(issue formats.SourceCodeRow, writer OutputWriter) string {
	table := getBaseJasViolationDetailsTable(issue.Watch, issue.Policies, []string{issue.CWE}, writer)
	table.AddRow(MarkAsBold("Rule ID:"), issue.RuleId)
	return getJasViolationFullDescription(issue, table.Build(), writer)
}
