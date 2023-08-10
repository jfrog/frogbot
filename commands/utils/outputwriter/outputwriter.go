package outputwriter

import (
	"fmt"
	//"github.com/jfrog/frogbot/commands/utils"
	"github.com/jfrog/froggit-go/vcsutils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-core/v2/xray/formats"
	xrayutils "github.com/jfrog/jfrog-cli-core/v2/xray/utils"
	"strings"
)

const (
	FrogbotPullRequestTitlePrefix                    = "[🐸 Frogbot]"
	CommentGeneratedByFrogbot                        = "[JFrog Frogbot](https://github.com/jfrog/frogbot#readme)"
	vulnerabilitiesTableHeader                       = "\n| SEVERITY                | DIRECT DEPENDENCIES                  | IMPACTED DEPENDENCY                   | FIXED VERSIONS                       |\n| :---------------------: | :----------------------------------: | :-----------------------------------: | :---------------------------------: |"
	vulnerabilitiesTableHeaderWithContextualAnalysis = "| SEVERITY                | CONTEXTUAL ANALYSIS                  | DIRECT DEPENDENCIES                  | IMPACTED DEPENDENCY                   | FIXED VERSIONS                       |\n| :---------------------: | :----------------------------------: | :----------------------------------: | :-----------------------------------: | :---------------------------------: |"
	iacTableHeader                                   = "\n| SEVERITY                | FILE                  | LINE:COLUMN                   | FINDING                       |\n| :---------------------: | :----------------------------------: | :-----------------------------------: | :---------------------------------: |"
	SecretsEmailCSS                                  = `body {
            text-align: center;
            font-family: Arial, sans-serif;
        }
        a img {
            display: block;
            margin: 0 auto;
            max-width: 100%;
        }
        table {
            margin: 20px auto;
            border-collapse: collapse;
            width: 80%;
        }
        th, td {
            padding: 10px;
            border: 1px solid #ccc;
            text-align: center;
        }
        th {
            background-color: #f2f2f2;
        }
        tr:nth-child(even) {
            background-color: #f9f9f9;
        }
        tr:hover {
            background-color: #f5f5f5;
        }
        img.severity-icon {
            max-height: 30px;
            vertical-align: middle;
        }
        h1 {
            font-size: 24px;
            color: #333;
            margin-bottom: 20px;
        }
        .table-container {
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
            border-radius: 10px;
            overflow: hidden;
            background-color: #fff;
        }`
	SecretsEmailHTMLTemplate = `
<!DOCTYPE html>
<html>
<head>
    <title>Frogbot Secret Detection</title>
    <style>
        %s
    </style>
</head>
<body>
    <div align="center" class="table-container">
        <a href="https://github.com/jfrog/frogbot#readme">
            <img src="%s" alt="Banner">
        </a>ֿ
        <table>
            <thead>
                <tr>
                    <th>SEVERITY</th>
                    <th>FILE</th>
                    <th>LINE:COLUMN</th>
                    <th>TEXT</th>
                </tr>
            </thead>
            <tbody>
                %s
            </tbody>
        </table>
    </div>
	%s
</body>
</html>`
	SecretsEmailTableRow = `
				<tr>
					<td><img class="severity-icon" src="%s" alt="severity"> %s </td>
					<td> %s </td>
					<td> %s </td>
					<td> %s </td>
				</tr>`
)

type OutputContext int

const (
	PullRequestScan OutputContext = 0
	RepositoryScan  OutputContext = 1
)

// The OutputWriter interface allows Frogbot output to be written in an appropriate way for each git provider.
// Some git providers support markdown only partially, whereas others support it fully.
type OutputWriter interface {
	VulnerabilitiesTableRow(vulnerability formats.VulnerabilityOrViolationRow) string
	NoVulnerabilitiesTitle() string
	VulnerabilitiesTitle(outputContext OutputContext) string
	VulnerabilitiesContent(vulnerabilities []formats.VulnerabilityOrViolationRow) string
	IacContent(iacRows []formats.IacSecretsRow) string
	Footer() string
	Separator() string
	FormattedSeverity(severity, applicability string) string
	IsFrogbotResultComment(comment string) bool
	SetJasOutputFlags(entitled, showCaColumn bool)
	VcsProvider() vcsutils.VcsProvider
	SetVcsProvider(provider vcsutils.VcsProvider)
	UntitledForJasMsg() string
	SetOutputContext(outputContext OutputContext)
	OutputContext() OutputContext
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

	cvesTitle := "**CVE:**"
	if len(cves) > 1 {
		cvesTitle = "**CVEs:**"
	}

	fixedVersionsTitle := "**Fixed Version:**"
	if len(vulnerability.FixedVersions) > 1 {
		fixedVersionsTitle = "**Fixed Versions:**"
	}

	descriptionBullets := []descriptionBullet{
		{title: "**Severity**", value: fmt.Sprintf("%s %s", xrayutils.GetSeverity(vulnerability.Severity, xrayutils.ApplicableStringValue).Emoji(), vulnerability.Severity)},
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

	vulnResearch := vulnerability.JfrogResearchInformation
	if vulnerability.JfrogResearchInformation == nil {
		vulnResearch = &formats.JfrogResearchInformation{Details: vulnerability.Summary}
	}

	// Write description if exists:
	if vulnResearch.Details != "" {
		descriptionBuilder.WriteString(fmt.Sprintf("\n**Description:**\n\n%s\n\n", vulnResearch.Details))
	}

	// Write remediation if exists
	if vulnResearch.Remediation != "" {
		descriptionBuilder.WriteString(fmt.Sprintf("**Remediation:**\n\n%s\n\n", vulnResearch.Remediation))
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
		tableContent += fmt.Sprintf("\n| %s | %s | %s | %s |", writer.FormattedSeverity(iac.Severity, xrayutils.ApplicableStringValue), iac.File, iac.LineColumn, iac.Text)
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

func getVulnerabilitiesTableHeader(showCaColumn bool) string {
	if showCaColumn {
		return vulnerabilitiesTableHeaderWithContextualAnalysis
	}
	return vulnerabilitiesTableHeader
}

func GetVulnerabilitiesTitleImagePath(outputContext OutputContext, provider vcsutils.VcsProvider) ImageSource {
	isPrContext := outputContext == PullRequestScan
	path := VulnerabilitiesFixPrBannerSource // Default value

	if isPrContext {
		if provider == vcsutils.GitLab {
			path = VulnerabilitiesMrBannerSource
		} else {
			path = VulnerabilitiesPrBannerSource
		}
	} else {
		if provider == vcsutils.GitLab {
			path = VulnerabilitiesFixMrBannerSource
		}
	}

	return getFullResourceUrl(path)
}
