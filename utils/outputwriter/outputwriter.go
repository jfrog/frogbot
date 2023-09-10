package outputwriter

import (
	"fmt"
	"github.com/jfrog/froggit-go/vcsutils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-core/v2/xray/formats"
	xrayutils "github.com/jfrog/jfrog-cli-core/v2/xray/utils"
	"strings"
)

const (
	FrogbotTitlePrefix                               = "[🐸 Frogbot]"
	CommentGeneratedByFrogbot                        = "[JFrog Frogbot](https://github.com/jfrog/frogbot#readme)"
	vulnerabilitiesTableHeader                       = "\n| SEVERITY                | DIRECT DEPENDENCIES                  | IMPACTED DEPENDENCY                   | FIXED VERSIONS                       | CVES                       |\n| :---------------------: | :----------------------------------: | :-----------------------------------: | :---------------------------------: | :---------------------------------: |"
	vulnerabilitiesTableHeaderWithContextualAnalysis = "| SEVERITY                | CONTEXTUAL ANALYSIS                  | DIRECT DEPENDENCIES                  | IMPACTED DEPENDENCY                   | FIXED VERSIONS                       | CVES                       |\n| :---------------------: | :----------------------------------: | :----------------------------------: | :-----------------------------------: | :---------------------------------: | :---------------------------------: |"
	iacTableHeader                                   = "\n| SEVERITY                | FILE                  | LINE:COLUMN                   | FINDING                       |\n| :---------------------: | :----------------------------------: | :-----------------------------------: | :---------------------------------: |"
	vulnerableDependenciesTitle                      = "## 📦 Vulnerable Dependencies"
	dependenciesSummaryTitle                         = "### ✍️ Summary"
	researchDetailsTitle                             = "## 🔬 Research Details"
	iacTitle                                         = "## 🛠️ Infrastructure as Code"
	licenseTitle                                     = "## ⚖️ Violated Licenses"
	licenseTableHeader                               = "\n| LICENSE                | DIRECT DEPENDENCIES                  | IMPACTED DEPENDENCY                   | \n| :---------------------: | :----------------------------------: | :-----------------------------------: |"
	SecretsEmailCSS                                  = `body {
            font-family: Arial, sans-serif;
            background-color: #f5f5f5;
        }
        table {
            border-collapse: collapse;
            width: 80%;
        }
        th, td {
            padding: 10px;
            border: 1px solid #ccc;
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
        .table-container {
            max-width: 700px;
            padding: 20px;
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
            border-radius: 10px;
            overflow: hidden;
            background-color: #fff;
			margin-top: 10px;
        }
        .ignore-comments {
            margin-top: 10px;
			margin-bottom: 5px;
            border-radius: 5px;
        }`
	//#nosec G101 -- full secrets would not be hard coded
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
	<div>
		The following potential exposed secrets in your <a href="%s">%s</a> have been detected by <a href="https://github.com/jfrog/frogbot#readme">Frogbot</a>
		<br/>
		<table class="table-container">
            <thead>
                <tr>
                    <th>FILE</th>
                    <th>LINE:COLUMN</th>
                    <th>SECRET</th>
                </tr>
            </thead>
            <tbody>
                %s
            </tbody>
        </table>
		<div class="ignore-comments">
		<b>NOTE:</b> If you'd like Frogbot to ignore the lines with the potential secrets, add a comment that includes the <b>jfrog-ignore</b> keyword above the lines with the secrets.	
		</div>
	</div>
</body>
</html>`
	//#nosec G101 -- full secrets would not be hard coded
	SecretsEmailTableRow = `
				<tr>
					<td> %s </td>
					<td> %s </td>
					<td> %s </td>
				</tr>`
)

// The OutputWriter interface allows Frogbot output to be written in an appropriate way for each git provider.
// Some git providers support markdown only partially, whereas others support it fully.
type OutputWriter interface {
	VulnerabilitiesTableRow(vulnerability formats.VulnerabilityOrViolationRow) string
	LicensesContent(licenses []formats.LicenseRow) string
	NoVulnerabilitiesTitle() string
	VulnerabilitiesTitle(isComment bool) string
	VulnerabilitiesContent(vulnerabilities []formats.VulnerabilityOrViolationRow) string
	IacContent(iacRows []formats.SourceCodeRow) string
	Footer() string
	Separator() string
	FormattedSeverity(severity, applicability string) string
	IsFrogbotResultComment(comment string) bool
	SetJasOutputFlags(entitled, showCaColumn bool)
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

func createVulnerabilityDescription(vulnerability *formats.VulnerabilityOrViolationRow) string {
	var descriptionBuilder strings.Builder
	vulnResearch := vulnerability.JfrogResearchInformation
	if vulnResearch == nil {
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

	if descriptionBuilder.Len() == 0 {
		return ""
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

func getIacTableContent(iacRows []formats.SourceCodeRow, writer OutputWriter) string {
	var tableContent strings.Builder
	for _, iac := range iacRows {
		tableContent.WriteString(fmt.Sprintf("\n| %s | %s | %s | %s |", writer.FormattedSeverity(iac.Severity, xrayutils.Applicable.String()), iac.File, iac.LineColumn, iac.Text))
	}
	return tableContent.String()
}

func getLicensesTableContent(licenses []formats.LicenseRow, writer OutputWriter) string {
	var tableContent strings.Builder
	for _, license := range licenses {
		var directDependenciesBuilder strings.Builder
		for _, component := range license.Components {
			directDependenciesBuilder.WriteString(fmt.Sprintf("%s %s%s", component.Name, component.Version, writer.Separator()))
		}
		directDependencies := strings.TrimSuffix(directDependenciesBuilder.String(), writer.Separator())
		impactedDependency := fmt.Sprintf("%s %s", license.ImpactedDependencyName, license.ImpactedDependencyVersion)
		tableContent.WriteString(fmt.Sprintf("\n| %s | %s | %s |", license.LicenseKey, directDependencies, impactedDependency))
	}
	return tableContent.String()
}

func MarkdownComment(text string) string {
	return fmt.Sprintf("\n[comment]: <> (%s)\n", text)
}

func GetAggregatedPullRequestTitle(tech coreutils.Technology) string {
	if tech.String() == "" {
		return FrogbotTitlePrefix + " Update dependencies"
	}
	return fmt.Sprintf("%s Update %s dependencies", FrogbotTitlePrefix, tech.ToFormal())
}

func getVulnerabilitiesTableHeader(showCaColumn bool) string {
	if showCaColumn {
		return vulnerabilitiesTableHeaderWithContextualAnalysis
	}
	return vulnerabilitiesTableHeader
}

func convertCveRowsToCveIds(cveRows []formats.CveRow, seperator string) string {
	cvesBuilder := strings.Builder{}
	for _, cve := range cveRows {
		if cve.Id != "" {
			cvesBuilder.WriteString(fmt.Sprintf("%s%s", cve.Id, seperator))
		}
	}
	return strings.TrimSuffix(cvesBuilder.String(), seperator)
}

func getTableRowCves(row formats.VulnerabilityOrViolationRow, writer OutputWriter) string {
	cves := convertCveRowsToCveIds(row.Cves, writer.Separator())
	if cves == "" {
		cves = " - "
	}
	return cves
}

func GetTableRowsFixedVersions(row formats.VulnerabilityOrViolationRow, writer OutputWriter) string {
	fixedVersions := strings.Join(row.FixedVersions, writer.Separator())
	if fixedVersions == "" {
		fixedVersions = " - "
	}
	return strings.TrimSuffix(fixedVersions, writer.Separator())
}

func getVulnerabilityCvesPrefix(cveRows []formats.CveRow) string {
	if len(cveRows) == 0 {
		return ""
	}
	cves := convertCveRowsToCveIds(cveRows, ", ")
	return fmt.Sprintf("[ %s ] ", cves)
}
