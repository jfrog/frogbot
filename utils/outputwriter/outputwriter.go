package outputwriter

import (
	"fmt"

	"github.com/jfrog/froggit-go/vcsutils"
)

const (
	// vulnerabilitiesTableHeader                       = "\n| SEVERITY                | DIRECT DEPENDENCIES                  | IMPACTED DEPENDENCY                   | FIXED VERSIONS                       | CVES                       |\n| :---------------------: | :----------------------------------: | :-----------------------------------: | :---------------------------------: | :---------------------------------: |"
	// vulnerabilitiesTableHeaderWithContextualAnalysis = "| SEVERITY                | CONTEXTUAL ANALYSIS                  | DIRECT DEPENDENCIES                  | IMPACTED DEPENDENCY                   | FIXED VERSIONS                       | CVES                       |\n| :---------------------: | :----------------------------------: | :----------------------------------: | :-----------------------------------: | :---------------------------------: | :---------------------------------: |"
	// iacTableHeader                                   = "\n| SEVERITY                | FILE                  | LINE:COLUMN                   | FINDING                       |\n| :---------------------: | :----------------------------------: | :-----------------------------------: | :---------------------------------: |"
	// licenseTableHeader                               = "\n| LICENSE                | DIRECT DEPENDENCIES                  | IMPACTED DEPENDENCY                   | \n| :---------------------: | :----------------------------------: | :-----------------------------------: |"
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
					<td> %d:%d </td>
					<td> %s </td>
				</tr>`
)

// The OutputWriter interface allows Frogbot output to be written in an appropriate way for each git provider.
// Some git providers support markdown only partially, whereas others support it fully.
type OutputWriter interface {
	// Options
	SetJasOutputFlags(entitled, showCaColumn bool)
	IsShowingCaColumn() bool
	IsEntitledForJas() bool
	// VCS info
	VcsProvider() vcsutils.VcsProvider
	SetVcsProvider(provider vcsutils.VcsProvider)
	// Interface for different type of writers
	FormattedSeverity(severity, applicability string) string
	Separator() string
	MarkInCenter(content string) string
	MarkAsDetails(summary string, subTitleDepth int, content string) string
	MarkAsTitle(title string, subTitleDepth int) string
	Image(source ImageSource) string

	// TODO: maybe combine and move to reviewcomment.go
	IsFrogbotResultComment(comment string) bool

	// Removed
	// NoVulnerabilitiesTitle() string
	// VulnerabilitiesTitle(isComment bool) string
	// Footer() string
	// UntitledForJasMsg() string
	// VulnerabilitiesContent(vulnerabilities []formats.VulnerabilityOrViolationRow) string
	// VulnerabilitiesTableRow(vulnerability formats.VulnerabilityOrViolationRow) string
	// LicensesContent(licenses []formats.LicenseRow) string
}

func GetCompatibleOutputWriter(provider vcsutils.VcsProvider) OutputWriter {
	switch provider {
	case vcsutils.BitbucketServer:
		return &SimplifiedOutput{vcsProvider: provider}
	default:
		return &StandardOutput{vcsProvider: provider}
	}
}

// TODO: remove
// func getVulnerabilitiesTableContent(vulnerabilities []formats.VulnerabilityOrViolationRow, writer OutputWriter) string {
// 	var tableContent string
// 	for _, vulnerability := range vulnerabilities {
// 		tableContent += "\n" + writer.VulnerabilitiesTableRow(vulnerability)
// 	}
// 	return tableContent
// }

// TODO: remove
// func getLicensesTableContent(licenses []formats.LicenseRow, writer OutputWriter) string {
// 	var tableContent strings.Builder
// 	for _, license := range licenses {
// 		var directDependenciesBuilder strings.Builder
// 		for _, component := range license.Components {
// 			directDependenciesBuilder.WriteString(fmt.Sprintf("%s %s%s", component.Name, component.Version, writer.Separator()))
// 		}
// 		directDependencies := strings.TrimSuffix(directDependenciesBuilder.String(), writer.Separator())
// 		impactedDependency := fmt.Sprintf("%s %s", license.ImpactedDependencyName, license.ImpactedDependencyVersion)
// 		tableContent.WriteString(fmt.Sprintf("\n| %s | %s | %s |", license.LicenseKey, directDependencies, impactedDependency))
// 	}
// 	return tableContent.String()
// }

func MarkdownComment(text string) string {
	return fmt.Sprintf("\n\n[comment]: <> (%s)\n", text)
}

func MarkAsBold(content string) string {
	return fmt.Sprintf("**%s**", content)
}

func MarkAsQuote(content string) string {
	return fmt.Sprintf("`%s`", content)
}

func MarkAsLink(content, link string) string {
	return fmt.Sprintf("[%s](%s)", content, link)
}

func SectionDivider() string {
	return "\n---\n"
}

func MarkAsCodeSnippet(snippet string) string {
	return fmt.Sprintf("```\n%s\n```", snippet)
}

// TODO: remove
// func getVulnerabilitiesTableHeader(showCaColumn bool) string {
// 	if showCaColumn {
// 		return vulnerabilitiesTableHeaderWithContextualAnalysis
// 	}
// 	return vulnerabilitiesTableHeader
// }

// // TODO: remove
// func getTableRowCves(row formats.VulnerabilityOrViolationRow, writer OutputWriter) string {
// 	cves := convertCveRowsToCveIds(row.Cves, writer.Separator())
// 	if cves == "" {
// 		cves = " - "
// 	}
// 	return cves
// }

// TODO: remove
// func convertCveRowsToCveIds(cveRows []formats.CveRow, separator string) string {
// 	cvesBuilder := strings.Builder{}
// 	for _, cve := range cveRows {
// 		if cve.Id != "" {
// 			cvesBuilder.WriteString(fmt.Sprintf("%s%s", cve.Id, separator))
// 		}
// 	}
// 	return strings.TrimSuffix(cvesBuilder.String(), separator)
// }

// TODO: remove
// func GetTableRowsFixedVersions(row formats.VulnerabilityOrViolationRow, writer OutputWriter) string {
// 	fixedVersions := strings.Join(row.FixedVersions, writer.Separator())
// 	if fixedVersions == "" {
// 		fixedVersions = " - "
// 	}
// 	return strings.TrimSuffix(fixedVersions, writer.Separator())
// }
