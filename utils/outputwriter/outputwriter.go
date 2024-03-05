package outputwriter

import (
	"fmt"
	"strings"

	"github.com/jfrog/froggit-go/vcsutils"
)

const (
	SecretsEmailCSS = `body {
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
		The following potential exposed secrets in your <a href="%s">%s</a> have been detected by <a href="https://docs.jfrog-applications.jfrog.io/jfrog-applications/frogbot">Frogbot</a>
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
	SetAvoidExtraMessages(avoidExtraMessages bool)
	AvoidExtraMessages() bool
	SetPullRequestCommentTitle(pullRequestCommentTitle string)
	PullRequestCommentTitle() string
	SetHasInternetConnection(connected bool)
	HasInternetConnection() bool
	// VCS info
	VcsProvider() vcsutils.VcsProvider
	SetVcsProvider(provider vcsutils.VcsProvider)
	// Markdown interface
	FormattedSeverity(severity, applicability string) string
	Separator() string
	MarkInCenter(content string) string
	MarkAsDetails(summary string, subTitleDepth int, content string) string
	MarkAsTitle(title string, subTitleDepth int) string
	Image(source ImageSource) string
}

type MarkdownOutput struct {
	pullRequestCommentTitle string
	avoidExtraMessages      bool
	showCaColumn            bool
	entitledForJas          bool
	hasInternetConnection   bool
	vcsProvider             vcsutils.VcsProvider
}

func (mo *MarkdownOutput) SetVcsProvider(provider vcsutils.VcsProvider) {
	mo.vcsProvider = provider
}

func (mo *MarkdownOutput) VcsProvider() vcsutils.VcsProvider {
	return mo.vcsProvider
}

func (mo *MarkdownOutput) SetAvoidExtraMessages(avoidExtraMessages bool) {
	mo.avoidExtraMessages = avoidExtraMessages
}

func (mo *MarkdownOutput) AvoidExtraMessages() bool {
	return mo.avoidExtraMessages
}

func (mo *MarkdownOutput) SetHasInternetConnection(connected bool) {
	mo.hasInternetConnection = connected
}

func (mo *MarkdownOutput) HasInternetConnection() bool {
	return mo.hasInternetConnection
}

func (mo *MarkdownOutput) SetJasOutputFlags(entitled, showCaColumn bool) {
	mo.entitledForJas = entitled
	mo.showCaColumn = showCaColumn
}

func (mo *MarkdownOutput) SetPullRequestCommentTitle(pullRequestCommentTitle string) {
	mo.pullRequestCommentTitle = pullRequestCommentTitle
}

func (mo *MarkdownOutput) IsShowingCaColumn() bool {
	return mo.showCaColumn
}

func (mo *MarkdownOutput) IsEntitledForJas() bool {
	return mo.entitledForJas
}

func (mo *MarkdownOutput) PullRequestCommentTitle() string {
	return mo.pullRequestCommentTitle
}

func GetCompatibleOutputWriter(provider vcsutils.VcsProvider) OutputWriter {
	switch provider {
	case vcsutils.BitbucketServer:
		return &SimplifiedOutput{MarkdownOutput{vcsProvider: provider, hasInternetConnection: true}}
	default:
		return &StandardOutput{MarkdownOutput{vcsProvider: provider, hasInternetConnection: true}}
	}
}

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
	return "\n---"
}

func MarkAsCodeSnippet(snippet string) string {
	return fmt.Sprintf("```\n%s\n```", snippet)
}

func WriteContent(builder *strings.Builder, contents ...string) {
	for _, content := range contents {
		fmt.Fprintf(builder, "\n%s", content)
	}
}

func WriteNewLine(builder *strings.Builder) {
	builder.WriteString("\n")
}
