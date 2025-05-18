package outputwriter

import (
	"fmt"
	"strings"

	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/froggit-go/vcsutils"
	"github.com/jfrog/jfrog-cli-security/utils/severityutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
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
		The following potential exposed secrets in your <a href="%s">%s</a> have been detected by <a href="https://jfrog.com/help/r/jfrog-security-user-guide/developers/frogbot">Frogbot</a>
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
	SizeLimit(comment bool) int
	SetSizeLimit(client vcsclient.VcsClient)
	// VCS info
	VcsProvider() vcsutils.VcsProvider
	SetVcsProvider(provider vcsutils.VcsProvider)
	// Markdown interface
	SeverityIcon(severity severityutils.Severity) string
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
	descriptionSizeLimit    int
	commentSizeLimit        int
	vcsProvider             vcsutils.VcsProvider
}

type CommentDecorator func(int, string) string

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

func (mo *MarkdownOutput) SizeLimit(comment bool) int {
	if comment {
		return mo.commentSizeLimit
	}
	return mo.descriptionSizeLimit
}

func (mo *MarkdownOutput) SetSizeLimit(client vcsclient.VcsClient) {
	if client == nil {
		return
	}
	mo.commentSizeLimit = client.GetPullRequestCommentSizeLimit()
	mo.descriptionSizeLimit = client.GetPullRequestDetailsSizeLimit()
}

func GetMarkdownSizeLimit(client vcsclient.VcsClient) int {
	limit := client.GetPullRequestCommentSizeLimit()
	if client.GetPullRequestDetailsSizeLimit() < limit {
		limit = client.GetPullRequestDetailsSizeLimit()
	}
	return limit
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

func MarkAsBullet(content string) string {
	return fmt.Sprintf("- %s", content)
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

// ConvertContentToComments converts the given content to comments, and returns the comments as a list of strings.
// The content is split into comments based on the size limit of the output writer.
// The commentDecorators are applied to each comment.
func ConvertContentToComments(content []string, writer OutputWriter, commentDecorators ...CommentDecorator) (comments []string) {
	commentBuilder := strings.Builder{}
	for _, commentContent := range content {
		if newContent, limitReached := getContentAndResetBuilderIfLimitReached(len(comments), commentContent, &commentBuilder, writer, commentDecorators...); limitReached && newContent != "" {
			comments = append(comments, newContent)
		}
		WriteContent(&commentBuilder, commentContent)
	}
	if commentBuilder.Len() > 0 || len(content) == 0 {
		if comment := decorate(len(comments), commentBuilder.String(), commentDecorators...); comment != "" {
			comments = append(comments, comment)
		}
	}
	return
}

func getContentAndResetBuilderIfLimitReached(commentCount int, newContent string, builder *strings.Builder, writer OutputWriter, commentDecorators ...CommentDecorator) (content string, reached bool) {
	limit := writer.SizeLimit(commentCount != 0)
	if limit <= 0 {
		// No limit
		return
	}
	if builder.Len()+decoratorsSize(commentCount, commentDecorators...)+len(newContent) < limit {
		return
	}
	// Limit reached - Add the current content as a comment to the list and reset the builder
	log.Debug(fmt.Sprintf("Content size limit reached (%d), splitting. (total comments for content: %d)", limit, commentCount+1))
	content = builder.String()
	builder.Reset()
	return decorate(commentCount, content, commentDecorators...), true
}

func decorate(commentCount int, content string, commentDecorators ...CommentDecorator) string {
	for _, decorator := range commentDecorators {
		content = decorator(commentCount, content)
	}
	return content
}

func decoratorsSize(commentCount int, decorators ...CommentDecorator) (size int) {
	for _, decorator := range decorators {
		size += len(decorator(commentCount, ""))
	}
	return
}
