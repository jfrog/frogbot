package outputwriter

import (
	"fmt"
	"strings"

	"github.com/jfrog/jfrog-cli-security/utils/severityutils"
)

type StandardOutput struct {
	MarkdownOutput
}

func (so *StandardOutput) Separator() string {
	return "<br>"
}

func (so *StandardOutput) SeverityIcon(severity severityutils.Severity) string {
	if !so.hasInternetConnection {
		return severityutils.GetSeverityIcon(severity)
	}
	return getSmallSeverityTag(IconName(severity))

}

func (so *StandardOutput) FormattedSeverity(severity, applicability string) string {
	if !so.hasInternetConnection {
		return severity
	}
	return fmt.Sprintf("%s%8s", getSeverityTag(IconName(severity), applicability), severity)
}

func (so *StandardOutput) Image(source ImageSource) string {
	if so.hasInternetConnection {
		return GetBanner(source)
	}
	return MarkAsBold(GetSimplifiedTitle(source))
}

func (so *StandardOutput) MarkInCenter(content string) string {
	return GetMarkdownCenterTag(content)
}

func (so *StandardOutput) MarkAsDetails(summary string, subTitleDepth int, content string) string {
	if summary != "" {
		summary = fmt.Sprintf("<summary><b>%s</b></summary>", summary)
	}
	return fmt.Sprintf("<details>%s%s<br></details>", summary, content)
}

func (so *StandardOutput) MarkAsTitle(title string, subTitleDepth int) string {
	if subTitleDepth == 0 {
		return title
	}
	return fmt.Sprintf("%s %s", strings.Repeat("#", subTitleDepth), title)
}

func GetMarkdownCenterTag(content string) string {
	return fmt.Sprintf("<div align='center'>\n\n%s\n\n</div>\n", content)
}
