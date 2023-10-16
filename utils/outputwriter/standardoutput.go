package outputwriter

import (
	"fmt"
	"strings"
)

type StandardOutput struct {
	MarkdownOutput
}

func (so *StandardOutput) Separator() string {
	return "<br>"
}

func (so *StandardOutput) FormattedSeverity(severity, applicability string) string {
	return fmt.Sprintf("%s%8s", getSeverityTag(IconName(severity), applicability), severity)
}

func (so *StandardOutput) Image(source ImageSource) string {
	return GetBanner(source)
}

func (so *StandardOutput) MarkInCenter(content string) string {
	return GetMarkdownCenterTag(content)
}

func (so *StandardOutput) MarkAsDetails(summary string, subTitleDepth int, content string) string {
	if summary != "" {
		summary = fmt.Sprintf("<summary> <b>%s</b> </summary>\n<br>\n", summary)
	}
	return fmt.Sprintf("<details>\n%s\n%s\n\n</details>\n", summary, content)
}

func (so *StandardOutput) MarkAsTitle(title string, subTitleDepth int) string {
	return fmt.Sprintf("%s %s", strings.Repeat("#", subTitleDepth), title)
}

func GetMarkdownCenterTag(content string) string {
	return fmt.Sprintf("<div align='center'>\n\n%s\n\n</div>\n", content)
}
