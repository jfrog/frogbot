package outputwriter

import (
	"fmt"
	"strings"

	"github.com/jfrog/froggit-go/vcsutils"
)

type StandardOutput struct {
	showCaColumn   bool
	entitledForJas bool
	vcsProvider    vcsutils.VcsProvider
}

func (so *StandardOutput) SetVcsProvider(provider vcsutils.VcsProvider) {
	so.vcsProvider = provider
}

func (so *StandardOutput) VcsProvider() vcsutils.VcsProvider {
	return so.vcsProvider
}

func (so *StandardOutput) SetJasOutputFlags(entitled, showCaColumn bool) {
	so.entitledForJas = entitled
	so.showCaColumn = showCaColumn
}

func (so *StandardOutput) IsShowingCaColumn() bool {
	return so.showCaColumn
}

func (so *StandardOutput) IsEntitledForJas() bool {
	return so.entitledForJas
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
	return fmt.Sprintf(`
<div align='center'>

%s

</div>`, content)
}

func (so *StandardOutput) MarkAsDetails(summary string, subTitleDepth int, content string) string {
	return fmt.Sprintf(`
<details>
<summary> <b>%s</b> </summary>
<br>
%s

</details>`, summary, content)
}

func (so *StandardOutput) MarkAsTitle(title string, subTitleDepth int) string {
	return fmt.Sprintf("%s %s", strings.Repeat("#", subTitleDepth), title)
}
