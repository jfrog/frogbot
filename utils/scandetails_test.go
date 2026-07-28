package utils

import (
	"testing"

	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	xscservices "github.com/jfrog/jfrog-client-go/xsc/services"
	"github.com/stretchr/testify/assert"
)

func TestSetResultsContext_PropagatesWorkspaceName(t *testing.T) {
	git := &Git{Workspace: "my-workspace"}
	sc := NewScanDetails(nil, &config.ServerDetails{}, git)

	sc.SetResultsContext("https://example.com/org/repo.git", "proj", true)

	assert.Equal(t, "my-workspace", sc.ResultContext.WorkspaceName)
}

func TestSetResultsContext_EmptyWorkspaceKeepsFieldEmpty(t *testing.T) {
	git := &Git{}
	sc := NewScanDetails(nil, &config.ServerDetails{}, git)

	sc.SetResultsContext("https://example.com/org/repo.git", "proj", true)

	assert.Empty(t, sc.ResultContext.WorkspaceName)
}

func TestXscGitInfoContext_WorkspaceNameField(t *testing.T) {
	// Guards against upstream removing the field: keeps Frogbot's plumbing honest.
	ctx := xscservices.XscGitInfoContext{WorkspaceName: "ws"}
	assert.Equal(t, "ws", ctx.WorkspaceName)
}
