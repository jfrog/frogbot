package utils

import (
	"testing"

	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
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
