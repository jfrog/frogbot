package utils

import (
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-client-go/xray/services"
	xscservices "github.com/jfrog/jfrog-client-go/xsc/services"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestCreateAnalyticsGeneralEvent(t *testing.T) {
	gitInfoContext := &services.XscGitInfoContext{
		GitRepoUrl:    "http://localhost:8080/my-user/my-project.git",
		GitRepoName:   "my-project",
		GitProject:    "my-user",
		GitProvider:   "GitHub",
		Technologies:  nil,
		BranchName:    "main",
		LastCommit:    "https://api.github.com/repos/my-user/my-project/commits/a23ba44a0d379dida668nmb72003a82e4e11d0ba",
		CommitHash:    "a23ba44a0d379dida668nmb72003a82e4e11d0ba",
		CommitMessage: ".",
		CommitAuthor:  "User",
	}

	serverDetails := &config.ServerDetails{
		Url:            "http://localhost:8080/",
		ArtifactoryUrl: "http://localhost:8080/artifactory/",
		XscUrl:         "http://localhost:8080/xray/",
		User:           "user",
		Password:       "password",
	}

	analyticsService := utils.NewAnalyticsMetricsService(serverDetails)
	analyticsGeneralEvent := createAnalyticsGeneralEvent(analyticsService, gitInfoContext, "monitor")

	// Comparison is made manually for selected fields since some of the fields are machine-dependent and cannot be known in advance
	assert.Equal(t, xscservices.FrogbotType, analyticsGeneralEvent.EventType)
	assert.Equal(t, xscservices.Started, analyticsGeneralEvent.EventStatus)
	assert.Equal(t, xscservices.FrogbotProduct, analyticsGeneralEvent.Product)
	assert.Equal(t, "user", analyticsGeneralEvent.JfrogUser)
	assert.Equal(t, "monitor", analyticsGeneralEvent.FrogbotScanType)
}
