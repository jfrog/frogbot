package utils

import (
	"os"
	"strings"

	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-security/utils/xsc"
	xscservices "github.com/jfrog/jfrog-client-go/xsc/services"
)

func CreateScanEvent(serviceDetails *config.ServerDetails, gitInfo *xscservices.XscGitInfoContext, scanType string) *xscservices.XscAnalyticsGeneralEvent {
	event := xsc.CreateAnalyticsEvent(xscservices.FrogbotProduct, xscservices.FrogbotType, serviceDetails)
	event.ProductVersion = FrogbotVersion
	event.FrogbotScanType = scanType
	event.FrogbotCiProvider = resolveCi()
	if gitInfo != nil {
		event.GitInfo = gitInfo
		event.IsGitInfoFlow = true
	}
	return event
}

// Returns the CI system that is currently running the command.
func resolveCi() string {
	switch {
	case strings.ToLower(os.Getenv("GITHUB_ACTIONS")) == "true":
		return string(githubActions)
	case strings.ToLower(os.Getenv("GITLAB_CI")) == "true":
		return string(gitlab)
	case os.Getenv("JENKINS_URL") != "":
		return string(jenkins)
	case strings.ToLower(os.Getenv("TF_BUILD")) == "true":
		return string(azurePipelines)
	// Currently, there isn't an environment variable specifically designed to identify JFrog Pipelines.
	default:
		return ""
	}
}
