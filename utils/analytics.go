package utils

import (
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray/services"
	xscservices "github.com/jfrog/jfrog-client-go/xsc/services"
	"os"
	"strings"
)

func AddAnalyticsGeneralEvent(gitInfoContext *services.XscGitInfoContext, serverDetails *config.ServerDetails, scanType string) *utils.AnalyticsMetricsService {
	log.Debug("Initiating General Event report to Analytics service")
	analyticsService := utils.NewAnalyticsMetricsService(serverDetails)
	if !analyticsService.ShouldReportEvents() {
		return analyticsService
	}
	analyticsService.AddGeneralEvent(createAnalyticsGeneralEvent(analyticsService, gitInfoContext, scanType))
	if analyticsService.GetMsi() != "" {
		analyticsService.SetFinalizeEvent(&xscservices.XscAnalyticsGeneralEventFinalize{MultiScanId: analyticsService.GetMsi()})
	} else {
		analyticsService.SetShouldReportEvents(false)
	}
	return analyticsService
}

func createAnalyticsGeneralEvent(analyticsService *utils.AnalyticsMetricsService, gitInfo *services.XscGitInfoContext, scanType string) *xscservices.XscAnalyticsGeneralEvent {
	generalEvent := analyticsService.CreateGeneralEvent(xscservices.FrogbotProduct, xscservices.FrogbotType)
	generalEvent.ProductVersion = FrogbotVersion
	generalEvent.FrogbotScanType = scanType
	generalEvent.FrogbotCiProvider = resolveCi()
	if gitInfo != nil {
		generalEvent.GitInfo = gitInfo
		generalEvent.IsGitInfoFlow = true
	}
	return generalEvent
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
