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

const (
	githubActionsCi  = "github-actions"
	jenkinsCi        = "jenkins"
	gitlabCi         = "gitlab"
	azurePipelinesCi = "azure-pipelines"
	jfrogPipelinesCi = "jfrog-pipelines"
)

func AddAnalyticsGeneralEvent(gitInfoContext *services.XscGitInfoContext, serverDetails *config.ServerDetails, scanType string) *utils.AnalyticsMetricsService {
	log.Debug("Initiating General Event report to Analytics service")
	analyticsService := utils.NewAnalyticsMetricsService(serverDetails)
	if !analyticsService.ShouldReportEvents() {
		return analyticsService
	}
	analyticsGeneralEvent := createAnalyticsGeneralEvent(analyticsService, gitInfoContext, scanType)
	analyticsService.AddGeneralEvent(analyticsGeneralEvent)
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
	generalEvent.GitInfo = gitInfo
	// In case we have git info to send, we consider the flow an GitInfoFlow and set this parameter to 'true'
	// TODO ERAN re-apply this field after the issue with is_gitinfo_flow is resolved
	// generalEvent.IsGitInfoFlow = true

	return generalEvent

	/* TODO ERAN
	at the finalizing event add the following:
	TotalFindings: in scan-pr subtract the results to present only new ones
	TotalIgnoredFindings
	TotalScanDuration
	*/
}

func resolveCi() string {
	switch {
	case strings.ToLower(os.Getenv("GITHUB_ACTIONS")) == "true":
		return githubActionsCi
	case strings.ToLower(os.Getenv("GITLAB_CI")) == "true":
		return gitlabCi
	case os.Getenv("JENKINS_URL") != "":
		return jenkinsCi
	case strings.ToLower(os.Getenv("TF_BUILD")) == "true":
		return azurePipelinesCi
	case strings.ToLower(os.Getenv("JFROG_PIPELINES_CI")) == "true": // TODO ERAN fix the correct env var for jfrog-pipelines
		return jfrogPipelinesCi
	default:
		return ""
	}
}
