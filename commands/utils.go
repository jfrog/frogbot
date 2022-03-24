package commands

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/froggit-go/vcsutils"
	coreconfig "github.com/jfrog/jfrog-cli-core/v2/utils/config"
)

type imageSource string
type vcsProvider string
type frogbotLabel string

type DoNotScan struct {
	reason string
}

func (m *DoNotScan) Error() string {
	return m.reason
}

const (
	baseResourceUrl = "https://raw.githubusercontent.com/jfrog/frogbot/dev/resources/"

	// Images
	NoVulnerabilityBannerSource imageSource = "noVulnerabilityBanner.png"
	VulnerabilitiesBannerSource imageSource = "vulnerabilitiesBanner.png"
	criticalSeveritySource      imageSource = "criticalSeverity.png"
	highSeveritySource          imageSource = "highSeverity.png"
	mediumSeveritySource        imageSource = "mediumSeverity.png"
	lowSeveritySource           imageSource = "lowSeverity.png"

	// VCS providers params
	gitHub vcsProvider = "github"
	gitLab vcsProvider = "gitlab"

	// Frogbot label
	labelName        frogbotLabel = "🐸 frogbot"
	labelDescription frogbotLabel = "triggers frogbot scan"
	labelColor       frogbotLabel = "4AB548"

	// JFrog platform environment varialbes
	jfrogUserEnv           = "JF_USER"
	jfrogUrlEnv            = "JF_URL"
	jfrogXrayUrlEnv        = "JF_XRAY_URL"
	jfrogArtifactoryUrlEnv = "JF_ARTIFACTORY_URL"
	jfrogPasswordEnv       = "JF_PASSWORD"
	jfrogTokenEnv          = "JF_TOKEN"
	jfrogWatchesEnv        = "JF_WATCHES"
	jfrogProjectEnv        = "JF_PROJECT"

	// Git environment variables
	gitProvider     = "JF_GIT_PROVIDER"
	gitRepoOwnerEnv = "JF_GIT_OWNER"
	gitRepoEnv      = "JF_GIT_REPO"
	//#nosec G101 -- False positive - no hardcoded credentials.
	gitTokenEnv         = "JF_GIT_TOKEN"
	gitBaseBranchEnv    = "JF_GIT_BASE_BRANCH"
	gitPullRequestIDEnv = "JF_GIT_PULL_REQUEST_ID"
	watchesDelimiter    = ","
)

func getParamsAndClient(includeJFrogEnv bool) (*FrogbotParams, vcsclient.VcsClient, error) {
	params, err := extractParamsFromEnv(includeJFrogEnv)
	if err != nil {
		return nil, nil, err
	}
	client, err := vcsclient.NewClientBuilder(params.gitProvider).Token(params.token).Build()
	return &params, client, err
}

func chdir(dir string) (func(), error) {
	wd, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	err = os.Chdir(dir)
	if err != nil {
		return nil, err
	}
	return func() {
		e := os.Chdir(wd)
		if err == nil {
			err = e
		}
	}, nil
}

func GetIconTag(imageSource imageSource) string {
	return fmt.Sprintf("![](%s)", baseResourceUrl+imageSource)
}

func GetIconSource(iconName string) (imageSource imageSource) {
	switch strings.ToLower(iconName) {
	case "critical":
		return criticalSeveritySource
	case "high":
		return highSeveritySource
	case "medium":
		return mediumSeveritySource
	case "low":
		return lowSeveritySource
	}
	return
}

type FrogbotParams struct {
	jfrogEnvParams
	gitParam
}

type jfrogEnvParams struct {
	server  coreconfig.ServerDetails
	project string
	watches string
}
type gitParam struct {
	gitProvider   vcsutils.VcsProvider
	repoOwner     string
	token         string
	repo          string
	baseBranch    string
	pullRequestID int
}

func extractParamsFromEnv(includeJFrogEnv bool) (FrogbotParams, error) {
	params := &FrogbotParams{}
	if includeJFrogEnv {
		if err := extractJFrogParamsFromEnv(params); err != nil {
			return *params, err
		}
	}
	err := extractGitParamsFromEnv(params)
	return *params, err
}

func extractJFrogParamsFromEnv(params *FrogbotParams) error {
	url := strings.TrimSuffix(os.Getenv(jfrogUrlEnv), "/")
	xrUrl := strings.TrimSuffix(os.Getenv(jfrogXrayUrlEnv), "/")
	rtUrl := strings.TrimSuffix(os.Getenv(jfrogArtifactoryUrlEnv), "/")
	if xrUrl != "" && rtUrl != "" {
		params.server.XrayUrl = xrUrl + "/"
		params.server.ArtifactoryUrl = rtUrl + "/"
	} else {
		if url == "" {
			return fmt.Errorf("%s or %s and %s are missing", jfrogUrlEnv, jfrogXrayUrlEnv, jfrogArtifactoryUrlEnv)
		}
		params.server.Url = url + "/"
		params.server.XrayUrl = url + "/xray/"
		params.server.ArtifactoryUrl = url + "/artifactory/"
	}

	password := os.Getenv(jfrogPasswordEnv)
	user := os.Getenv(jfrogUserEnv)
	if password != "" && user != "" {
		params.server.User = user
		params.server.Password = password
	} else if accessToken := os.Getenv(jfrogTokenEnv); accessToken != "" {
		params.server.AccessToken = accessToken
	} else {
		return fmt.Errorf("%s and %s or %s are missing", jfrogUserEnv, jfrogPasswordEnv, jfrogTokenEnv)
	}
	// Non mandatory Xray context params
	params.watches = os.Getenv(jfrogWatchesEnv)
	params.project = os.Getenv(jfrogProjectEnv)
	return nil
}

func extractGitParamsFromEnv(params *FrogbotParams) error {
	var err error
	if params.gitProvider, err = extractVcsProviderFromEnv(); err != nil {
		return err
	}
	if params.repoOwner = os.Getenv(gitRepoOwnerEnv); params.repoOwner == "" {
		return fmt.Errorf("%s is missing", gitRepoOwnerEnv)
	}
	if params.repo = os.Getenv(gitRepoEnv); params.repo == "" {
		return fmt.Errorf("%s is missing", gitRepoEnv)
	}
	if params.token = os.Getenv(gitTokenEnv); params.token == "" {
		return fmt.Errorf("%s is missing", gitTokenEnv)
	}
	if params.baseBranch = os.Getenv(gitBaseBranchEnv); params.baseBranch == "" {
		return fmt.Errorf("%s is missing", gitBaseBranchEnv)
	}
	if pullRequestIDString := os.Getenv(gitPullRequestIDEnv); pullRequestIDString != "" {
		params.pullRequestID, err = strconv.Atoi(pullRequestIDString)
		return err
	}
	return fmt.Errorf("%s is missing", gitPullRequestIDEnv)
}

func extractVcsProviderFromEnv() (vcsutils.VcsProvider, error) {
	vcsProvider := strings.ToLower(os.Getenv(gitProvider))
	switch vcsProvider {
	case string(gitHub):
		return vcsutils.GitHub, nil
	case string(gitLab):
		return vcsutils.GitLab, nil
	}

	return 0, fmt.Errorf("%s should be one of: '%s' or '%s'", gitProvider, gitHub, gitLab)
}
