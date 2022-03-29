package utils

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/froggit-go/vcsutils"
	coreconfig "github.com/jfrog/jfrog-cli-core/v2/utils/config"
)

type FrogbotParams struct {
	JFrogEnvParams
	GitParam
	InstallCommandName string
	InstallCommandArgs []string
}

type JFrogEnvParams struct {
	Server  coreconfig.ServerDetails
	Project string
	Watches string
}
type GitParam struct {
	GitProvider   vcsutils.VcsProvider
	RepoOwner     string
	Token         string
	Repo          string
	BaseBranch    string
	PullRequestID int
}

func GetParamsAndClient() (*FrogbotParams, vcsclient.VcsClient, error) {
	params, err := extractParamsFromEnv()
	if err != nil {
		return nil, nil, err
	}
	client, err := vcsclient.NewClientBuilder(params.GitProvider).Token(params.Token).Build()
	return &params, client, err
}

func extractParamsFromEnv() (FrogbotParams, error) {
	params := &FrogbotParams{}
	extractInstallationCommandFromEnv(params)
	if err := extractJFrogParamsFromEnv(params); err != nil {
		return *params, err
	}

	err := extractGitParamsFromEnv(params)
	return *params, err
}

func extractJFrogParamsFromEnv(params *FrogbotParams) error {
	url := strings.TrimSuffix(os.Getenv(jfrogUrlEnv), "/")
	xrUrl := strings.TrimSuffix(os.Getenv(jfrogXrayUrlEnv), "/")
	rtUrl := strings.TrimSuffix(os.Getenv(jfrogArtifactoryUrlEnv), "/")
	if xrUrl != "" && rtUrl != "" {
		params.Server.XrayUrl = xrUrl + "/"
		params.Server.ArtifactoryUrl = rtUrl + "/"
	} else {
		if url == "" {
			return fmt.Errorf("%s or %s and %s environment variables are missing", jfrogUrlEnv, jfrogXrayUrlEnv, jfrogArtifactoryUrlEnv)
		}
		params.Server.Url = url + "/"
		params.Server.XrayUrl = url + "/xray/"
		params.Server.ArtifactoryUrl = url + "/artifactory/"
	}

	password := os.Getenv(jfrogPasswordEnv)
	user := os.Getenv(jfrogUserEnv)
	if password != "" && user != "" {
		params.Server.User = user
		params.Server.Password = password
	} else if accessToken := os.Getenv(jfrogTokenEnv); accessToken != "" {
		params.Server.AccessToken = accessToken
	} else {
		return fmt.Errorf("%s and %s or %s environment variables are missing", jfrogUserEnv, jfrogPasswordEnv, jfrogTokenEnv)
	}
	// Non mandatory Xray context params
	params.Watches = os.Getenv(jfrogWatchesEnv)
	params.Project = os.Getenv(jfrogProjectEnv)
	return nil
}

func extractGitParamsFromEnv(params *FrogbotParams) error {
	var err error
	if params.GitProvider, err = extractVcsProviderFromEnv(); err != nil {
		return err
	}
	if params.RepoOwner = os.Getenv(gitRepoOwnerEnv); params.RepoOwner == "" {
		return &errMissingEnv{gitRepoOwnerEnv}
	}
	if params.Repo = os.Getenv(gitRepoEnv); params.Repo == "" {
		return &errMissingEnv{gitRepoEnv}
	}
	if params.Token = os.Getenv(gitTokenEnv); params.Token == "" {
		return &errMissingEnv{gitTokenEnv}
	}
	if params.BaseBranch = os.Getenv(gitBaseBranchEnv); params.BaseBranch == "" {
		return &errMissingEnv{gitBaseBranchEnv}
	}
	if pullRequestIDString := os.Getenv(gitPullRequestIDEnv); pullRequestIDString != "" {
		params.PullRequestID, err = strconv.Atoi(pullRequestIDString)
		return err
	}
	return &errMissingEnv{gitPullRequestIDEnv}
}

func extractInstallationCommandFromEnv(params *FrogbotParams) {
	installCommand := strings.TrimSpace(os.Getenv(installCommandEnv))
	if installCommand == "" {
		return
	}
	parts := strings.Fields(installCommand)
	if len(parts) > 1 {
		params.InstallCommandArgs = parts[1:]
	}
	params.InstallCommandName = parts[0]
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
