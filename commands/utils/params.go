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
	ApiEndpoint   string
	PullRequestID int
}

func GetParamsAndClient() (*FrogbotParams, vcsclient.VcsClient, error) {
	params, err := extractParamsFromEnv()
	if err != nil {
		return nil, nil, err
	}
	client, err := vcsclient.NewClientBuilder(params.GitProvider).ApiEndpoint(params.ApiEndpoint).Token(params.Token).Build()
	return &params, client, err
}

func extractParamsFromEnv() (FrogbotParams, error) {
	params := &FrogbotParams{}
	extractInstallationCommandFromEnv(params)
	if err := extractJFrogParamsFromEnv(params); err != nil {
		return *params, err
	}

	if err := extractGitParamsFromEnv(params); err != nil {
		return *params, err
	}

	return *params, sanitizeEnv()
}

func extractJFrogParamsFromEnv(params *FrogbotParams) error {
	url := strings.TrimSuffix(os.Getenv(JFrogUrlEnv), "/")
	xrUrl := strings.TrimSuffix(os.Getenv(jfrogXrayUrlEnv), "/")
	rtUrl := strings.TrimSuffix(os.Getenv(jfrogArtifactoryUrlEnv), "/")
	if xrUrl != "" && rtUrl != "" {
		params.Server.XrayUrl = xrUrl + "/"
		params.Server.ArtifactoryUrl = rtUrl + "/"
	} else {
		if url == "" {
			return fmt.Errorf("%s or %s and %s environment variables are missing", JFrogUrlEnv, jfrogXrayUrlEnv, jfrogArtifactoryUrlEnv)
		}
		params.Server.Url = url + "/"
		params.Server.XrayUrl = url + "/xray/"
		params.Server.ArtifactoryUrl = url + "/artifactory/"
	}

	password := os.Getenv(JFrogPasswordEnv)
	user := os.Getenv(JFrogUserEnv)
	if password != "" && user != "" {
		params.Server.User = user
		params.Server.Password = password
	} else if accessToken := os.Getenv(JFrogTokenEnv); accessToken != "" {
		params.Server.AccessToken = accessToken
	} else {
		return fmt.Errorf("%s and %s or %s environment variables are missing", JFrogUserEnv, JFrogPasswordEnv, JFrogTokenEnv)
	}
	// Non mandatory Xray context params
	params.Watches = os.Getenv(jfrogWatchesEnv)
	params.Project = os.Getenv(jfrogProjectEnv)
	return nil
}

func extractGitParamsFromEnv(params *FrogbotParams) error {
	var err error
	params.ApiEndpoint = os.Getenv(GitApiEndpoint)
	if params.GitProvider, err = extractVcsProviderFromEnv(); err != nil {
		return err
	}
	if params.RepoOwner = os.Getenv(GitRepoOwnerEnv); params.RepoOwner == "" {
		return &errMissingEnv{GitRepoOwnerEnv}
	}
	if params.Repo = os.Getenv(GitRepoEnv); params.Repo == "" {
		return &errMissingEnv{GitRepoEnv}
	}
	if params.Token = os.Getenv(GitTokenEnv); params.Token == "" {
		return &errMissingEnv{GitTokenEnv}
	}
	if params.BaseBranch = os.Getenv(GitBaseBranchEnv); params.BaseBranch == "" {
		return &errMissingEnv{GitBaseBranchEnv}
	}
	if pullRequestIDString := os.Getenv(GitPullRequestIDEnv); pullRequestIDString != "" {
		params.PullRequestID, err = strconv.Atoi(pullRequestIDString)
		return err
	}
	return &errMissingEnv{GitPullRequestIDEnv}
}

func extractInstallationCommandFromEnv(params *FrogbotParams) {
	installCommand := strings.TrimSpace(os.Getenv(InstallCommandEnv))
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
	vcsProvider := strings.ToLower(os.Getenv(GitProvider))
	switch vcsProvider {
	case string(GitHub):
		return vcsutils.GitHub, nil
	case string(GitLab):
		return vcsutils.GitLab, nil
	}

	return 0, fmt.Errorf("%s should be one of: '%s' or '%s'", GitProvider, GitHub, GitLab)
}

func sanitizeEnv() error {
	for _, env := range os.Environ() {
		if !strings.HasPrefix(env, "JF_") {
			continue
		}
		envSplit := strings.Split(env, "=")
		if err := os.Unsetenv(envSplit[0]); err != nil {
			return err
		}
	}
	return nil
}
