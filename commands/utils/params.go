package utils

import (
	"fmt"
	"github.com/jfrog/jfrog-client-go/utils/log"
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
	WorkingDirectory          string
	InstallCommandName        string
	IncludeAllVulnerabilities bool
	InstallCommandArgs        []string
	SimplifiedOutput          bool
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
	extractGeneralParamsFromEnv(params)
	if err := extractJFrogParamsFromEnv(params); err != nil {
		return *params, err
	}

	if err := extractGitParamsFromEnv(params); err != nil {
		return *params, err
	}

	return *params, sanitizeEnv()
}

func extractJFrogParamsFromEnv(params *FrogbotParams) error {
	url := strings.TrimSuffix(getTrimmedEnv(JFrogUrlEnv), "/")
	xrUrl := strings.TrimSuffix(getTrimmedEnv(jfrogXrayUrlEnv), "/")
	rtUrl := strings.TrimSuffix(getTrimmedEnv(jfrogArtifactoryUrlEnv), "/")
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

	password := getTrimmedEnv(JFrogPasswordEnv)
	user := getTrimmedEnv(JFrogUserEnv)
	if password != "" && user != "" {
		params.Server.User = user
		params.Server.Password = password
	} else if accessToken := getTrimmedEnv(JFrogTokenEnv); accessToken != "" {
		params.Server.AccessToken = accessToken
	} else {
		return fmt.Errorf("%s and %s or %s environment variables are missing", JFrogUserEnv, JFrogPasswordEnv, JFrogTokenEnv)
	}
	// Non-mandatory Xray context params
	_ = readParamFromEnv(jfrogWatchesEnv, &params.Watches)
	_ = readParamFromEnv(jfrogProjectEnv, &params.Project)
	return nil
}

func extractGitParamsFromEnv(params *FrogbotParams) error {
	var err error

	// Non-mandatory Git Api Endpoint
	_ = readParamFromEnv(GitApiEndpointEnv, &params.ApiEndpoint)

	if params.GitProvider, err = extractVcsProviderFromEnv(); err != nil {
		return err
	}
	if err = readParamFromEnv(GitRepoOwnerEnv, &params.RepoOwner); err != nil {
		return err
	}
	if err = readParamFromEnv(GitRepoEnv, &params.Repo); err != nil {
		return err
	}
	if err = readParamFromEnv(GitTokenEnv, &params.Token); err != nil {
		return err
	}
	// Non-mandatory git branch and pr id.
	_ = readParamFromEnv(GitBaseBranchEnv, &params.BaseBranch)
	if pullRequestIDString := getTrimmedEnv(GitPullRequestIDEnv); pullRequestIDString != "" {
		params.PullRequestID, err = strconv.Atoi(pullRequestIDString)
		return err
	}
	return nil
}

func extractGeneralParamsFromEnv(params *FrogbotParams) {
	params.WorkingDirectory = getTrimmedEnv(WorkingDirectoryEnv)
	var err error
	includeAllIssues := getTrimmedEnv(IncludeAllVulnerabilitiesEnv)
	params.IncludeAllVulnerabilities, err = strconv.ParseBool(includeAllIssues)
	if err != nil {
		log.Info("JF_INCLUDE_ALL_VULNERABILITIES is off, the value is: ", includeAllIssues)
		params.IncludeAllVulnerabilities = false
	}
	installCommand := getTrimmedEnv(InstallCommandEnv)
	if installCommand == "" {
		return
	}
	parts := strings.Fields(installCommand)
	if len(parts) > 1 {
		params.InstallCommandArgs = parts[1:]
	}
	params.InstallCommandName = parts[0]
}

func readParamFromEnv(envKey string, paramValue *string) error {
	*paramValue = getTrimmedEnv(envKey)
	if *paramValue == "" {
		return &ErrMissingEnv{envKey}
	}
	return nil
}

func getTrimmedEnv(envKey string) string {
	return strings.TrimSpace(os.Getenv(envKey))
}

func extractVcsProviderFromEnv() (vcsutils.VcsProvider, error) {
	vcsProvider := getTrimmedEnv(GitProvider)
	switch vcsProvider {
	case string(GitHub):
		return vcsutils.GitHub, nil
	case string(GitLab):
		return vcsutils.GitLab, nil
	// For backward compatibility, we are accepting also "bitbucket server"
	case string(BitbucketServer), "bitbucket server":
		return vcsutils.BitbucketServer, nil
	}

	return 0, fmt.Errorf("%s should be one of: '%s', '%s' or '%s'", GitProvider, GitHub, GitLab, BitbucketServer)
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
