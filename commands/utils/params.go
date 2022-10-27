package utils

import (
	"errors"
	"fmt"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/froggit-go/vcsutils"
	coreconfig "github.com/jfrog/jfrog-cli-core/v2/utils/config"
)

const (
	validateRepoNameExistErr = "repo name is missing. In the config file, fill out the repo name for each repository configuration"
	emptyConfigFilePathErr   = "configuration file was not provided"
)

type FrogbotConfigAggregator []FrogbotRepoConfig

type FrogbotRepoConfig struct {
	JFrogEnvParams
	GitParams
	SimplifiedOutput          bool
	IncludeAllVulnerabilities bool      `yaml:"includeAllVulnerabilities,omitempty"`
	FailOnSecurityIssues      bool      `yaml:"failOnSecurityIssues,omitempty"`
	ProjectKey                string    `yaml:"projectKey,omitempty"`
	RepoName                  string    `yaml:"repoName,omitempty"`
	Projects                  []Project `yaml:"projects,omitempty"`
	Watches                   []string  `yaml:"watches,omitempty"`
}

type Project struct {
	InstallCommandName string   `yaml:"installCommandName,omitempty"`
	InstallCommandArgs []string `yaml:"installCommandArgs,omitempty"`
	RequirementsFile   string   `yaml:"requirementsFile,omitempty"`
	WorkingDir         []string `yaml:"workingDir,omitempty"`
	UseWrapper         bool     `yaml:"useWrapper,omitempty"`
}

type JFrogEnvParams struct {
	Server coreconfig.ServerDetails
}

type GitParams struct {
	GitProvider   vcsutils.VcsProvider
	RepoOwner     string
	Token         string
	BaseBranch    string
	ApiEndpoint   string
	PullRequestID int
}

func GetParamsAndClient(configFilePath string) (FrogbotConfigAggregator, *coreconfig.ServerDetails, vcsclient.VcsClient, error) {
	configAggregator, server, gitParams, err := extractFrogbotConfig(configFilePath)
	if err != nil {
		return nil, nil, nil, err
	}
	client, err := vcsclient.NewClientBuilder(gitParams.GitProvider).ApiEndpoint(gitParams.ApiEndpoint).Token(gitParams.Token).Build()
	if err != nil {
		return nil, nil, nil, err
	}
	return configAggregator, server, client, err
}

func extractJFrogParamsFromEnv() (JFrogEnvParams, error) {
	jfrogEnvParams := JFrogEnvParams{}
	url := strings.TrimSuffix(getTrimmedEnv(JFrogUrlEnv), "/")
	xrUrl := strings.TrimSuffix(getTrimmedEnv(jfrogXrayUrlEnv), "/")
	rtUrl := strings.TrimSuffix(getTrimmedEnv(jfrogArtifactoryUrlEnv), "/")
	if xrUrl != "" && rtUrl != "" {
		jfrogEnvParams.Server.XrayUrl = xrUrl + "/"
		jfrogEnvParams.Server.ArtifactoryUrl = rtUrl + "/"
	} else {
		if url == "" {
			return jfrogEnvParams, fmt.Errorf("%s or %s and %s environment variables are missing", JFrogUrlEnv, jfrogXrayUrlEnv, jfrogArtifactoryUrlEnv)
		}
		jfrogEnvParams.Server.Url = url + "/"
		jfrogEnvParams.Server.XrayUrl = url + "/xray/"
		jfrogEnvParams.Server.ArtifactoryUrl = url + "/artifactory/"
	}

	password := getTrimmedEnv(JFrogPasswordEnv)
	user := getTrimmedEnv(JFrogUserEnv)
	if password != "" && user != "" {
		jfrogEnvParams.Server.User = user
		jfrogEnvParams.Server.Password = password
	} else if accessToken := getTrimmedEnv(JFrogTokenEnv); accessToken != "" {
		jfrogEnvParams.Server.AccessToken = accessToken
	} else {
		return JFrogEnvParams{}, fmt.Errorf("%s and %s or %s environment variables are missing", JFrogUserEnv, JFrogPasswordEnv, JFrogTokenEnv)
	}
	return jfrogEnvParams, nil
}

func extractGitParamsFromEnv() (GitParams, error) {
	var err error
	gitParams := GitParams{}
	// Non-mandatory Git Api Endpoint
	_ = readParamFromEnv(GitApiEndpointEnv, &gitParams.ApiEndpoint)

	if gitParams.GitProvider, err = extractVcsProviderFromEnv(); err != nil {
		return GitParams{}, err
	}
	if err = readParamFromEnv(GitRepoOwnerEnv, &gitParams.RepoOwner); err != nil {
		return GitParams{}, err
	}

	if err = readParamFromEnv(GitTokenEnv, &gitParams.Token); err != nil {
		return GitParams{}, err
	}
	// Non-mandatory git branch and pr id.
	_ = readParamFromEnv(GitBaseBranchEnv, &gitParams.BaseBranch)
	if pullRequestIDString := getTrimmedEnv(GitPullRequestIDEnv); pullRequestIDString != "" {
		gitParams.PullRequestID, err = strconv.Atoi(pullRequestIDString)
	}
	return gitParams, err
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

func SanitizeEnv() error {
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

func extractFrogbotConfig(configFilePath string) (FrogbotConfigAggregator, *coreconfig.ServerDetails, *GitParams, error) {
	configData, err := OpenAndParseConfigFile(configFilePath)
	if err != nil {
		return nil, nil, nil, err
	}

	jfrogEnvParams, gitParams, err := extractEnvParams()
	if err != nil {
		return nil, nil, nil, err
	}

	var configAggregator FrogbotConfigAggregator
	for _, config := range *configData {
		if config.RepoName == "" {
			return nil, nil, nil, errors.New(validateRepoNameExistErr)
		}
		configAggregator = append(configAggregator, FrogbotRepoConfig{
			JFrogEnvParams:            jfrogEnvParams,
			GitParams:                 gitParams,
			IncludeAllVulnerabilities: config.IncludeAllVulnerabilities,
			FailOnSecurityIssues:      config.FailOnSecurityIssues,
			SimplifiedOutput:          config.SimplifiedOutput,
			Projects:                  config.Projects,
			Watches:                   config.Watches,
			ProjectKey:                config.ProjectKey,
			RepoName:                  config.RepoName,
		})
	}

	return configAggregator, &jfrogEnvParams.Server, &gitParams, nil
}

func extractEnvParams() (JFrogEnvParams, GitParams, error) {
	jfrogEnvParams, err := extractJFrogParamsFromEnv()
	if err != nil {
		return JFrogEnvParams{}, GitParams{}, err
	}

	gitParams, err := extractGitParamsFromEnv()
	if err != nil {
		return JFrogEnvParams{}, GitParams{}, err
	}

	return jfrogEnvParams, gitParams, SanitizeEnv()
}

func OpenAndParseConfigFile(configFilePath string) (*FrogbotConfigAggregator, error) {
	if configFilePath == "" {
		return nil, errors.New(emptyConfigFilePathErr)
	}
	filePath, err := filepath.Abs(configFilePath)
	if err != nil {
		return nil, err
	}

	configFile, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var config FrogbotConfigAggregator
	if err := yaml.Unmarshal(configFile, &config); err != nil {
		return nil, err
	}
	return &config, nil
}
