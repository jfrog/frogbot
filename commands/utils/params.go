package utils

import (
	"errors"
	"fmt"
	"github.com/jfrog/build-info-go/utils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	clientLog "github.com/jfrog/jfrog-client-go/utils/log"
	"gopkg.in/yaml.v3"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/froggit-go/vcsutils"
	coreconfig "github.com/jfrog/jfrog-cli-core/v2/utils/config"
)

var configRelativePath = filepath.Join(".", ".jfrog", FrogbotConfigFile)

const (
	FrogbotConfigFile        = "frogbot-config.yml"
	emptyConfigFilePath      = "configuration file was not provided"
	validateRepoNameExistErr = "repo name is missing. In the config file, fill out the repo name for each repository configuration"
)

type FrogbotConfigAggregator []FrogbotRepoConfig

type FrogbotRepoConfig struct {
	GitParams
	Server                    coreconfig.ServerDetails
	SimplifiedOutput          bool
	IncludeAllVulnerabilities bool      `yaml:"includeAllVulnerabilities,omitempty"`
	FailOnSecurityIssues      bool      `yaml:"failOnSecurityIssues,omitempty"`
	JFrogProjectKey           string    `yaml:"jfrogProjectKey,omitempty"`
	RepoName                  string    `yaml:"repoName,omitempty"`
	Projects                  []Project `yaml:"projects,omitempty"`
	Watches                   []string  `yaml:"watches,omitempty"`
}

type Project struct {
	InstallCommandName  string   `yaml:"installCommandName,omitempty"`
	InstallCommandArgs  []string `yaml:"installCommandArgs,omitempty"`
	PipRequirementsFile string   `yaml:"pipRequirementsFile,omitempty"`
	WorkingDirs         []string `yaml:"workingDirs,omitempty"`
	UseWrapper          bool     `yaml:"useWrapper,omitempty"`
}

type GitParams struct {
	GitProvider   vcsutils.VcsProvider
	RepoOwner     string
	Token         string
	BaseBranch    string
	ApiEndpoint   string
	PullRequestID int
}

func GetParamsAndClient() (FrogbotConfigAggregator, *coreconfig.ServerDetails, vcsclient.VcsClient, error) {
	server, gitParams, err := extractEnvParams()
	if err != nil {
		return nil, nil, nil, err
	}

	client, err := vcsclient.NewClientBuilder(gitParams.GitProvider).ApiEndpoint(gitParams.ApiEndpoint).Token(gitParams.Token).Build()
	if err != nil {
		return nil, nil, nil, err
	}

	configPath, cleanup, err := getConfigRepo(client, gitParams)
	if cleanup != nil {
		defer cleanup(err)
	}
	if err != nil {
		return nil, nil, nil, err
	}
	if configPath == "" {
		configPath = configRelativePath
	}
	configData, err := ReadConfig(configPath)
	if err != nil {
		return nil, nil, nil, err
	}

	var configAggregator FrogbotConfigAggregator
	for _, config := range *configData {
		// Repo name is mandatory for Bitbucket Server
		if config.RepoName == "" && gitParams.GitProvider == vcsutils.BitbucketServer {
			return nil, nil, nil, errors.New(validateRepoNameExistErr)
		}
		configAggregator = append(configAggregator, FrogbotRepoConfig{
			Server:                    server,
			GitParams:                 gitParams,
			IncludeAllVulnerabilities: config.IncludeAllVulnerabilities,
			FailOnSecurityIssues:      config.FailOnSecurityIssues,
			SimplifiedOutput:          config.SimplifiedOutput,
			Projects:                  config.Projects,
			Watches:                   config.Watches,
			JFrogProjectKey:           config.JFrogProjectKey,
			RepoName:                  config.RepoName,
		})
	}

	return configAggregator, &server, client, nil
}

// getConfigRepo parses the FROGBOT_CONFIG_REPO environment variable to find the Frogbot's config file location and downloads it to a temp directory.
// Return Values:
// 1. configPath - The path to the temp folder in which Frogbot's config file resides.
// 2. cleanup - This function cleans the temp directory after the function that called getConfigRepo has used it.
// 3. err - If an error occurs, getConfigRepo will stop and return the error.
func getConfigRepo(client vcsclient.VcsClient, gitParams GitParams) (configPath string, cleanup func(err error) error, err error) {
	configRepoName := getTrimmedEnv(FrogbotConfigRepoEnv)
	if configRepoName == "" {
		return configRepoName, nil, nil
	}
	wd, removeTempDir, err := DownloadRepoToTempDir(client, configRepoName, &gitParams)
	cleanup = removeTempDir
	if err != nil {
		return
	}
	configPath = filepath.Join(wd, FrogbotConfigFile)
	configExist, err := fileutils.IsFileExists(configPath, false)
	if !configExist {
		err = fmt.Errorf("%s could not be found in repo %s", FrogbotConfigFile, configRepoName)
		return
	}
	return
}

func extractJFrogParamsFromEnv() (coreconfig.ServerDetails, error) {
	server := coreconfig.ServerDetails{}
	url := strings.TrimSuffix(getTrimmedEnv(JFrogUrlEnv), "/")
	xrUrl := strings.TrimSuffix(getTrimmedEnv(jfrogXrayUrlEnv), "/")
	rtUrl := strings.TrimSuffix(getTrimmedEnv(jfrogArtifactoryUrlEnv), "/")
	if xrUrl != "" && rtUrl != "" {
		server.XrayUrl = xrUrl + "/"
		server.ArtifactoryUrl = rtUrl + "/"
	} else {
		if url == "" {
			return server, fmt.Errorf("%s or %s and %s environment variables are missing", JFrogUrlEnv, jfrogXrayUrlEnv, jfrogArtifactoryUrlEnv)
		}
		server.Url = url + "/"
		server.XrayUrl = url + "/xray/"
		server.ArtifactoryUrl = url + "/artifactory/"
	}

	password := getTrimmedEnv(JFrogPasswordEnv)
	user := getTrimmedEnv(JFrogUserEnv)
	if password != "" && user != "" {
		server.User = user
		server.Password = password
	} else if accessToken := getTrimmedEnv(JFrogTokenEnv); accessToken != "" {
		server.AccessToken = accessToken
	} else {
		return coreconfig.ServerDetails{}, fmt.Errorf("%s and %s or %s environment variables are missing", JFrogUserEnv, JFrogPasswordEnv, JFrogTokenEnv)
	}
	return server, nil
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

func extractEnvParams() (coreconfig.ServerDetails, GitParams, error) {
	server, err := extractJFrogParamsFromEnv()
	if err != nil {
		return coreconfig.ServerDetails{}, GitParams{}, err
	}

	gitParams, err := extractGitParamsFromEnv()
	if err != nil {
		return coreconfig.ServerDetails{}, GitParams{}, err
	}

	return server, gitParams, SanitizeEnv()
}

func ReadConfig(configFilePath string) (*FrogbotConfigAggregator, error) {
	if configFilePath == "" {
		clientLog.Info(emptyConfigFilePath)
		return nil, nil
	}
	filePath, err := filepath.Abs(configFilePath)
	if err != nil {
		return nil, err
	}
	fileExist, err := fileutils.IsFileExists(filePath, false)
	if !fileExist || err != nil {
		// If the WD directory is not ./frogbot, look in parent directories for ./jfrog/frogbot-config.yml.
		if filePath, err = utils.FindFileInDirAndParents(filePath, configRelativePath); err != nil {
			clientLog.Info(fmt.Sprintf("%s wasn't found in the Frogbot directory and its subdirectories. Continue running with default settings", FrogbotConfigFile))
			return nil, nil
		}
		filePath = filepath.Join(filePath, configFilePath)
	}

	configFile, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var config FrogbotConfigAggregator
	if err := yaml.Unmarshal(configFile, &config); err != nil {
		return nil, err
	}
	return &config, nil
}
