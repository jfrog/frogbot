package utils

import (
	"fmt"
	"github.com/jfrog/build-info-go/utils"
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/froggit-go/vcsutils"
	coreconfig "github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"gopkg.in/yaml.v3"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	FrogbotConfigFile = "frogbot-config.yml"
)

var configRelativePath = filepath.Join(".", ".jfrog", FrogbotConfigFile)

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
	server, gitParams, repoName, err := extractEnvParams()
	if err != nil {
		return nil, nil, nil, err
	}

	client, err := vcsclient.NewClientBuilder(gitParams.GitProvider).ApiEndpoint(gitParams.ApiEndpoint).Token(gitParams.Token).Build()
	if err != nil {
		return nil, nil, nil, err
	}

	configData, err := ReadConfig(configRelativePath)
	// If the error is due to missing configuration, try to generate an environment variable-based config aggregator.
	_, missingConfigErr := err.(*ErrMissingConfig)
	if err != nil && missingConfigErr {
		// If no config file is used, the repo name must be set as a part of the envs.
		if repoName == "" {
			return nil, nil, nil, &ErrMissingEnv{GitRepoEnv}
		}
		configData, err = generateConfigAggregatorFromEnv(&gitParams, &server, repoName)
		if err != nil {
			return nil, nil, nil, err
		}
		return *configData, &server, client, err
	} else if err != nil {
		return nil, nil, nil, err
	}

	var configAggregator FrogbotConfigAggregator
	for _, config := range *configData {
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

	return configAggregator, &server, client, err
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

func extractGitParamsFromEnv() (GitParams, string, error) {
	var err error
	gitParams := GitParams{}
	// Non-mandatory Git Api Endpoint
	_ = readParamFromEnv(GitApiEndpointEnv, &gitParams.ApiEndpoint)
	if gitParams.GitProvider, err = extractVcsProviderFromEnv(); err != nil {
		return GitParams{}, "", err
	}
	if err = readParamFromEnv(GitRepoOwnerEnv, &gitParams.RepoOwner); err != nil {
		return GitParams{}, "", err
	}
	if err = readParamFromEnv(GitTokenEnv, &gitParams.Token); err != nil {
		return GitParams{}, "", err
	}

	// Repo name validation will be checked later, this env is mandatory in case there is no config file.
	var repoName string
	_ = readParamFromEnv(GitRepoEnv, &repoName)
	// Non-mandatory git branch and pr id.
	_ = readParamFromEnv(GitBaseBranchEnv, &gitParams.BaseBranch)
	if pullRequestIDString := getTrimmedEnv(GitPullRequestIDEnv); pullRequestIDString != "" {
		gitParams.PullRequestID, err = strconv.Atoi(pullRequestIDString)
	}
	return gitParams, repoName, err
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

func extractEnvParams() (coreconfig.ServerDetails, GitParams, string, error) {
	server, err := extractJFrogParamsFromEnv()
	if err != nil {
		return coreconfig.ServerDetails{}, GitParams{}, "", err
	}

	gitParams, repoName, err := extractGitParamsFromEnv()
	if err != nil {
		return coreconfig.ServerDetails{}, GitParams{}, "", err
	}

	return server, gitParams, repoName, SanitizeEnv()
}

func ReadConfig(configFilePath string) (*FrogbotConfigAggregator, error) {
	filePath, err := filepath.Abs(configFilePath)
	if err != nil {
		return nil, err
	}
	fileExist, err := fileutils.IsFileExists(filePath, false)
	if !fileExist || err != nil {
		// If the WD directory is not ./frogbot, look in parent directories for ./jfrog/frogbot-config.yml.
		if filePath, err = utils.FindFileInDirAndParents(filePath, configRelativePath); err != nil {
			return nil, &ErrMissingConfig{
				fmt.Sprintf("%s wasn't found in the Frogbot directory and its subdirectories. Continue running with environment variables", FrogbotConfigFile),
			}
		}
		filePath = filepath.Join(filePath, configFilePath)
	}

	configFile, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var config FrogbotConfigAggregator
	return &config, yaml.Unmarshal(configFile, &config)
}

func extractProjectParamsFromEnv(project *Project) error {
	workingDir := getTrimmedEnv(WorkingDirectoryEnv)
	project.WorkingDirs = []string{workingDir}
	project.PipRequirementsFile = getTrimmedEnv(RequirementsFileEnv)
	var err error
	if project.UseWrapper, err = getBoolEnv(UseWrapperEnv, true); err != nil {
		return err
	}

	installCommand := getTrimmedEnv(InstallCommandEnv)
	if installCommand == "" {
		return nil
	}
	parts := strings.Fields(installCommand)
	if len(parts) > 1 {
		project.InstallCommandArgs = parts[1:]
	}
	project.InstallCommandName = parts[0]

	return err
}

func extractRepoParamsFromEnv(repo *FrogbotRepoConfig) error {
	var err error
	if repo.IncludeAllVulnerabilities, err = getBoolEnv(IncludeAllVulnerabilitiesEnv, false); err != nil {
		return err
	}
	repo.FailOnSecurityIssues, err = getBoolEnv(FailOnSecurityIssuesEnv, true)
	// Non-mandatory Xray context params
	var watches string
	_ = readParamFromEnv(jfrogWatchesEnv, &watches)
	if watches != "" {
		// Remove spaces if exists
		watches = strings.ReplaceAll(watches, " ", "")
		repo.Watches = strings.Split(watches, WatchesDelimiter)
	}
	_ = readParamFromEnv(jfrogProjectEnv, &repo.JFrogProjectKey)
	return err
}

func getBoolEnv(envKey string, defaultValue bool) (bool, error) {
	envValue := getTrimmedEnv(envKey)
	if envValue != "" {
		parsedEnv, err := strconv.ParseBool(envValue)
		if err != nil {
			return false, fmt.Errorf("the value of the %s environment is expected to be either TRUE or FALSE. The value received however is %s", envKey, envValue)
		}
		return parsedEnv, nil
	}

	return defaultValue, nil
}

// In case config file wasn't provided by the user, generateConfigAggregatorFromEnv generates a FrogbotConfigAggregator with the environment variables values.
func generateConfigAggregatorFromEnv(gitParams *GitParams, server *coreconfig.ServerDetails, repoName string) (*FrogbotConfigAggregator, error) {
	var project Project
	if err := extractProjectParamsFromEnv(&project); err != nil {
		return nil, err
	}
	repo := FrogbotRepoConfig{GitParams: *gitParams, Server: *server, RepoName: repoName}
	if err := extractRepoParamsFromEnv(&repo); err != nil {
		return nil, err
	}
	repo.Projects = append(repo.Projects, project)
	return &FrogbotConfigAggregator{repo}, nil
}
