package utils

import (
	"fmt"
	"github.com/jfrog/build-info-go/utils"
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/froggit-go/vcsutils"
	coreconfig "github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"gopkg.in/yaml.v3"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	FrogbotConfigFile = "frogbot-config.yml"
)

// Possible Config file path's to Frogbot Management repository
var frogbotConfigPath = filepath.Join(".", "frogbot", FrogbotConfigFile)

type FrogbotConfigAggregator []FrogbotRepoConfig

type FrogbotRepoConfig struct {
	Server           coreconfig.ServerDetails
	SimplifiedOutput bool
	Params           `yaml:"params,omitempty"`
}

type Params struct {
	Scan          `yaml:"scan,omitempty"`
	Git           `yaml:"git,omitempty"`
	JFrogPlatform `yaml:"jfrogPlatform,omitempty"`
}

type Project struct {
	InstallCommandName  string   `yaml:"installCommandName,omitempty"`
	InstallCommandArgs  []string `yaml:"installCommandArgs,omitempty"`
	PipRequirementsFile string   `yaml:"pipRequirementsFile,omitempty"`
	WorkingDirs         []string `yaml:"workingDirs,omitempty"`
	UseWrapper          bool     `yaml:"useWrapper,omitempty"`
}

type Scan struct {
	IncludeAllVulnerabilities bool      `yaml:"includeAllVulnerabilities,omitempty"`
	FailOnSecurityIssues      *bool     `yaml:"failOnSecurityIssues,omitempty"`
	Projects                  []Project `yaml:"projects,omitempty"`
}

type JFrogPlatform struct {
	Watches         []string `yaml:"watches,omitempty"`
	JFrogProjectKey string   `yaml:"jfrogProjectKey,omitempty"`
}

type Git struct {
	GitProvider   vcsutils.VcsProvider
	RepoName      string   `yaml:"repoName,omitempty"`
	Branches      []string `yaml:"branches,omitempty"`
	GitProject    string
	RepoOwner     string
	Token         string
	ApiEndpoint   string
	PullRequestID int
}

func GetParamsAndClient() (configAggregator FrogbotConfigAggregator, server *coreconfig.ServerDetails, client vcsclient.VcsClient, err error) {
	server, gitParams, err := extractEnvParams()
	if err != nil {
		return nil, nil, nil, err
	}
	defer func() {
		e := SanitizeEnv()
		if err == nil {
			err = e
		} else if e != nil {
			err = fmt.Errorf("%s\n%s", err.Error(), e.Error())
		}
	}()

	client, err = vcsclient.NewClientBuilder(gitParams.GitProvider).ApiEndpoint(gitParams.ApiEndpoint).Token(gitParams.Token).Project(gitParams.GitProject).Logger(log.GetLogger()).Build()
	if err != nil {
		return nil, nil, nil, err
	}

	configData, err := ReadConfig(frogbotConfigPath)
	// If the error is due to missing configuration, try to generate an environment variable-based config aggregator.
	_, missingConfigErr := err.(*ErrMissingConfig)
	if err != nil && missingConfigErr {
		// If no config file is used, the repo name must be set as a part of the envs.
		if gitParams.RepoName == "" {
			return nil, nil, nil, &ErrMissingEnv{GitRepoEnv}
		}
		configData, err = generateConfigAggregatorFromEnv(&gitParams, server)
		if err != nil {
			return nil, nil, nil, err
		}
		return *configData, server, client, err
	} else if err != nil {
		return nil, nil, nil, err
	}

	for _, config := range *configData {
		if config.RepoName == "" {
			return nil, nil, nil, &ErrMissingEnv{GitRepoEnv}
		}
		gitParams.RepoName = config.RepoName
		if config.Branches != nil {
			gitParams.Branches = config.Branches
		}
		if config.FailOnSecurityIssues == nil {
			trueVal := true
			config.FailOnSecurityIssues = &trueVal
		}
		config.Git = gitParams
		configAggregator = append(configAggregator, FrogbotRepoConfig{
			SimplifiedOutput: config.SimplifiedOutput,
			Server:           *server,
			Params:           config.Params,
		})
	}

	return configAggregator, server, client, err
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

func extractGitParamsFromEnv() (Git, error) {
	var err error
	gitParams := Git{}
	// Non-mandatory Git Api Endpoint
	_ = readParamFromEnv(GitApiEndpointEnv, &gitParams.ApiEndpoint)
	if gitParams.GitProvider, err = extractVcsProviderFromEnv(); err != nil {
		return Git{}, err
	}
	if err = readParamFromEnv(GitRepoOwnerEnv, &gitParams.RepoOwner); err != nil {
		return Git{}, err
	}
	if err = readParamFromEnv(GitTokenEnv, &gitParams.Token); err != nil {
		return Git{}, err
	}

	// Repo name validation will be performed later, this env is mandatory in case there is no config file.
	_ = readParamFromEnv(GitRepoEnv, &gitParams.RepoName)
	if err := readParamFromEnv(GitProjectEnv, &gitParams.GitProject); err != nil && gitParams.GitProvider == vcsutils.AzureRepos {
		return Git{}, err
	}
	// Non-mandatory git branch and pr id.
	var branch string
	_ = readParamFromEnv(GitBaseBranchEnv, &branch)
	gitParams.Branches = append(gitParams.Branches, branch)
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
	case string(AzureRepos):
		return vcsutils.AzureRepos, nil
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

func extractEnvParams() (*coreconfig.ServerDetails, Git, error) {
	server, err := extractJFrogParamsFromEnv()
	if err != nil {
		return &coreconfig.ServerDetails{}, Git{}, err
	}

	gitParams, err := extractGitParamsFromEnv()
	return &server, gitParams, err
}

// ReadConfig looks for the frogbot-config.yml file based on the configRelativePath, and then unmarshal the file into the FrogbotConfigAggregator struct.
func ReadConfig(configRelativePath string) (config *FrogbotConfigAggregator, err error) {
	fullConfigDirPath, err := filepath.Abs(configRelativePath)
	if err != nil {
		return nil, err
	}

	// Look for the frogbot-config.yml file in fullConfigPath
	exist, err := utils.IsFileExists(fullConfigDirPath, false)
	if !exist || err != nil {
		// Look for the frogbot-config.yml in fullConfigPath parents dirs
		if fullConfigDirPath, err = utils.FindFileInDirAndParents(fullConfigDirPath, configRelativePath); err != nil {
			return nil, &ErrMissingConfig{
				fmt.Sprintf("%s wasn't found in the Frogbot directory and its subdirectories. Continuing with environment variables", FrogbotConfigFile),
			}
		}
		fullConfigDirPath = filepath.Join(fullConfigDirPath, configRelativePath)
	}

	configFile, err := os.ReadFile(fullConfigDirPath)
	if err != nil {
		return nil, err
	}

	return config, yaml.Unmarshal(configFile, &config)
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
	failOnSecurityIssues, err := getBoolEnv(FailOnSecurityIssuesEnv, true)
	repo.FailOnSecurityIssues = &failOnSecurityIssues
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
func generateConfigAggregatorFromEnv(gitParams *Git, server *coreconfig.ServerDetails) (*FrogbotConfigAggregator, error) {
	var project Project
	if err := extractProjectParamsFromEnv(&project); err != nil {
		return nil, err
	}
	params := Params{Git: *gitParams}
	repo := FrogbotRepoConfig{Params: params, Server: *server}
	if err := extractRepoParamsFromEnv(&repo); err != nil {
		return nil, err
	}
	repo.Projects = append(repo.Projects, project)
	return &FrogbotConfigAggregator{repo}, nil
}
