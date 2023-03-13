package utils

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/jfrog/build-info-go/utils"
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/froggit-go/vcsutils"
	coreconfig "github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v3"
)

const (
	frogbotConfigDir  = ".frogbot"
	FrogbotConfigFile = "frogbot-config.yml"
)

var errFrogbotConfigNotFound = fmt.Errorf("%s wasn't found in the Frogbot directory and its subdirectories. Assuming all the configuration is stored as environment variables", FrogbotConfigFile)

// Possible Config file path's to Frogbot Management repository
var osFrogbotConfigPath = filepath.Join(frogbotConfigDir, FrogbotConfigFile)

type FrogbotUtils struct {
	ConfigAggregator FrogbotConfigAggregator
	ServerDetails    *coreconfig.ServerDetails
	Client           vcsclient.VcsClient
}

type FrogbotConfigAggregator []FrogbotRepoConfig

// UnmarshalYaml uses the yaml.Unmarshaler interface to parse the yamlContent, and then sets default values if they weren't set by the user.
func (fca FrogbotConfigAggregator) UnmarshalYaml(yamlContent []byte) (result FrogbotConfigAggregator, err error) {
	var configFile *FrogbotConfigAggregator
	if err := yaml.Unmarshal(yamlContent, &configFile); err != nil {
		return nil, err
	}
	for _, repository := range *configFile {
		repository.Params, err = repository.Params.setDefaultsIfNeeded()
		if err != nil {
			return
		}
		result = append(result, repository)
	}
	return
}

type FrogbotRepoConfig struct {
	Params `yaml:"params,omitempty"`
	OutputWriter
	Server coreconfig.ServerDetails
}

type Params struct {
	Scan          `yaml:"scan,omitempty"`
	Git           `yaml:"git,omitempty"`
	JFrogPlatform `yaml:"jfrogPlatform,omitempty"`
}

func (p *Params) setDefaultsIfNeeded() (Params, error) {
	if p.RepoName == "" {
		return Params{}, errors.New("repository name is missing")
	}
	p.Scan = *p.Scan.setDefaultsIfNeeded()
	return *p, nil
}

type Project struct {
	InstallCommand      string   `yaml:"installCommand,omitempty"`
	PipRequirementsFile string   `yaml:"pipRequirementsFile,omitempty"`
	WorkingDirs         []string `yaml:"workingDirs,omitempty"`
	UseWrapper          *bool    `yaml:"useWrapper,omitempty"`
	Repository          string   `yaml:"repository,omitempty"`
	InstallCommandName  string
	InstallCommandArgs  []string
}

func (p *Project) setDefaultsIfNeeded() *Project {
	if len(p.WorkingDirs) == 0 {
		p.WorkingDirs = append(p.WorkingDirs, RootDir)
	}
	if p.UseWrapper == nil {
		p.UseWrapper = &TrueVal
	}
	if p.InstallCommand != "" {
		setProjectInstallCommand(p.InstallCommand, p)
	}
	return p
}

type Scan struct {
	IncludeAllVulnerabilities bool      `yaml:"includeAllVulnerabilities,omitempty"`
	FailOnSecurityIssues      *bool     `yaml:"failOnSecurityIssues,omitempty"`
	Projects                  []Project `yaml:"projects,omitempty"`
}

func (s *Scan) setDefaultsIfNeeded() *Scan {
	if s.FailOnSecurityIssues == nil {
		s.FailOnSecurityIssues = &TrueVal
	}
	if s.Projects == nil {
		s.Projects = []Project{{}}
	}
	var projectsWithDefaults []Project
	for _, project := range s.Projects {
		projectsWithDefaults = append(projectsWithDefaults, *project.setDefaultsIfNeeded())
	}
	s.Projects = projectsWithDefaults
	return s
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
	Username      string
	PullRequestID int
}

func GetFrogbotUtils() (frogbotUtils *FrogbotUtils, err error) {
	// Get server and git details
	server, gitParams, err := extractEnvParams()
	if err != nil {
		return nil, err
	}
	defer func() {
		e := SanitizeEnv()
		if err == nil {
			err = e
		} else if e != nil {
			err = fmt.Errorf("%s\n%s", err.Error(), e.Error())
		}
	}()

	// Build Version control client for REST API requests
	client, err := vcsclient.
		NewClientBuilder(gitParams.GitProvider).
		ApiEndpoint(gitParams.ApiEndpoint).
		Token(gitParams.Token).
		Project(gitParams.GitProject).
		Logger(log.GetLogger()).
		Username(gitParams.Username).
		Build()
	if err != nil {
		return nil, err
	}

	configAggregator, err := getConfigAggregator(client, server, gitParams)
	return &FrogbotUtils{ConfigAggregator: configAggregator, Client: client, ServerDetails: server}, err
}

// getConfigAggregator returns a FrogbotConfigAggregator based on frogbot-config.yml and environment variables.
func getConfigAggregator(client vcsclient.VcsClient, server *coreconfig.ServerDetails, gitParams *Git) (FrogbotConfigAggregator, error) {
	if err := downloadExtractorsFromRemoteIfNeeded(server, ""); err != nil {
		return nil, err
	}
	configFileContent, err := getConfigFileContent(client)
	// If there is a missing configuration file error, try to generate an environment variable-based config aggregator.
	if _, missingConfigErr := err.(*ErrMissingConfig); missingConfigErr {
		log.Debug("Retrieving", FrogbotConfigFile, "failed with:", err.Error())
		configAggregator, err := newConfigAggregatorFromEnv(gitParams, server)
		if err != nil {
			return nil, err
		}
		return configAggregator, err
	} else if err != nil {
		return nil, err
	}

	return NewConfigAggregatorFromFile(configFileContent, gitParams, server)
}

// The getConfigFileContent function retrieves the frogbot-config.yml file content.
// If the JF_GIT_REPO and JF_GIT_OWNER environment variables are set, this function will attempt to retrieve the frogbot-config.yml file from the target repository based on these variables.
// If these variables are not set, this function will attempt to retrieve the frogbot-config.yml file from the current working directory.
func getConfigFileContent(client vcsclient.VcsClient) (configFileContent []byte, err error) {
	var targetConfigContent []byte
	configFileContent, err = readConfigFromTarget(client)
	_, missingConfigErr := err.(*ErrMissingConfig)
	if err != nil && !missingConfigErr {
		return nil, err
	}

	// Read the config from the current working dir
	if targetConfigContent == nil && err == nil {
		configFileContent, err = ReadConfigFromFileSystem(osFrogbotConfigPath)
	}
	return
}

// NewConfigAggregatorFromFile receive a frogbot-config.yml file content along with the Git and ServerDetails parameters, and returns a FrogbotConfigAggregator instance with all the default and necessary fields.
func NewConfigAggregatorFromFile(configFileContent []byte, gitParams *Git, server *coreconfig.ServerDetails) (result FrogbotConfigAggregator, err error) {
	// Unmarshal the frogbot-config.yml file
	result, err = result.UnmarshalYaml(configFileContent)
	if err != nil {
		return nil, err
	}
	// Set git parameters and server details for each repository
	for i := range result {
		gitParams.RepoName = result[i].RepoName
		if result[i].Branches != nil {
			gitParams.Branches = result[i].Branches
		}
		result[i].Git = *gitParams
		result[i].Server = *server
		result[i].OutputWriter = GetCompatibleOutputWriter(result[i].GitProvider)
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

func extractGitParamsFromEnv() (*Git, error) {
	var err error
	gitParams := Git{}
	// Non-mandatory Git Api Endpoint, if not set, default values will be used.
	_ = ReadParamFromEnv(GitApiEndpointEnv, &gitParams.ApiEndpoint)
	if gitParams.GitProvider, err = extractVcsProviderFromEnv(); err != nil {
		return nil, err
	}
	if err = ReadParamFromEnv(GitRepoOwnerEnv, &gitParams.RepoOwner); err != nil {
		return nil, err
	}
	if err = ReadParamFromEnv(GitTokenEnv, &gitParams.Token); err != nil {
		return nil, err
	}
	// Username is only mandatory for Bitbucket server on the scan-and-fix-repos command.
	_ = ReadParamFromEnv(GitUsernameEnv, &gitParams.Username)
	// Repo name validation will be performed later, this env is mandatory in case there is no config file.
	_ = ReadParamFromEnv(GitRepoEnv, &gitParams.RepoName)
	if err := ReadParamFromEnv(GitProjectEnv, &gitParams.GitProject); err != nil && gitParams.GitProvider == vcsutils.AzureRepos {
		return nil, err
	}
	// Non-mandatory git branch and pr id.
	var branch string
	_ = ReadParamFromEnv(GitBaseBranchEnv, &branch)
	gitParams.Branches = append(gitParams.Branches, branch)
	if pullRequestIDString := getTrimmedEnv(GitPullRequestIDEnv); pullRequestIDString != "" {
		gitParams.PullRequestID, err = strconv.Atoi(pullRequestIDString)
	}
	return &gitParams, err
}

func ReadParamFromEnv(envKey string, paramValue *string) error {
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

func extractEnvParams() (*coreconfig.ServerDetails, *Git, error) {
	server, err := extractJFrogParamsFromEnv()
	if err != nil {
		return nil, nil, err
	}

	gitParams, err := extractGitParamsFromEnv()
	return &server, gitParams, err
}

// ReadConfigFromFileSystem looks for .frogbot/frogbot-config.yml from the given path and return its content. The path is relative and starts from the root of the project.
// If the config file is not found in the relative path, it will search in parent dirs.
func ReadConfigFromFileSystem(configRelativePath string) (configFileContent []byte, err error) {
	log.Debug("Reading config from file system. Looking for", osFrogbotConfigPath)
	fullConfigDirPath, err := filepath.Abs(configRelativePath)
	if err != nil {
		return nil, err
	}

	// Look for the frogbot-config.yml file in fullConfigPath
	exist, err := utils.IsFileExists(fullConfigDirPath, false)
	if !exist || err != nil {
		// Look for the frogbot-config.yml in fullConfigPath parents dirs
		log.Debug(FrogbotConfigFile, "wasn't found in "+fullConfigDirPath+". Searching for it in upstream directories")
		if fullConfigDirPath, err = utils.FindFileInDirAndParents(fullConfigDirPath, configRelativePath); err != nil {
			return nil, &ErrMissingConfig{errFrogbotConfigNotFound.Error()}
		}
		fullConfigDirPath = filepath.Join(fullConfigDirPath, configRelativePath)
	}

	log.Debug(FrogbotConfigFile, "found in", fullConfigDirPath)
	return os.ReadFile(fullConfigDirPath)
}

func extractProjectParamsFromEnv(project *Project) error {
	workingDir := getTrimmedEnv(WorkingDirectoryEnv)
	if workingDir == "" {
		workingDir = RootDir
	}
	project.WorkingDirs = []string{workingDir}
	project.Repository = getTrimmedEnv(DepsRepoEnv)
	project.PipRequirementsFile = getTrimmedEnv(RequirementsFileEnv)
	installCommand := getTrimmedEnv(InstallCommandEnv)
	setProjectInstallCommand(installCommand, project)
	var err error
	var useWrapper bool
	if useWrapper, err = getBoolEnv(UseWrapperEnv, true); err != nil {
		return err
	}
	project.UseWrapper = &useWrapper
	return err
}

func setProjectInstallCommand(installCommand string, project *Project) {
	if installCommand == "" {
		return
	}
	parts := strings.Fields(installCommand)
	if len(parts) > 1 {
		project.InstallCommandArgs = parts[1:]
	}
	project.InstallCommandName = parts[0]
}

func extractRepoParamsFromEnv(repo *FrogbotRepoConfig) error {
	var err error
	if repo.IncludeAllVulnerabilities, err = getBoolEnv(IncludeAllVulnerabilitiesEnv, false); err != nil {
		return err
	}
	failOnSecurityIssues, err := getBoolEnv(FailOnSecurityIssuesEnv, true)
	if err != nil {
		return err
	}
	repo.FailOnSecurityIssues = &failOnSecurityIssues
	// Non-mandatory Xray context params
	var watches string
	_ = ReadParamFromEnv(jfrogWatchesEnv, &watches)
	if watches != "" {
		// Remove spaces if exists
		watches = strings.ReplaceAll(watches, " ", "")
		repo.Watches = strings.Split(watches, WatchesDelimiter)
	}
	_ = ReadParamFromEnv(jfrogProjectEnv, &repo.JFrogProjectKey)
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

// In case frogbot-config.yml does not exist, newConfigAggregatorFromEnv generates a FrogbotConfigAggregator with the environment variables values.
func newConfigAggregatorFromEnv(gitParams *Git, server *coreconfig.ServerDetails) (FrogbotConfigAggregator, error) {
	// The repo name must be set as a part of the envs.
	if gitParams.RepoName == "" {
		return nil, &ErrMissingEnv{GitRepoEnv}
	}
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
	repo.OutputWriter = GetCompatibleOutputWriter(gitParams.GitProvider)
	return FrogbotConfigAggregator{repo}, nil
}

// readConfigFromTarget reads the .frogbot/frogbot-config.yml from the target repository
func readConfigFromTarget(client vcsclient.VcsClient) (configContent []byte, err error) {
	var branch string
	_ = ReadParamFromEnv(GitBaseBranchEnv, &branch)
	var repo string
	_ = ReadParamFromEnv(GitRepoEnv, &repo)
	var owner string
	_ = ReadParamFromEnv(GitRepoOwnerEnv, &owner)
	if repo != "" && owner != "" {
		if branch == "" {
			log.Debug(GitBaseBranchEnv, "is missing. Assuming that the", FrogbotConfigFile, "file exists on default branch")
		}
		log.Debug("Downloading", FrogbotConfigFile, "from target", owner, "/", repo, "/", branch)
		gitFrogbotConfigPath := fmt.Sprintf("%s/%s", frogbotConfigDir, FrogbotConfigFile)
		var statusCode int
		configContent, statusCode, err = client.DownloadFileFromRepo(context.Background(), owner, repo, branch, gitFrogbotConfigPath)
		if statusCode == http.StatusNotFound {
			log.Debug(gitFrogbotConfigPath, "wasn't found on", owner, "/", repo)
			// If .frogbot/frogbot-config.yml isn't found, we'll try to run Frogbot using environment variables
			return nil, &ErrMissingConfig{errFrogbotConfigNotFound.Error()}
		}
		if err != nil {
			return nil, err
		}
	}

	return configContent, nil
}
