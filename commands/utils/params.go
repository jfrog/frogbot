package utils

import (
	"context"
	"errors"
	"fmt"
	xrutils "github.com/jfrog/jfrog-cli-core/v2/xray/utils"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/jfrog/build-info-go/utils"
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/froggit-go/vcsutils"
	coreconfig "github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"gopkg.in/yaml.v3"
)

const (
	frogbotConfigDir  = ".frogbot"
	FrogbotConfigFile = "frogbot-config.yml"
)

var (
	errFrogbotConfigNotFound = fmt.Errorf("%s wasn't found in the Frogbot directory and its subdirectories. Assuming all the configuration is stored as environment variables", FrogbotConfigFile)
	// Possible Config file path's to Frogbot Management repository
	osFrogbotConfigPath = filepath.Join(frogbotConfigDir, FrogbotConfigFile)
)

type FrogbotUtils struct {
	Repositories  RepoAggregator
	ServerDetails *coreconfig.ServerDetails
	Client        vcsclient.VcsClient
	ReleasesRepo  string
}

type RepoAggregator []Repository

type Repository struct {
	Params `yaml:"params,omitempty"`
	OutputWriter
	Server coreconfig.ServerDetails
}

type Params struct {
	Scan          `yaml:"scan,omitempty"`
	Git           `yaml:"git,omitempty"`
	JFrogPlatform `yaml:"jfrogPlatform,omitempty"`
}

func (p *Params) setDefaultsIfNeeded(git *Git) error {
	if err := p.Git.setDefaultsIfNeeded(git); err != nil {
		return err
	}
	if err := p.JFrogPlatform.setDefaultsIfNeeded(); err != nil {
		return err
	}
	return p.Scan.setDefaultsIfNeeded()
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

func (p *Project) setDefaultsIfNeeded() error {
	if len(p.WorkingDirs) == 0 {
		workingDir := getTrimmedEnv(WorkingDirectoryEnv)
		if workingDir == "" {
			workingDir = RootDir
		}
		p.WorkingDirs = append(p.WorkingDirs, workingDir)
	}
	if p.UseWrapper == nil {
		useWrapper, err := getBoolEnv(UseWrapperEnv, true)
		if err != nil {
			return err
		}
		p.UseWrapper = &useWrapper
	}
	if p.InstallCommand == "" {
		p.InstallCommand = getTrimmedEnv(InstallCommandEnv)
	}
	if p.InstallCommand != "" {
		setProjectInstallCommand(p.InstallCommand, p)
	}
	if p.PipRequirementsFile == "" {
		p.PipRequirementsFile = getTrimmedEnv(RequirementsFileEnv)
	}
	if p.Repository == "" {
		p.Repository = getTrimmedEnv(DepsRepoEnv)
	}
	return nil
}

type Scan struct {
	IncludeAllVulnerabilities bool      `yaml:"includeAllVulnerabilities,omitempty"`
	FixableOnly               bool      `yaml:"fixableOnly,omitempty"`
	FailOnSecurityIssues      *bool     `yaml:"failOnSecurityIssues,omitempty"`
	MinSeverity               string    `yaml:"minSeverity,omitempty"`
	Projects                  []Project `yaml:"projects,omitempty"`
}

func (s *Scan) setDefaultsIfNeeded() (err error) {
	e := &ErrMissingEnv{}
	if !s.IncludeAllVulnerabilities {
		if s.IncludeAllVulnerabilities, err = getBoolEnv(IncludeAllVulnerabilitiesEnv, false); err != nil {
			return
		}
	}
	if !s.FixableOnly {
		if s.FixableOnly, err = getBoolEnv(FixableOnlyEnv, false); err != nil {
			return
		}
	}
	if s.FailOnSecurityIssues == nil {
		var failOnSecurityIssues bool
		if failOnSecurityIssues, err = getBoolEnv(FailOnSecurityIssuesEnv, true); err != nil {
			return
		}
		s.FailOnSecurityIssues = &failOnSecurityIssues
	}
	if s.MinSeverity == "" {
		if err = readParamFromEnv(MinSeverityEnv, &s.MinSeverity); err != nil && !e.IsMissingEnvErr(err) {
			return
		}
	}
	if s.MinSeverity, err = xrutils.GetSeveritiesFormat(s.MinSeverity); err != nil {
		return
	}
	if len(s.Projects) == 0 {
		s.Projects = append(s.Projects, Project{})
	}
	for i := range s.Projects {
		if err = s.Projects[i].setDefaultsIfNeeded(); err != nil {
			return
		}
	}
	return
}

type JFrogPlatform struct {
	Watches         []string `yaml:"watches,omitempty"`
	JFrogProjectKey string   `yaml:"jfrogProjectKey,omitempty"`
}

func (jp *JFrogPlatform) setDefaultsIfNeeded() (err error) {
	e := &ErrMissingEnv{}
	if jp.Watches == nil {
		var watches string
		if err = readParamFromEnv(jfrogWatchesEnv, &watches); err != nil && !e.IsMissingEnvErr(err) {
			return
		}
		if watches != "" {
			// Remove spaces if exists
			watches = strings.ReplaceAll(watches, " ", "")
			jp.Watches = strings.Split(watches, WatchesDelimiter)
		}
	}

	if jp.JFrogProjectKey == "" {
		if err = readParamFromEnv(jfrogProjectEnv, &jp.JFrogProjectKey); err != nil && !e.IsMissingEnvErr(err) {
			return
		}
		// We don't want to return an error from this function if the error is of type ErrMissingEnv because JFrogPlatform environment variables are not mandatory.
		err = nil
	}
	return
}

type ClientInfo struct {
	GitProvider vcsutils.VcsProvider
	vcsclient.VcsInfo
	RepoName  string   `yaml:"repoName,omitempty"`
	Branches  []string `yaml:"branches,omitempty"`
	RepoOwner string
}

type Git struct {
	ClientInfo               `yaml:",inline"`
	BranchNameTemplate       string `yaml:"branchNameTemplate,omitempty"`
	CommitMessageTemplate    string `yaml:"commitMessageTemplate,omitempty"`
	PullRequestTitleTemplate string `yaml:"pullRequestTitleTemplate,omitempty"`
	EmailAuthor              string `yaml:"emailAuthor,omitempty"`
	AggregateFixes           bool   `yaml:"aggregateFixes,omitempty"`
	PullRequestID            int
}

func (g *Git) setDefaultsIfNeeded(git *Git) (err error) {
	g.RepoOwner = git.RepoOwner
	g.GitProvider = git.GitProvider
	g.VcsInfo = git.VcsInfo
	if g.RepoName == "" {
		if git.RepoName == "" {
			return fmt.Errorf("repository name is missing. please set the repository name in your %s file or as the %s environment variable", FrogbotConfigFile, GitRepoEnv)
		}
		g.RepoName = git.RepoName
	}
	if len(g.Branches) == 0 {
		g.Branches = append(g.Branches, git.Branches...)
	}
	if g.BranchNameTemplate == "" {
		branchTemplate := getTrimmedEnv(BranchNameTemplateEnv)
		if err = validateHashPlaceHolder(branchTemplate); err != nil {
			return
		}
		g.BranchNameTemplate = branchTemplate
	}
	if g.CommitMessageTemplate == "" {
		g.CommitMessageTemplate = getTrimmedEnv(CommitMessageTemplateEnv)
	}
	if g.PullRequestTitleTemplate == "" {
		g.PullRequestTitleTemplate = getTrimmedEnv(PullRequestTitleTemplateEnv)
	}
	g.AggregateFixes = git.AggregateFixes
	if !g.AggregateFixes {
		if g.AggregateFixes, err = getBoolEnv(GitAggregateFixesEnv, false); err != nil {
			return
		}
	}
	if g.EmailAuthor == "" {
		if g.EmailAuthor = getTrimmedEnv(GitEmailAuthorEnv); g.EmailAuthor == "" {
			g.EmailAuthor = frogbotAuthorEmail
		}
	}
	// Non-mandatory git branch pr id.
	if pullRequestIDString := getTrimmedEnv(GitPullRequestIDEnv); pullRequestIDString != "" {
		if g.PullRequestID, err = strconv.Atoi(pullRequestIDString); err != nil {
			return err
		}
	}
	return
}

func validateHashPlaceHolder(template string) error {
	if template != "" && !strings.Contains(template, BranchHashPlaceHolder) {
		return fmt.Errorf("branch name template must contain %s", BranchHashPlaceHolder)
	}
	return nil
}

func GetFrogbotUtils() (frogbotUtils *FrogbotUtils, err error) {
	// Get server and git details
	server, gitParams, err := extractClientServerParams()
	if err != nil {
		return nil, err
	}
	defer func() {
		err = errors.Join(err, SanitizeEnv())
	}()

	// Build a version control client for REST API requests
	client, err := vcsclient.
		NewClientBuilder(gitParams.GitProvider).
		ApiEndpoint(gitParams.APIEndpoint).
		Token(gitParams.Token).
		Project(gitParams.Project).
		Logger(log.GetLogger()).
		Username(gitParams.Username).
		Build()
	if err != nil {
		return nil, err
	}

	configAggregator, err := getConfigAggregator(client, gitParams, server)
	if err != nil {
		return nil, err
	}
	return &FrogbotUtils{Repositories: configAggregator, Client: client, ServerDetails: server, ReleasesRepo: os.Getenv(jfrogReleasesRepoEnv)}, err
}

// getConfigAggregator returns a RepoAggregator based on frogbot-config.yml and environment variables.
func getConfigAggregator(client vcsclient.VcsClient, gitParams *Git, server *coreconfig.ServerDetails) (RepoAggregator, error) {
	configFileContent, err := getConfigFileContent(client, &gitParams.ClientInfo)
	// Don't return error in case of a missing frogbot-config.yml file
	// If an error occurs due to a missing file, attempt to generate an environment variable-based configuration aggregator as an alternative.
	if _, missingConfigErr := err.(*ErrMissingConfig); !missingConfigErr && len(configFileContent) == 0 {
		return nil, err
	}
	return BuildRepoAggregator(configFileContent, gitParams, server)
}

// The getConfigFileContent function retrieves the frogbot-config.yml file content.
// If the JF_GIT_REPO and JF_GIT_OWNER environment variables are set, this function will attempt to retrieve the frogbot-config.yml file from the target repository based on these variables.
// If these variables aren't set, this function will attempt to retrieve the frogbot-config.yml file from the current working directory.
func getConfigFileContent(client vcsclient.VcsClient, clientInfo *ClientInfo) (configFileContent []byte, err error) {
	configFileContent, err = readConfigFromTarget(client, clientInfo)
	_, missingConfigErr := err.(*ErrMissingConfig)
	if err != nil && !missingConfigErr {
		return nil, err
	}
	// Read the config from the current working dir
	if len(configFileContent) == 0 {
		configFileContent, err = ReadConfigFromFileSystem(osFrogbotConfigPath)
	}
	return
}

// BuildRepoAggregator receive a frogbot-config.yml file content along with the ClientInfo and ServerDetails parameters.
// Returns a RepoAggregator instance with all the defaults and necessary fields.
func BuildRepoAggregator(configFileContent []byte, gitParams *Git, server *coreconfig.ServerDetails) (resultAggregator RepoAggregator, err error) {
	var cleanAggregator RepoAggregator
	// Unmarshal the frogbot-config.yml file if exists
	if cleanAggregator, err = unmarshalFrogbotConfigYaml(configFileContent); err != nil {
		return
	}
	for _, repository := range cleanAggregator {
		repository.Server = *server
		repository.OutputWriter = GetCompatibleOutputWriter(gitParams.GitProvider)
		if err = repository.Params.setDefaultsIfNeeded(gitParams); err != nil {
			return
		}
		resultAggregator = append(resultAggregator, repository)
	}

	return
}

// unmarshalFrogbotConfigYaml uses the yaml.Unmarshaler interface to parse the yamlContent.
// If there is no config file, the function returns a RepoAggregator with an empty repository.
func unmarshalFrogbotConfigYaml(yamlContent []byte) (result RepoAggregator, err error) {
	if len(yamlContent) == 0 {
		return RepoAggregator{{Params: Params{Scan: Scan{Projects: []Project{{}}}}}}, nil
	}
	err = yaml.Unmarshal(yamlContent, &result)
	return
}

func extractJFrogCredentialsFromEnv() (coreconfig.ServerDetails, error) {
	server := coreconfig.ServerDetails{}
	platformUrl := strings.TrimSuffix(getTrimmedEnv(JFrogUrlEnv), "/")
	xrUrl := strings.TrimSuffix(getTrimmedEnv(jfrogXrayUrlEnv), "/")
	rtUrl := strings.TrimSuffix(getTrimmedEnv(jfrogArtifactoryUrlEnv), "/")
	if xrUrl != "" && rtUrl != "" {
		server.XrayUrl = xrUrl + "/"
		server.ArtifactoryUrl = rtUrl + "/"
	} else {
		if platformUrl == "" {
			return server, fmt.Errorf("%s or %s and %s environment variables are missing", JFrogUrlEnv, jfrogXrayUrlEnv, jfrogArtifactoryUrlEnv)
		}
		server.Url = platformUrl + "/"
		server.XrayUrl = platformUrl + "/xray/"
		server.ArtifactoryUrl = platformUrl + "/artifactory/"
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

func extractClientInfo() (*ClientInfo, error) {
	e := &ErrMissingEnv{}
	var err error
	clientInfo := &ClientInfo{}
	// Branch & Repo names are mandatory variables.
	// Must be set in the frogbot-config.yml or as an environment variables.
	// Validation performed later
	// Set the base branch name
	var branch string
	if err = readParamFromEnv(GitBaseBranchEnv, &branch); err != nil && !e.IsMissingEnvErr(err) {
		return nil, err
	}
	clientInfo.Branches = []string{branch}
	// Set the repository name
	if err = readParamFromEnv(GitRepoEnv, &clientInfo.RepoName); err != nil && !e.IsMissingEnvErr(err) {
		return nil, err
	}

	// Non-mandatory Git Api Endpoint, if not set, default values will be used.
	if err = readParamFromEnv(GitApiEndpointEnv, &clientInfo.APIEndpoint); err != nil && !e.IsMissingEnvErr(err) {
		return nil, err
	}
	if err = verifyValidApiEndpoint(clientInfo.APIEndpoint); err != nil {
		return nil, err
	}
	// Set the Git provider
	if clientInfo.GitProvider, err = extractVcsProviderFromEnv(); err != nil {
		return nil, err
	}
	// Set the git repository owner name (organization)
	if err = readParamFromEnv(GitRepoOwnerEnv, &clientInfo.RepoOwner); err != nil {
		return nil, err
	}
	// Set the access token to the git provider
	if err = readParamFromEnv(GitTokenEnv, &clientInfo.Token); err != nil {
		return nil, err
	}

	// Set Bitbucket Server username
	// Mandatory only for Bitbucket Server, this authentication detail is required for performing git operations.
	if err = readParamFromEnv(GitUsernameEnv, &clientInfo.Username); err != nil && !e.IsMissingEnvErr(err) {
		return nil, err
	}
	// Set Azure Repos Project name
	// Mandatory for Azure Repos only
	if err = readParamFromEnv(GitProjectEnv, &clientInfo.Project); err != nil && clientInfo.GitProvider == vcsutils.AzureRepos {
		return nil, err
	}

	return clientInfo, nil
}

func verifyValidApiEndpoint(apiEndpoint string) error {
	// Empty string will resolve to default values.
	if apiEndpoint == "" {
		return nil
	}
	parsedUrl, err := url.Parse(apiEndpoint)
	if err != nil {
		return err
	}
	if parsedUrl.Scheme == "" {
		return errors.New("the given API endpoint is invalid. Please note that the API endpoint format should be provided with the 'HTTPS' protocol as a prefix")
	}
	return nil
}

func readParamFromEnv(envKey string, paramValue *string) error {
	*paramValue = getTrimmedEnv(envKey)
	if *paramValue == "" {
		return &ErrMissingEnv{VariableName: envKey}
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

func extractClientServerParams() (*coreconfig.ServerDetails, *Git, error) {
	clientInfo, err := extractClientInfo()
	if err != nil {
		return nil, nil, err
	}
	server, err := extractJFrogCredentialsFromEnv()
	if err != nil {
		return nil, nil, err
	}
	git := Git{ClientInfo: *clientInfo}
	return &server, &git, nil
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
	configFileContent, err = os.ReadFile(fullConfigDirPath)
	if err != nil {
		err = fmt.Errorf("an error occurd while reading the %s file at: %s\n%s", FrogbotConfigFile, configRelativePath, err.Error())
	}
	return
}

func setProjectInstallCommand(installCommand string, project *Project) {
	parts := strings.Fields(installCommand)
	if len(parts) > 1 {
		project.InstallCommandArgs = parts[1:]
	}
	project.InstallCommandName = parts[0]
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

// readConfigFromTarget reads the .frogbot/frogbot-config.yml from the target repository
func readConfigFromTarget(client vcsclient.VcsClient, clientInfo *ClientInfo) (configContent []byte, err error) {
	if clientInfo.RepoName != "" && clientInfo.RepoOwner != "" {
		log.Debug("Downloading", FrogbotConfigFile, "from target", clientInfo.RepoOwner, "/", clientInfo.RepoName)
		var branch string
		if len(clientInfo.Branches) == 0 {
			log.Debug(GitBaseBranchEnv, "is missing. Assuming that the", FrogbotConfigFile, "file exists on default branch")
		} else {
			branch = clientInfo.Branches[0]
			log.Debug("the", FrogbotConfigFile, "will be downloaded from the", branch, "branch")
		}

		gitFrogbotConfigPath := fmt.Sprintf("%s/%s", frogbotConfigDir, FrogbotConfigFile)
		var statusCode int
		configContent, statusCode, err = client.DownloadFileFromRepo(context.Background(), clientInfo.RepoOwner, clientInfo.RepoName, branch, gitFrogbotConfigPath)
		if statusCode == http.StatusNotFound {
			log.Debug(fmt.Sprintf("the %s file wasn't recognized in the %s repository owned by %s", gitFrogbotConfigPath, clientInfo.RepoName, clientInfo.RepoOwner))
			// If .frogbot/frogbot-config.yml isn't found, we'll try to run Frogbot using environment variables
			return nil, &ErrMissingConfig{errFrogbotConfigNotFound.Error()}
		}
	}

	return configContent, err
}
