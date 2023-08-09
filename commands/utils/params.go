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

	// Pull Request ID cannot be 0
	UndefinedPrID = 0
)

var (
	errFrogbotConfigNotFound = fmt.Errorf("%s wasn't found in the Frogbot directory and its subdirectories. Assuming all the configuration is stored as environment variables", FrogbotConfigFile)
	// Possible Config file path's to Frogbot Management repository
	osFrogbotConfigPath = filepath.Join(frogbotConfigDir, FrogbotConfigFile)
)

type FrogbotDetails struct {
	Repositories  RepoAggregator
	ServerDetails *coreconfig.ServerDetails
	GitClient     vcsclient.VcsClient
	ReleasesRepo  string
}

type RepoAggregator []Repository

// NewRepoAggregator returns an initialized RepoAggregator with an empty repository
func NewRepoAggregator() RepoAggregator {
	return RepoAggregator{{Params: Params{Scan: Scan{Projects: []Project{{}}}}}}
}

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

func (p *Params) setDefaultsIfNeeded(gitParamsFromEnv *Git) error {
	if err := p.Git.setDefaultsIfNeeded(gitParamsFromEnv); err != nil {
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
	DepsRepo            string   `yaml:"repository,omitempty"`
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
	if p.DepsRepo == "" {
		p.DepsRepo = getTrimmedEnv(DepsRepoEnv)
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

type Git struct {
	GitProvider vcsutils.VcsProvider
	vcsclient.VcsInfo
	RepoOwner                string
	RepoName                 string   `yaml:"repoName,omitempty"`
	Branches                 []string `yaml:"branches,omitempty"`
	BranchNameTemplate       string   `yaml:"branchNameTemplate,omitempty"`
	CommitMessageTemplate    string   `yaml:"commitMessageTemplate,omitempty"`
	PullRequestTitleTemplate string   `yaml:"pullRequestTitleTemplate,omitempty"`
	EmailAuthor              string   `yaml:"emailAuthor,omitempty"`
	AggregateFixes           bool     `yaml:"aggregateFixes,omitempty"`
	PullRequestDetails       vcsclient.PullRequestInfo
}

func (g *Git) setDefaultsIfNeeded(gitParamsFromEnv *Git) (err error) {
	g.RepoOwner = gitParamsFromEnv.RepoOwner
	g.GitProvider = gitParamsFromEnv.GitProvider
	g.VcsInfo = gitParamsFromEnv.VcsInfo
	if g.RepoName == "" {
		if gitParamsFromEnv.RepoName == "" {
			return fmt.Errorf("repository name is missing. please set the repository name in your %s file or as the %s environment variable", FrogbotConfigFile, GitRepoEnv)
		}
		g.RepoName = gitParamsFromEnv.RepoName
	}
	if len(g.Branches) == 0 && len(gitParamsFromEnv.Branches) == 0 {
		var branch string
		if branch, err = GetBranchFromDotGit(); err != nil {
			return
		}
		g.Branches = append(g.Branches, branch)
	} else if len(g.Branches) == 0 {
		g.Branches = append(g.Branches, gitParamsFromEnv.Branches...)
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
	if g.PullRequestDetails.ID == UndefinedPrID {
		if idStr := getTrimmedEnv(GitPullRequestIDEnv); idStr != "" {
			var idNum int
			if idNum, err = strconv.Atoi(idStr); err != nil {
				return fmt.Errorf("failed parsing pull request ID as a number. ID as string : %s", idStr)
			}
			g.PullRequestDetails.ID = int64(idNum)
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

func GetFrogbotDetails(commandName string) (frogbotDetails *FrogbotDetails, err error) {
	// Get server and git details
	jfrogServer, err := extractJFrogCredentialsFromEnvs()
	if err != nil {
		return
	}
	gitParamsFromEnv, err := extractGitInfoFromEnvs()
	if err != nil {
		return
	}

	defer func() {
		err = errors.Join(err, SanitizeEnv())
	}()

	// Build a version control client for REST API requests
	client, err := vcsclient.
		NewClientBuilder(gitParamsFromEnv.GitProvider).
		ApiEndpoint(gitParamsFromEnv.APIEndpoint).
		Token(gitParamsFromEnv.Token).
		Project(gitParamsFromEnv.Project).
		Logger(log.GetLogger()).
		Username(gitParamsFromEnv.Username).
		Build()
	if err != nil {
		return nil, err
	}

	configAggregator, err := getConfigAggregator(client, gitParamsFromEnv, jfrogServer, commandName)
	if err != nil {
		return nil, err
	}
	return &FrogbotDetails{Repositories: configAggregator, GitClient: client, ServerDetails: jfrogServer, ReleasesRepo: os.Getenv(jfrogReleasesRepoEnv)}, err
}

// getConfigAggregator returns a RepoAggregator based on frogbot-config.yml and environment variables.
func getConfigAggregator(gitClient vcsclient.VcsClient, gitParamsFromEnv *Git, jfrogServer *coreconfig.ServerDetails, commandName string) (RepoAggregator, error) {
	configFileContent, err := getConfigFileContent(gitClient, gitParamsFromEnv, commandName)
	// Don't return error in case of a missing frogbot-config.yml file
	// If an error occurs due to a missing file, attempt to generate an environment variable-based configuration aggregator as an alternative.
	var errMissingConfig *ErrMissingConfig
	if !errors.As(err, &errMissingConfig) && len(configFileContent) == 0 {
		return nil, err
	}
	return BuildRepoAggregator(configFileContent, gitParamsFromEnv, jfrogServer)
}

// The getConfigFileContent function retrieves the frogbot-config.yml file content.
// If the JF_GIT_REPO and JF_GIT_OWNER environment variables are set, this function will attempt to retrieve the frogbot-config.yml file from the target repository based on these variables.
// If these variables aren't set, this function will attempt to retrieve the frogbot-config.yml file from the current working directory.
func getConfigFileContent(gitClient vcsclient.VcsClient, gitParamsFromEnv *Git, commandName string) (configFileContent []byte, err error) {
	if commandName == ScanAndFixRepos || commandName == CreateFixPullRequests {
		configFileContent, err = ReadConfigFromFileSystem(osFrogbotConfigPath)
		return
	}
	return readConfigFromTarget(gitClient, gitParamsFromEnv)
}

// BuildRepoAggregator receives the content of a frogbot-config.yml file, along with the Git (built from environment variables) and ServerDetails parameters.
// Returns a RepoAggregator instance with all the defaults and necessary fields.
func BuildRepoAggregator(configFileContent []byte, gitParamsFromEnv *Git, server *coreconfig.ServerDetails) (resultAggregator RepoAggregator, err error) {
	var cleanAggregator RepoAggregator
	// Unmarshal the frogbot-config.yml file if exists
	if cleanAggregator, err = unmarshalFrogbotConfigYaml(configFileContent); err != nil {
		return
	}
	for _, repository := range cleanAggregator {
		repository.Server = *server
		repository.OutputWriter = GetCompatibleOutputWriter(gitParamsFromEnv.GitProvider)
		if err = repository.Params.setDefaultsIfNeeded(gitParamsFromEnv); err != nil {
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
		result = NewRepoAggregator()
		return
	}
	err = yaml.Unmarshal(yamlContent, &result)
	return
}

func extractJFrogCredentialsFromEnvs() (*coreconfig.ServerDetails, error) {
	server := coreconfig.ServerDetails{}
	platformUrl := strings.TrimSuffix(getTrimmedEnv(JFrogUrlEnv), "/")
	xrUrl := strings.TrimSuffix(getTrimmedEnv(jfrogXrayUrlEnv), "/")
	rtUrl := strings.TrimSuffix(getTrimmedEnv(jfrogArtifactoryUrlEnv), "/")
	if xrUrl != "" && rtUrl != "" {
		server.XrayUrl = xrUrl + "/"
		server.ArtifactoryUrl = rtUrl + "/"
	} else {
		if platformUrl == "" {
			return nil, fmt.Errorf("%s or %s and %s environment variables are missing", JFrogUrlEnv, jfrogXrayUrlEnv, jfrogArtifactoryUrlEnv)
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
		return nil, fmt.Errorf("%s and %s or %s environment variables are missing", JFrogUserEnv, JFrogPasswordEnv, JFrogTokenEnv)
	}
	return &server, nil
}

func extractGitInfoFromEnvs() (*Git, error) {
	e := &ErrMissingEnv{}
	var err error
	gitEnvParams := &Git{}
	// Branch & Repo names are mandatory variables.
	// Must be set in the frogbot-config.yml or as an environment variables.
	// Validation performed later
	// Set the base branch name
	var branch string
	if err = readParamFromEnv(GitBaseBranchEnv, &branch); err != nil && !e.IsMissingEnvErr(err) {
		return nil, err
	}
	if branch != "" {
		gitEnvParams.Branches = []string{branch}
	}
	// Set the repository name
	if err = readParamFromEnv(GitRepoEnv, &gitEnvParams.RepoName); err != nil && !e.IsMissingEnvErr(err) {
		return nil, err
	}

	// Non-mandatory Git Api Endpoint, if not set, default values will be used.
	if err = readParamFromEnv(GitApiEndpointEnv, &gitEnvParams.APIEndpoint); err != nil && !e.IsMissingEnvErr(err) {
		return nil, err
	}
	if err = verifyValidApiEndpoint(gitEnvParams.APIEndpoint); err != nil {
		return nil, err
	}
	// Set the Git provider
	if gitEnvParams.GitProvider, err = extractVcsProviderFromEnv(); err != nil {
		return nil, err
	}
	// Set the git repository owner name (organization)
	if err = readParamFromEnv(GitRepoOwnerEnv, &gitEnvParams.RepoOwner); err != nil {
		return nil, err
	}
	// Set the access token to the git provider
	if err = readParamFromEnv(GitTokenEnv, &gitEnvParams.Token); err != nil {
		return nil, err
	}

	// Set Bitbucket Server username
	// Mandatory only for Bitbucket Server, this authentication detail is required for performing git operations.
	if err = readParamFromEnv(GitUsernameEnv, &gitEnvParams.Username); err != nil && !e.IsMissingEnvErr(err) {
		return nil, err
	}
	// Set Azure Repos Project name
	// Mandatory for Azure Repos only
	if err = readParamFromEnv(GitProjectEnv, &gitEnvParams.Project); err != nil && gitEnvParams.GitProvider == vcsutils.AzureRepos {
		return nil, err
	}

	return gitEnvParams, nil
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
	return 0, fmt.Errorf("%s should be one of: '%s', '%s', '%s' or '%s'", GitProvider, GitHub, GitLab, BitbucketServer, AzureRepos)
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
func readConfigFromTarget(client vcsclient.VcsClient, gitParamsFromEnv *Git) (configContent []byte, err error) {
	repoName := gitParamsFromEnv.RepoName
	repoOwner := gitParamsFromEnv.RepoOwner
	branches := gitParamsFromEnv.Branches
	if repoName != "" && repoOwner != "" {
		log.Debug("Downloading", FrogbotConfigFile, "from target", repoOwner, "/", repoName)
		var branch string
		if len(branches) == 0 {
			log.Debug(GitBaseBranchEnv, "is missing. Assuming that the", FrogbotConfigFile, "file exists on default branch")
		} else {
			// We encounter this scenario when the JF_GIT_BASE_BRANCH is defined. In this situation, we have only one branch.
			branch = branches[0]
			log.Debug("the", FrogbotConfigFile, "will be downloaded from the", branch, "branch")
		}

		gitFrogbotConfigPath := fmt.Sprintf("%s/%s", frogbotConfigDir, FrogbotConfigFile)
		var statusCode int
		configContent, statusCode, err = client.DownloadFileFromRepo(context.Background(), repoOwner, repoName, branch, gitFrogbotConfigPath)
		if statusCode == http.StatusNotFound {
			log.Debug(fmt.Sprintf("the %s file wasn't recognized in the %s repository owned by %s", gitFrogbotConfigPath, repoName, repoOwner))
			// If .frogbot/frogbot-config.yml isn't found, we'll try to run Frogbot using environment variables
			return nil, &ErrMissingConfig{errFrogbotConfigNotFound.Error()}
		}
	}

	return configContent, err
}
