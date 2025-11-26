package utils

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"

	clientutils "github.com/jfrog/jfrog-client-go/utils"

	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-cli-security/utils/xsc"
	"github.com/jfrog/jfrog-client-go/xsc/services"
	"golang.org/x/exp/slices"

	"github.com/jfrog/frogbot/v2/utils/outputwriter"
	securityutils "github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/severityutils"

	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/froggit-go/vcsutils"
	coreconfig "github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-client-go/utils/log"
)

type FrogbotDetails struct {
	XrayVersion   string
	XscVersion    string
	Repositories  RepoAggregator
	ServerDetails *coreconfig.ServerDetails
	GitClient     vcsclient.VcsClient
	ReleasesRepo  string
}

type RepoAggregator []Repository

// Returns an initialized RepoAggregator with an empty repository
func newRepoAggregator() RepoAggregator {
	return RepoAggregator{{Params: Params{Scan: Scan{Projects: []Project{{}}}}}}
}

type Repository struct {
	Params       `yaml:"params,omitempty"`
	OutputWriter outputwriter.OutputWriter
	Server       coreconfig.ServerDetails
}

func (r *Repository) setOutputWriterDetails() {
	r.OutputWriter = outputwriter.GetCompatibleOutputWriter(r.Params.GitProvider)
	r.OutputWriter.SetAvoidExtraMessages(r.Params.AvoidExtraMessages)
	r.OutputWriter.SetPullRequestCommentTitle(r.Params.PullRequestCommentTitle)
}

type Params struct {
	Scan          `yaml:"scan,omitempty"`
	Git           `yaml:"git,omitempty"`
	JFrogPlatform `yaml:"jfrogPlatform,omitempty"`
}

func (p *Params) setDefaultsIfNeeded(gitParamsFromEnv *Git, commandName string) error {
	if err := p.Git.setDefaultsIfNeeded(gitParamsFromEnv, commandName); err != nil {
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
	PathExclusions      []string `yaml:"pathExclusions,omitempty"`
	UseWrapper          *bool    `yaml:"useWrapper,omitempty"`
	MaxPnpmTreeDepth    string   `yaml:"maxPnpmTreeDepth,omitempty"`
	DepsRepo            string   `yaml:"repository,omitempty"`
	InstallCommandName  string
	InstallCommandArgs  []string
	IsRecursiveScan     bool
}

func (p *Project) setDefaultsIfNeeded() error {
	if len(p.WorkingDirs) == 0 {
		workingDir := getTrimmedEnv(WorkingDirectoryEnv)
		if workingDir == "" {

			// If no working directories are provided, and none exist in the environment variable, we designate the project's root directory as our sole working directory.
			// We then execute a recursive scan across the entire project, commencing from the root.
			workingDir = RootDir
			p.IsRecursiveScan = true
			p.WorkingDirs = append(p.WorkingDirs, workingDir)
		} else {
			workingDirs := strings.Split(workingDir, ",")
			p.WorkingDirs = append(p.WorkingDirs, workingDirs...)
		}
	}
	if len(p.PathExclusions) == 0 {
		if p.PathExclusions, _ = readArrayParamFromEnv(PathExclusionsEnv, ";"); len(p.PathExclusions) == 0 {
			p.PathExclusions = securityutils.DefaultScaExcludePatterns
		}
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
	if p.MaxPnpmTreeDepth == "" {
		p.MaxPnpmTreeDepth = getTrimmedEnv(MaxPnpmTreeDepthEnv)
	}

	return nil
}

func (p *Project) GetTechFromInstallCmdIfExists() []string {
	var technologies []string
	if p.InstallCommandName != "" {
		if !slices.Contains(techutils.AllTechnologiesStrings, p.InstallCommandName) {
			log.Warn(fmt.Sprintf("The technology ‘%s’ was inferred from the provided install command but is not listed among the supported technologies. Please provide an install command for one of the following supported technologies: %s", p.InstallCommandName, techutils.AllTechnologiesStrings))
			return technologies
		}
		technologies = append(technologies, p.InstallCommandName)
		if strings.ToLower(p.InstallCommandName) == "dotnet" {
			technologies = append(technologies, "nuget")
		}
	}
	return technologies
}

type Scan struct {
	IncludeAllVulnerabilities       bool      `yaml:"includeAllVulnerabilities,omitempty"`
	FixableOnly                     bool      `yaml:"fixableOnly,omitempty"`
	DetectionOnly                   bool      `yaml:"skipAutoFix,omitempty"`
	FailOnSecurityIssues            *bool     `yaml:"failOnSecurityIssues,omitempty"`
	AvoidPreviousPrCommentsDeletion bool      `yaml:"avoidPreviousPrCommentsDeletion,omitempty"`
	MinSeverity                     string    `yaml:"minSeverity,omitempty"`
	DisableJas                      bool      `yaml:"disableJas,omitempty"`
	AddPrCommentOnSuccess           bool      `yaml:"addPrCommentOnSuccess,omitempty"`
	AllowedLicenses                 []string  `yaml:"allowedLicenses,omitempty"`
	Projects                        []Project `yaml:"projects,omitempty"`
	ConfigProfile                   *services.ConfigProfile
	SkipAutoInstall                 bool
	AllowPartialResults             bool
}

func (s *Scan) setDefaultsIfNeeded() (err error) {
	e := &ErrMissingEnv{}
	if !s.IncludeAllVulnerabilities {
		if s.IncludeAllVulnerabilities, err = getBoolEnv(IncludeAllVulnerabilitiesEnv, false); err != nil {
			return
		}
	}
	if !s.AvoidPreviousPrCommentsDeletion {
		if s.AvoidPreviousPrCommentsDeletion, err = getBoolEnv(AvoidPreviousPrCommentsDeletionEnv, false); err != nil {
			return
		}
	}
	if !s.FixableOnly {
		if s.FixableOnly, err = getBoolEnv(FixableOnlyEnv, false); err != nil {
			return
		}
	}
	if !s.DisableJas {
		if s.DisableJas, err = getBoolEnv(DisableJasEnv, false); err != nil {
			return
		}
	}
	if !s.AddPrCommentOnSuccess {
		if s.AddPrCommentOnSuccess, err = getBoolEnv(AddPrCommentOnSuccessEnv, true); err != nil {
			return
		}
	}
	if !s.DetectionOnly {
		if s.DetectionOnly, err = getBoolEnv(DetectionOnlyEnv, false); err != nil {
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
	if s.MinSeverity != "" {
		var severity severityutils.Severity
		if severity, err = severityutils.ParseSeverity(s.MinSeverity, false); err != nil {
			return
		}
		s.MinSeverity = severity.String()
	}
	if !s.SkipAutoInstall {
		if s.SkipAutoInstall, err = getBoolEnv(SkipAutoInstallEnv, false); err != nil {
			return
		}
	}
	if len(s.Projects) == 0 {
		s.Projects = append(s.Projects, Project{})
	}
	if len(s.AllowedLicenses) == 0 {
		if s.AllowedLicenses, err = readArrayParamFromEnv(AllowedLicensesEnv, ","); err != nil && !e.IsMissingEnvErr(err) {
			return
		}
	}
	if !s.AllowPartialResults {
		if s.AllowPartialResults, err = getBoolEnv(AllowPartialResultsEnv, false); err != nil {
			return
		}
	}
	for i := range s.Projects {
		if err = s.Projects[i].setDefaultsIfNeeded(); err != nil {
			return
		}
	}
	return
}

type JFrogPlatform struct {
	XrayVersion            string
	XscVersion             string
	Watches                []string `yaml:"watches,omitempty"`
	IncludeVulnerabilities bool     `yaml:"includeVulnerabilities,omitempty"`
	JFrogProjectKey        string   `yaml:"jfrogProjectKey,omitempty"`
}

func (jp *JFrogPlatform) setDefaultsIfNeeded() (err error) {
	e := &ErrMissingEnv{}
	if len(jp.Watches) == 0 {
		if jp.Watches, err = readArrayParamFromEnv(jfrogWatchesEnv, WatchesDelimiter); err != nil && !e.IsMissingEnvErr(err) {
			return
		}
	}
	if jp.JFrogProjectKey == "" {
		if err = readParamFromEnv(jfrogProjectEnv, &jp.JFrogProjectKey); err != nil && !e.IsMissingEnvErr(err) {
			return
		}
		// We don't want to return an error from this function if the error is of type ErrMissingEnv because JFrogPlatform environment variables are not mandatory.
		err = nil
	}
	if !jp.IncludeVulnerabilities {
		if jp.IncludeVulnerabilities, err = getBoolEnv(IncludeVulnerabilitiesEnv, false); err != nil {
			return
		}
	}
	return
}

type Git struct {
	GitProvider vcsutils.VcsProvider
	vcsclient.VcsInfo
	RepoOwner                 string
	RepoName                  string   `yaml:"repoName,omitempty"`
	Branches                  []string `yaml:"branches,omitempty"`
	BranchNameTemplate        string   `yaml:"branchNameTemplate,omitempty"`
	CommitMessageTemplate     string   `yaml:"commitMessageTemplate,omitempty"`
	PullRequestTitleTemplate  string   `yaml:"pullRequestTitleTemplate,omitempty"`
	PullRequestCommentTitle   string   `yaml:"pullRequestCommentTitle,omitempty"`
	PullRequestSecretComments bool     `yaml:"pullRequestSecretComments,omitempty"`
	AvoidExtraMessages        bool     `yaml:"avoidExtraMessages,omitempty"`
	EmailAuthor               string   `yaml:"emailAuthor,omitempty"`
	AggregateFixes            bool     `yaml:"aggregateFixes,omitempty"`
	PullRequestDetails        vcsclient.PullRequestInfo
	RepositoryCloneUrl        string
	UseLocalRepository        bool
	UploadSbomToVcs           *bool `yaml:"uploadSbomToVcs,omitempty"`
}

func (g *Git) GetRepositoryHttpsCloneUrl(gitClient vcsclient.VcsClient) (string, error) {
	if g.RepositoryCloneUrl != "" {
		return g.RepositoryCloneUrl, nil
	}
	// If the repository clone URL is not cached, we fetch it from the VCS provider
	repositoryInfo, err := gitClient.GetRepositoryInfo(context.Background(), g.RepoOwner, g.RepoName)
	if err != nil {
		return "", fmt.Errorf("failed to fetch the repository clone URL. %s", err.Error())
	}
	g.RepositoryCloneUrl = repositoryInfo.CloneInfo.HTTP
	return g.RepositoryCloneUrl, nil
}

func (g *Git) setDefaultsIfNeeded(gitParamsFromEnv *Git, commandName string) (err error) {
	g.RepoOwner = gitParamsFromEnv.RepoOwner
	g.GitProvider = gitParamsFromEnv.GitProvider
	g.VcsInfo = gitParamsFromEnv.VcsInfo
	g.PullRequestDetails = gitParamsFromEnv.PullRequestDetails
	if g.RepoName == "" {
		if gitParamsFromEnv.RepoName == "" {
			return fmt.Errorf("repository name is missing. please set the %s environment variable", GitRepoEnv)
		}
		g.RepoName = gitParamsFromEnv.RepoName
	}
	if g.EmailAuthor == "" {
		g.EmailAuthor = frogbotAuthorEmail
	}
	if commandName == ScanPullRequest {
		if err = g.extractScanPullRequestEnvParams(gitParamsFromEnv); err != nil {
			return
		}
	}
	if commandName == ScanRepository {
		if err = g.extractScanRepositoryEnvParams(gitParamsFromEnv); err != nil {
			return
		}
	}

	// We don't need to examine gitParamsFromEnv since GitDependencyGraphSubmissionEnv value is not fetched upon gitParamsFromEnv creation
	if g.UploadSbomToVcs == nil {
		envValue, err := getBoolEnv(GitDependencyGraphSubmissionEnv, true)
		if err != nil {
			return err
		}
		g.UploadSbomToVcs = &envValue
	}

	return
}

func (g *Git) extractScanPullRequestEnvParams(gitParamsFromEnv *Git) (err error) {
	// The Pull Request ID is a mandatory requirement for Frogbot to properly identify and scan the relevant pull request
	if gitParamsFromEnv.PullRequestDetails.ID == 0 {
		return errors.New("no Pull Request ID has been provided. Please configure it by using the `JF_GIT_PULL_REQUEST_ID` environment variable")
	}
	if g.PullRequestCommentTitle == "" {
		g.PullRequestCommentTitle = getTrimmedEnv(PullRequestCommentTitleEnv)
	}
	if !g.PullRequestSecretComments {
		if g.PullRequestSecretComments, err = getBoolEnv(PullRequestSecretCommentsEnv, false); err != nil {
			return
		}
	}

	g.AvoidExtraMessages, err = getBoolEnv(AvoidExtraMessages, false)
	return
}

func (g *Git) extractScanRepositoryEnvParams(gitParamsFromEnv *Git) (err error) {
	// Continue to extract ScanRepository related env params
	noBranchesProvidedViaConfig := len(g.Branches) == 0
	noBranchesProvidedViaEnv := len(gitParamsFromEnv.Branches) == 0
	if noBranchesProvidedViaConfig {
		if noBranchesProvidedViaEnv {
			return errors.New("no branches were provided. Please set your branches using the `JF_GIT_BASE_BRANCH` environment variable")
		}
		g.Branches = gitParamsFromEnv.Branches
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
	if !g.UseLocalRepository {
		if g.UseLocalRepository, err = getBoolEnv(GitUseLocalRepositoryEnv, false); err != nil {
			return
		}
	}
	return
}

func validateHashPlaceHolder(template string) error {
	if template == "" {
		return nil
	}
	if !strings.Contains(template, BranchHashPlaceHolder) {
		return fmt.Errorf("branch name template must contain %s, provided: %s", BranchHashPlaceHolder, template)
	}
	return nil
}

func GetFrogbotDetails(commandName string) (frogbotDetails *FrogbotDetails, err error) {
	// Get server and git details
	jfrogServer, err := extractJFrogCredentialsFromEnvs()
	if err != nil {
		return
	}
	xrayVersion, xscVersion, err := xsc.GetJfrogServicesVersion(jfrogServer)
	if err != nil {
		return
	}

	gitParamsFromEnv, err := extractGitParamsFromEnvs()
	if err != nil {
		return
	}

	defer func() {
		err = errors.Join(err, SanitizeEnv())
	}()

	// Build a version control client for REST API requests
	client, err := vcsclient.
		NewClientBuilder(gitParamsFromEnv.GitProvider).
		ApiEndpoint(strings.TrimSuffix(gitParamsFromEnv.APIEndpoint, "/")).
		Token(gitParamsFromEnv.Token).
		Project(gitParamsFromEnv.Project).
		Logger(log.GetLogger()).
		Username(gitParamsFromEnv.Username).
		Build()
	if err != nil {
		return
	}

	configAggregator, err := getConfigAggregator(xrayVersion, xscVersion, client, gitParamsFromEnv, jfrogServer, commandName)
	if err != nil {
		return
	}

	// TODO when deprecating multiple repositories support, pass the correct projectKey from the single repo we have to getConfigProfileIfExistsAndValid
	configProfile, repoCloneUrl, err := getConfigProfileIfExistsAndValid(xrayVersion, jfrogServer, client, gitParamsFromEnv, configAggregator[0].JFrogProjectKey)
	if err != nil {
		return
	}

	// We apply the configProfile to all received repositories. If no config profile was fetched, a nil value is passed
	// TODO This loop must be deleted when we will no longer accept multiple repositories in a single scan
	for i := range configAggregator {
		configAggregator[i].Scan.ConfigProfile = configProfile
		configAggregator[i].Git.RepositoryCloneUrl = repoCloneUrl
	}

	frogbotDetails = &FrogbotDetails{XrayVersion: xrayVersion, XscVersion: xscVersion, Repositories: configAggregator, GitClient: client, ServerDetails: jfrogServer, ReleasesRepo: os.Getenv(jfrogReleasesRepoEnv)}
	return
}

// Returns a RepoAggregator based on environment variables only.
func getConfigAggregator(xrayVersion, xscVersion string, gitClient vcsclient.VcsClient, gitParamsFromEnv *Git, jfrogServer *coreconfig.ServerDetails, commandName string) (RepoAggregator, error) {
	return BuildRepoAggregator(xrayVersion, xscVersion, gitClient, gitParamsFromEnv, jfrogServer, commandName)
}

// Builds a RepoAggregator from environment variables only (no config file).
// Returns a RepoAggregator instance with all the defaults and necessary fields.
func BuildRepoAggregator(xrayVersion, xscVersion string, gitClient vcsclient.VcsClient, gitParamsFromEnv *Git, server *coreconfig.ServerDetails, commandName string) (resultAggregator RepoAggregator, err error) {
	// Create a single repository from environment variables
	repository := newRepoAggregator()[0]
	repository.Server = *server
	repository.Params.XrayVersion = xrayVersion
	repository.Params.XscVersion = xscVersion
	if err = repository.Params.setDefaultsIfNeeded(gitParamsFromEnv, commandName); err != nil {
		return
	}
	repository.setOutputWriterDetails()
	repository.OutputWriter.SetSizeLimit(gitClient)
	resultAggregator = append(resultAggregator, repository)
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

func extractGitParamsFromEnvs() (*Git, error) {
	e := &ErrMissingEnv{}
	var err error
	gitEnvParams := &Git{}
	// Branch & Repo names are mandatory variables.
	// Must be set as environment variables.
	// Validation performed later
	// Set the base branch name
	var branch string
	if err = readParamFromEnv(GitBaseBranchEnv, &branch); err != nil && !e.IsMissingEnvErr(err) {
		return nil, err
	}
	if branch != "" {
		gitEnvParams.Branches = []string{branch}
	}
	// Non-mandatory Git Api Endpoint, if not set, default values will be used.
	if err = readParamFromEnv(GitApiEndpointEnv, &gitEnvParams.APIEndpoint); err != nil && !e.IsMissingEnvErr(err) {
		return nil, err
	}
	if err = verifyValidApiEndpoint(gitEnvParams.APIEndpoint); err != nil {
		return nil, err
	}
	// [Mandatory] Set the Git provider
	if gitEnvParams.GitProvider, err = extractVcsProviderFromEnv(); err != nil {
		return nil, err
	}
	// [Mandatory] Set the git repository owner name (organization)
	if err = readParamFromEnv(GitRepoOwnerEnv, &gitEnvParams.RepoOwner); err != nil {
		return nil, err
	}
	// [Mandatory] Set the access token to the git provider
	if err = readParamFromEnv(GitTokenEnv, &gitEnvParams.Token); err != nil {
		return nil, err
	}

	// [Mandatory] Set the repository name, except for multi repository.
	if err = readParamFromEnv(GitRepoEnv, &gitEnvParams.RepoName); err != nil {
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
	if envPrId := getTrimmedEnv(GitPullRequestIDEnv); envPrId != "" {
		var convertedPrId int
		if convertedPrId, err = strconv.Atoi(envPrId); err != nil {
			return nil, fmt.Errorf("failed parsing %s environment variable as a number. The received environment is : %s", GitPullRequestIDEnv, envPrId)
		}
		gitEnvParams.PullRequestDetails = vcsclient.PullRequestInfo{ID: int64(convertedPrId)}
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

func readArrayParamFromEnv(envKey, delimiter string) ([]string, error) {
	var envValue string
	var err error
	e := &ErrMissingEnv{}
	if err = readParamFromEnv(envKey, &envValue); err != nil && !e.IsMissingEnvErr(err) {
		return nil, err
	}
	if envValue == "" {
		return nil, &ErrMissingEnv{VariableName: envKey}
	}
	// Remove spaces if exists
	envValue = strings.ReplaceAll(envValue, " ", "")
	return strings.Split(envValue, delimiter), nil
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

// This function attempts to fetch a config profile if JF_USE_CONFIG_PROFILE is set to true.
// If we need to use a profile, we first try to get the profile by name that can be provided through JF_CONFIG_PROFILE. If name is provided but profile doesn't exist we return an error.
// If we need to use a profile, but name is not provided, we check if there is a config profile associated to the repo URL.
// When a profile is found we verify several conditions on it.
// If a profile was requested but not found by url nor by name we return an error.
func getConfigProfileIfExistsAndValid(xrayVersion string, jfrogServer *coreconfig.ServerDetails, gitClient vcsclient.VcsClient, gitParams *Git, projectKey string) (configProfile *services.ConfigProfile, repoCloneUrl string, err error) {
	var useConfigProfile bool
	if useConfigProfile, err = getBoolEnv(JfrogUseConfigProfileEnv, false); err != nil || !useConfigProfile {
		log.Debug(fmt.Sprintf("Configuration Profile usage is disabled. All configurations will be derived from environment variables and files.\nTo enable a Configuration Profile, please set %s to TRUE", JfrogUseConfigProfileEnv))
		return
	}

	if err = clientutils.ValidateMinimumVersion(clientutils.Xray, xrayVersion, services.ConfigProfileNewSchemaMinXrayVersion); err != nil {
		log.Info(fmt.Sprintf("The utilized Frogbot version requires a higher version of Xray than %s in order to use Config Profile. Please upgrade Xray to version %s and above or downgrade Frogbot to prior versions", xrayVersion, services.ConfigProfileNewSchemaMinXrayVersion))
		return
	}

	// Attempt to get the config profile by profile's name
	profileName := getTrimmedEnv(JfrogConfigProfileEnv)
	if profileName != "" {
		log.Debug(fmt.Sprintf("Configuration profile was requested. Searching profile by provided name '%s'", profileName))
		if configProfile, err = xsc.GetConfigProfileByName(xrayVersion, jfrogServer, profileName, projectKey); err != nil || configProfile == nil {
			return
		}
		err = verifyConfigProfileValidity(configProfile)
		return
	}
	// Getting repository's url in order to get repository HTTP url
	if repoCloneUrl, err = gitParams.GetRepositoryHttpsCloneUrl(gitClient); err != nil {
		return
	}
	// Attempt to get a config profile associated with the repo URL
	log.Debug(fmt.Sprintf("Configuration profile was requested. Searching profile associated to repository '%s'", jfrogServer.Url))
	if configProfile, err = xsc.GetConfigProfileByUrl(xrayVersion, jfrogServer, repoCloneUrl); err != nil || configProfile == nil {
		return
	}
	err = verifyConfigProfileValidity(configProfile)
	return
}

func verifyConfigProfileValidity(configProfile *services.ConfigProfile) (err error) {
	// Currently, only a single Module that represents the entire project is supported
	if len(configProfile.Modules) != 1 {
		err = fmt.Errorf("more than one module was found '%s' profile. Frogbot currently supports only one module per config profile", configProfile.ProfileName)
		return
	}
	if configProfile.Modules[0].PathFromRoot != "." {
		err = fmt.Errorf("module '%s' in profile '%s' contains the following path from root: '%s'. Frogbot currently supports only a single module with a '.' path from root", configProfile.Modules[0].ModuleName, configProfile.ProfileName, configProfile.Modules[0].PathFromRoot)
		return
	}
	log.Info(fmt.Sprintf("Using Config profile '%s'. jfrog-apps-config will be ignored if exists", configProfile.ProfileName))
	return
}
