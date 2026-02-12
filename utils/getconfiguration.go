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

	"github.com/jfrog/jfrog-cli-security/utils/xsc"
	"github.com/jfrog/jfrog-client-go/xsc/services"

	"github.com/jfrog/frogbot/v2/utils/outputwriter"

	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/froggit-go/vcsutils"
	coreconfig "github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-client-go/utils/log"
)

const configProfileV3MinXrayVersion = "3.117.0" // TODO switch to real the Xray version when available

type FrogbotDetails struct {
	XrayVersion   string
	XscVersion    string
	Repository    Repository
	ServerDetails *coreconfig.ServerDetails
	GitClient     vcsclient.VcsClient
	ReleasesRepo  string
}

type Repository struct {
	Params
	OutputWriter outputwriter.OutputWriter
	Server       coreconfig.ServerDetails
}

func (r *Repository) setOutputWriterDetails() {
	// Check if the user has access to the frogbot repository (to access the resources needed)
	frogbotRepoConnection := CheckConnection(outputwriter.FrogbotRepoUrl)
	r.OutputWriter = outputwriter.GetCompatibleOutputWriter(r.Params.Git.GitProvider, frogbotRepoConnection.IsConnected())
}

type Params struct {
	*services.ConfigProfile
	Git
	JFrogPlatform
}

type JFrogPlatform struct {
	XrayVersion     string
	XscVersion      string
	JFrogProjectKey string
}

func (jp *JFrogPlatform) setJfProjectKeyIfExists() (err error) {
	e := &ErrMissingEnv{}
	if err = readParamFromEnv(jfrogProjectEnv, &jp.JFrogProjectKey); err != nil && !e.IsMissingEnvErr(err) {
		return
	}
	return nil
}

type Git struct {
	GitProvider vcsutils.VcsProvider
	vcsclient.VcsInfo
	RepoOwner          string
	RepoName           string
	Branches           []string
	PullRequestDetails vcsclient.PullRequestInfo
	RepositoryCloneUrl string
	UploadSbomToVcs    *bool
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
	g.RepoName = gitParamsFromEnv.RepoName

	if commandName == ScanPullRequest {
		if gitParamsFromEnv.PullRequestDetails.ID == 0 {
			return errors.New("no Pull Request ID has been provided. Please configure it by using the `JF_GIT_PULL_REQUEST_ID` environment variable")
		}
	}
	if commandName == ScanRepository {
		if len(gitParamsFromEnv.Branches) == 0 {
			return errors.New("no branches were provided. Please set your branches using the `JF_GIT_BASE_BRANCH` environment variable")
		}
		g.Branches = gitParamsFromEnv.Branches
	}
	envValue, err := getBoolEnv(GitDependencyGraphSubmissionEnv, true)
	if err != nil {
		return err
	}
	g.UploadSbomToVcs = &envValue
	return
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

	gitParams, err := extractGitParamsFromEnvs()
	if err != nil {
		return
	}

	defer func() {
		err = errors.Join(err, SanitizeEnv())
	}()

	// Build a version control client for REST API requests
	client, err := vcsclient.
		NewClientBuilder(gitParams.GitProvider).
		ApiEndpoint(strings.TrimSuffix(gitParams.APIEndpoint, "/")).
		Token(gitParams.Token).
		Project(gitParams.Project).
		Logger(log.GetLogger()).
		Username(gitParams.Username).
		Build()
	if err != nil {
		return
	}

	repository, err := BuildRepositoryFromEnv(xrayVersion, xscVersion, client, gitParams, jfrogServer, commandName)
	if err != nil {
		return
	}

	configProfile, repoCloneUrl, err := getConfigurationProfile(xrayVersion, jfrogServer, client, gitParams)
	if err != nil {
		return
	}

	// We apply the configProfile to the repository. If no config profile was fetched, a nil value is passed
	repository.ConfigProfile = configProfile
	repository.Git.RepositoryCloneUrl = repoCloneUrl

	frogbotDetails = createFrogbotDetails(xrayVersion, xscVersion, repository, client, jfrogServer)
	return
}

func createFrogbotDetails(xrayVersion string, xscVersion string, repository Repository, client vcsclient.VcsClient, jfrogServer *coreconfig.ServerDetails) *FrogbotDetails {
	frogbotDetails := FrogbotDetails{XrayVersion: xrayVersion, XscVersion: xscVersion, Repository: repository, GitClient: client, ServerDetails: jfrogServer}
	frogbotDetails.ReleasesRepo = os.Getenv(jfrogReleasesRepoEnv)
	if frogbotDetails.ReleasesRepo == "" {
		frogbotDetails.ReleasesRepo = repository.GeneralConfig.ScannersDownloadPath
	}
	return &frogbotDetails
}

// Builds a Repository from environment variables only
// Returns a Repository instance with all the defaults and necessary fields.
func BuildRepositoryFromEnv(xrayVersion, xscVersion string, gitClient vcsclient.VcsClient, gitParamsFromEnv *Git, server *coreconfig.ServerDetails, commandName string) (repository Repository, err error) {
	// Create a single repository from environment variables
	repository = Repository{}
	repository.Server = *server
	repository.Params.JFrogPlatform.XrayVersion = xrayVersion
	repository.Params.JFrogPlatform.XscVersion = xscVersion
	if err = repository.Params.JFrogPlatform.setJfProjectKeyIfExists(); err != nil {
		return
	}

	if err = repository.Params.Git.setDefaultsIfNeeded(gitParamsFromEnv, commandName); err != nil {
		return
	}

	repository.setOutputWriterDetails()
	repository.OutputWriter.SetSizeLimit(gitClient)
	return repository, nil
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
	if accessToken := getTrimmedEnv(JFrogTokenEnv); accessToken != "" {
		server.AccessToken = accessToken
	} else {
		return nil, fmt.Errorf("%s environment variable is missing", JFrogTokenEnv)
	}
	return &server, nil
}

func autoDetectCIEnvVars() {
	gitProvider := getTrimmedEnv(GitProvider)

	switch {
	case os.Getenv("GITLAB_CI") == "true":
		if gitProvider == "" || gitProvider == string(GitLab) {
			autoDetectGitLabCI()
		}
	case os.Getenv("TF_BUILD") == "True":
		autoDetectAzurePipelinesUniversal()
		if gitProvider == "" || gitProvider == string(AzureRepos) || gitProvider == string(GitHub) {
			autoDetectAzurePipelinesWithPRSupport()
		}
		if gitProvider == "" || gitProvider == string(AzureRepos) {
			autoDetectAzurePipelinesAzureRepos()
		}
	case os.Getenv("JENKINS_URL") != "":
		autoDetectJenkins()
	}
}

func autoDetectGitLabCI() {
	if os.Getenv(GitProvider) == "" {
		if err := os.Setenv(GitProvider, string(GitLab)); err != nil {
			log.Warn("Failed to set JF_GIT_PROVIDER:", err)
		}
	}

	if os.Getenv(GitRepoOwnerEnv) == "" {
		if namespace := os.Getenv("CI_PROJECT_NAMESPACE"); namespace != "" {
			if err := os.Setenv(GitRepoOwnerEnv, namespace); err != nil {
				log.Warn("Failed to set JF_GIT_OWNER:", err)
			}
		}
	}

	if os.Getenv(GitRepoEnv) == "" {
		if repoName := os.Getenv("CI_PROJECT_NAME"); repoName != "" {
			if err := os.Setenv(GitRepoEnv, repoName); err != nil {
				log.Warn("Failed to set JF_GIT_REPO:", err)
			}
		}
	}

	if os.Getenv(GitBaseBranchEnv) == "" {
		if targetBranch := os.Getenv("CI_MERGE_REQUEST_TARGET_BRANCH_NAME"); targetBranch != "" {
			if err := os.Setenv(GitBaseBranchEnv, targetBranch); err != nil {
				log.Warn("Failed to set JF_GIT_BASE_BRANCH:", err)
			}
		} else if commitBranch := os.Getenv("CI_COMMIT_REF_NAME"); commitBranch != "" {
			if err := os.Setenv(GitBaseBranchEnv, commitBranch); err != nil {
				log.Warn("Failed to set JF_GIT_BASE_BRANCH:", err)
			}
		}
	}

	if os.Getenv(GitPullRequestIDEnv) == "" {
		if mrIID := os.Getenv("CI_MERGE_REQUEST_IID"); mrIID != "" {
			if err := os.Setenv(GitPullRequestIDEnv, mrIID); err != nil {
				log.Warn("Failed to set JF_GIT_PULL_REQUEST_ID:", err)
			}
		}
	}

	if os.Getenv(GitApiEndpointEnv) == "" {
		if apiURL := os.Getenv("CI_API_V4_URL"); apiURL != "" {
			if err := os.Setenv(GitApiEndpointEnv, apiURL); err != nil {
				log.Warn("Failed to set JF_GIT_API_ENDPOINT:", err)
			}
		}
	}
}

func autoDetectAzurePipelinesUniversal() {
	if os.Getenv(GitRepoEnv) == "" {
		if repoName := os.Getenv("BUILD_REPOSITORY_NAME"); repoName != "" {
			if err := os.Setenv(GitRepoEnv, repoName); err != nil {
				log.Warn("Failed to set JF_GIT_REPO:", err)
			}
		}
	}

	if os.Getenv(GitBaseBranchEnv) == "" {
		if sourceBranch := os.Getenv("BUILD_SOURCEBRANCHNAME"); sourceBranch != "" {
			if err := os.Setenv(GitBaseBranchEnv, sourceBranch); err != nil {
				log.Warn("Failed to set JF_GIT_BASE_BRANCH:", err)
			}
		}
	}
}

func autoDetectAzurePipelinesWithPRSupport() {
	if os.Getenv(GitBaseBranchEnv) == "" {
		if targetBranch := os.Getenv("SYSTEM_PULLREQUEST_TARGETBRANCH"); targetBranch != "" {
			cleanBranch := strings.TrimPrefix(targetBranch, "refs/heads/")
			if err := os.Setenv(GitBaseBranchEnv, cleanBranch); err != nil {
				log.Warn("Failed to set JF_GIT_BASE_BRANCH:", err)
			}
		}
	}

	if os.Getenv(GitPullRequestIDEnv) == "" {
		if prID := os.Getenv("SYSTEM_PULLREQUEST_PULLREQUESTID"); prID != "" {
			if err := os.Setenv(GitPullRequestIDEnv, prID); err != nil {
				log.Warn("Failed to set JF_GIT_PULL_REQUEST_ID:", err)
			}
		}
	}
}

func autoDetectAzurePipelinesAzureRepos() {
	if os.Getenv(GitProvider) == "" {
		if err := os.Setenv(GitProvider, string(AzureRepos)); err != nil {
			log.Warn("Failed to set JF_GIT_PROVIDER:", err)
		}
	}

	if os.Getenv(GitAzureProjectEnv) == "" {
		if project := os.Getenv("SYSTEM_TEAMPROJECT"); project != "" {
			if err := os.Setenv(GitAzureProjectEnv, project); err != nil {
				log.Warn("Failed to set JF_GIT_PROJECT:", err)
			}
		}
	}

	if os.Getenv(GitApiEndpointEnv) == "" {
		if orgURL := os.Getenv("SYSTEM_TEAMFOUNDATIONCOLLECTIONURI"); orgURL != "" {
			apiURL := strings.TrimSuffix(orgURL, "/") + "/_apis"
			if err := os.Setenv(GitApiEndpointEnv, apiURL); err != nil {
				log.Warn("Failed to set JF_GIT_API_ENDPOINT:", err)
			}
		}
	}
}

func autoDetectJenkins() {
	if os.Getenv(GitPullRequestIDEnv) == "" {
		if changeID := os.Getenv("CHANGE_ID"); changeID != "" {
			if err := os.Setenv(GitPullRequestIDEnv, changeID); err != nil {
				log.Warn("Failed to set JF_GIT_PULL_REQUEST_ID:", err)
			}
		}
	}

	if os.Getenv(GitBaseBranchEnv) == "" {
		if branch := os.Getenv("BRANCH_NAME"); branch != "" {
			if err := os.Setenv(GitBaseBranchEnv, branch); err != nil {
				log.Warn("Failed to set JF_GIT_BASE_BRANCH:", err)
			}
		}
	}
}

func extractGitParamsFromEnvs() (*Git, error) {
	e := &ErrMissingEnv{}
	var err error
	gitEnvParams := &Git{}

	autoDetectCIEnvVars()

	// Mandatory as env var for scan-repository, fetched from vcsclient.PullRequestInfo for scan-pr
	var branch string
	if err = readParamFromEnv(GitBaseBranchEnv, &branch); err != nil && !e.IsMissingEnvErr(err) {
		return nil, err
	}
	if branch != "" {
		gitEnvParams.Branches = []string{branch}
	}

	if err = readParamFromEnv(GitRepoEnv, &gitEnvParams.RepoName); err != nil {
		return nil, err
	}

	if err = readParamFromEnv(GitApiEndpointEnv, &gitEnvParams.APIEndpoint); err != nil && !e.IsMissingEnvErr(err) {
		return nil, err
	}
	if err = verifyValidApiEndpoint(gitEnvParams.APIEndpoint); err != nil {
		return nil, err
	}
	if gitEnvParams.GitProvider, err = extractVcsProviderFromEnv(); err != nil {
		return nil, err
	}
	if err = readParamFromEnv(GitRepoOwnerEnv, &gitEnvParams.RepoOwner); err != nil {
		return nil, err
	}
	if err = readParamFromEnv(GitTokenEnv, &gitEnvParams.Token); err != nil {
		return nil, err
	}

	// Mandatory only for Bitbucket Server, this authentication detail is required for performing git operations.
	if err = readParamFromEnv(GitBitBucketUsernameEnv, &gitEnvParams.Username); err != nil && gitEnvParams.GitProvider == vcsutils.BitbucketServer {
		return nil, err
	}
	// Mandatory for Azure Repos only
	if err = readParamFromEnv(GitAzureProjectEnv, &gitEnvParams.Project); err != nil && gitEnvParams.GitProvider == vcsutils.AzureRepos {
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

func getBoolEnv(envKey string, defaultValue bool) (bool, error) {
	envValue := getTrimmedEnv(envKey)
	if envValue != "" {
		parsedEnv, err := strconv.ParseBool(envValue)
		if err != nil {
			return false, fmt.Errorf("the value of the %s environment is expected to boolean. The value received however is %s", envKey, envValue)
		}
		return parsedEnv, nil
	}

	return defaultValue, nil
}

func getConfigurationProfile(xrayVersion string, jfrogServer *coreconfig.ServerDetails, gitClient vcsclient.VcsClient, gitParams *Git) (configProfile *services.ConfigProfile, repoCloneUrl string, err error) {
	if err = clientutils.ValidateMinimumVersion(clientutils.Xray, xrayVersion, configProfileV3MinXrayVersion); err != nil {
		log.Info(fmt.Sprintf("The utilized Frogbot version requires a higher version of Xray than %s in order to use Config Profile. Please upgrade Xray to version %s and above. Frogbot configurations will be derived from environment variables only.", xrayVersion, configProfileV3MinXrayVersion))
		return
	}
	if repoCloneUrl, err = gitParams.GetRepositoryHttpsCloneUrl(gitClient); err != nil {
		return
	}
	log.Debug(fmt.Sprintf("Searching central configuration associated to repository '%s'", jfrogServer.Url))
	if configProfile, err = xsc.GetConfigProfileByUrl(xrayVersion, jfrogServer, repoCloneUrl); err != nil || configProfile == nil {
		return
	}

	log.Info(fmt.Sprintf("Using Config profile '%s'", configProfile.ProfileName))
	// TODO: Remove this line once autofix logic is added
	configProfile.FrogbotConfig.CreateAutoFixPr = false
	return
}
