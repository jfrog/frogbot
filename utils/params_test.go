package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/jfrog/frogbot/v2/testdata"
	"github.com/stretchr/testify/require"

	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-client-go/xsc/services"

	"github.com/jfrog/froggit-go/vcsutils"
	"github.com/stretchr/testify/assert"
)

var (
	configProfileFile = filepath.Join("..", "testdata", "configprofile", "configProfileExample.json")
)

func TestExtractParamsFromEnvError(t *testing.T) {
	SetEnvAndAssert(t, map[string]string{
		JFrogUrlEnv:      "",
		JFrogUserEnv:     "",
		JFrogPasswordEnv: "",
		JFrogTokenEnv:    "",
	})
	_, err := extractJFrogCredentialsFromEnvs()
	assert.EqualError(t, err, "JF_URL or JF_XRAY_URL and JF_ARTIFACTORY_URL environment variables are missing")

	SetEnvAndAssert(t, map[string]string{JFrogUrlEnv: "http://127.0.0.1:8081"})
	_, err = extractJFrogCredentialsFromEnvs()
	assert.EqualError(t, err, "JF_USER and JF_PASSWORD or JF_ACCESS_TOKEN environment variables are missing")
}

// Test extraction of env params in ScanPullRequest command
// Pull request ID is not the default, which means we don't have branches related variables defined.
func TestExtractParamsFromEnvPlatformScanPullRequest(t *testing.T) {
	SetEnvAndAssert(t, map[string]string{
		JFrogUrlEnv:         "http://127.0.0.1:8081",
		JFrogUserEnv:        "admin",
		JFrogPasswordEnv:    "password",
		GitProvider:         string(BitbucketServer),
		GitRepoOwnerEnv:     "jfrog",
		GitRepoEnv:          "frogbot",
		GitTokenEnv:         "123456789",
		GitPullRequestIDEnv: "1",
	})
	extractAndAssertParamsFromEnv(t, true, true, ScanPullRequest)
}

// Test extraction in ScanRepository command
// Pull request ID's default is 0, which means we will have branches related variables.
func TestExtractParamsFromEnvPlatformScanRepository(t *testing.T) {
	SetEnvAndAssert(t, map[string]string{
		JFrogUrlEnv:      "http://127.0.0.1:8081",
		JFrogUserEnv:     "admin",
		JFrogPasswordEnv: "password",
		GitProvider:      string(BitbucketServer),
		GitRepoOwnerEnv:  "jfrog",
		GitRepoEnv:       "frogbot",
		GitTokenEnv:      "123456789",
		GitBaseBranchEnv: "dev",
	})
	extractAndAssertParamsFromEnv(t, true, true, ScanRepository)
}

func TestExtractParamsFromEnvArtifactoryXray(t *testing.T) {
	SetEnvAndAssert(t, map[string]string{
		JFrogUrlEnv:            "",
		jfrogArtifactoryUrlEnv: "http://127.0.0.1:8081/artifactory",
		jfrogXrayUrlEnv:        "http://127.0.0.1:8081/xray",
		JFrogUserEnv:           "admin",
		JFrogPasswordEnv:       "password",
		GitProvider:            string(BitbucketServer),
		GitRepoOwnerEnv:        "jfrog",
		GitRepoEnv:             "frogbot",
		GitTokenEnv:            "123456789",
		GitBaseBranchEnv:       "dev",
	})
	extractAndAssertParamsFromEnv(t, false, true, ScanRepository)
}

func TestExtractParamsFromEnvToken(t *testing.T) {
	SetEnvAndAssert(t, map[string]string{
		JFrogUrlEnv:      "http://127.0.0.1:8081",
		JFrogUserEnv:     "",
		JFrogPasswordEnv: "",
		JFrogTokenEnv:    "token",
		GitProvider:      string(BitbucketServer),
		GitRepoOwnerEnv:  "jfrog",
		GitRepoEnv:       "frogbot",
		GitTokenEnv:      "123456789",
		GitBaseBranchEnv: "dev",
	})
	extractAndAssertParamsFromEnv(t, true, false, ScanRepository)
}

func TestExtractVcsProviderFromEnv(t *testing.T) {
	_, err := extractVcsProviderFromEnv()
	assert.Error(t, err)
	defer func() {
		assert.NoError(t, SanitizeEnv())
	}()

	SetEnvAndAssert(t, map[string]string{GitProvider: string(GitHub)})
	vcsProvider, err := extractVcsProviderFromEnv()
	assert.NoError(t, err)
	assert.Equal(t, vcsutils.GitHub, vcsProvider)

	SetEnvAndAssert(t, map[string]string{GitProvider: string(GitLab)})
	vcsProvider, err = extractVcsProviderFromEnv()
	assert.NoError(t, err)
	assert.Equal(t, vcsutils.GitLab, vcsProvider)

	SetEnvAndAssert(t, map[string]string{GitProvider: string(BitbucketServer)})
	vcsProvider, err = extractVcsProviderFromEnv()
	assert.NoError(t, err)
	assert.Equal(t, vcsutils.BitbucketServer, vcsProvider)

	SetEnvAndAssert(t, map[string]string{GitProvider: string(AzureRepos)})
	vcsProvider, err = extractVcsProviderFromEnv()
	assert.NoError(t, err)
	assert.Equal(t, vcsutils.AzureRepos, vcsProvider)
}

func TestExtractClientInfo(t *testing.T) {
	defer func() {
		assert.NoError(t, SanitizeEnv())
	}()

	_, err := extractGitParamsFromEnvs()
	assert.EqualError(t, err, "JF_GIT_PROVIDER should be one of: 'github', 'gitlab', 'bitbucketServer' or 'azureRepos'")

	SetEnvAndAssert(t, map[string]string{GitProvider: "github"})
	_, err = extractGitParamsFromEnvs()
	assert.EqualError(t, err, "'JF_GIT_OWNER' environment variable is missing")

	SetEnvAndAssert(t, map[string]string{GitRepoOwnerEnv: "jfrog"})
	_, err = extractGitParamsFromEnvs()
	assert.EqualError(t, err, "'JF_GIT_TOKEN' environment variable is missing")

	SetEnvAndAssert(t, map[string]string{GitTokenEnv: "token"})
	_, err = extractGitParamsFromEnvs()
	assert.EqualError(t, err, "'JF_GIT_REPO' environment variable is missing")
}

func testExtractAndAssertProjectParams(t *testing.T, project Project) {
	assert.Equal(t, "nuget", project.InstallCommandName)
	assert.Equal(t, []string{"restore"}, project.InstallCommandArgs)
	assert.ElementsMatch(t, []string{"a/b", "b/c"}, project.WorkingDirs)
	assert.Equal(t, "", project.PipRequirementsFile)
}

func extractAndAssertParamsFromEnv(t *testing.T, platformUrl, basicAuth bool, commandName string) {
	server, err := extractJFrogCredentialsFromEnvs()
	assert.NoError(t, err)
	gitParams, err := extractGitParamsFromEnvs()
	assert.NoError(t, err)
	configFile, err := BuildRepository("xrayVersion", "xscVersion", nil, gitParams, server, commandName)
	assert.NoError(t, err)
	err = SanitizeEnv()
	assert.NoError(t, err)
	AssertSanitizedEnv(t)

	configServer := server
	if platformUrl {
		assert.Equal(t, "http://127.0.0.1:8081/", configServer.Url)
	}
	assert.Equal(t, "http://127.0.0.1:8081/artifactory/", configServer.ArtifactoryUrl)
	assert.Equal(t, "http://127.0.0.1:8081/xray/", configServer.XrayUrl)
	if basicAuth {
		assert.Equal(t, "admin", configServer.User)
		assert.Equal(t, "password", configServer.Password)
	} else {
		assert.Equal(t, "token", configServer.AccessToken)
	}
	assert.Equal(t, vcsutils.BitbucketServer, configFile.GitProvider)
	assert.Equal(t, "jfrog", configFile.RepoOwner)
	assert.Equal(t, "frogbot", configFile.RepoName)
	assert.Equal(t, "123456789", configFile.Token)
	// ScanRepository command context
	if commandName == ScanRepository {
		assert.Equal(t, "dev", configFile.Branches[0])
		assert.Equal(t, int64(0), configFile.PullRequestDetails.ID)
	} else {
		// ScanPullRequest context
		assert.Equal(t, int64(1), configFile.PullRequestDetails.ID)
	}
}

func TestExtractInstallationCommandFromEnv(t *testing.T) {
	defer func() {
		assert.NoError(t, SanitizeEnv())
	}()

	project := &Project{}
	err := project.setDefaultsIfNeeded()
	assert.NoError(t, err)
	assert.Empty(t, project.InstallCommandName)
	assert.Empty(t, project.InstallCommandArgs)

	project = &Project{}
	SetEnvAndAssert(t, map[string]string{InstallCommandEnv: "a"})
	err = project.setDefaultsIfNeeded()
	assert.NoError(t, err)
	assert.Equal(t, "a", project.InstallCommandName)
	assert.Empty(t, project.InstallCommandArgs)

	project = &Project{}
	SetEnvAndAssert(t, map[string]string{InstallCommandEnv: "a b"})
	err = project.setDefaultsIfNeeded()
	assert.NoError(t, err)
	assert.Equal(t, "a", project.InstallCommandName)
	assert.Equal(t, []string{"b"}, project.InstallCommandArgs)

	project = &Project{}
	SetEnvAndAssert(t, map[string]string{InstallCommandEnv: "a b --flagName=flagValue"})
	err = project.setDefaultsIfNeeded()
	assert.NoError(t, err)
	assert.Equal(t, "a", project.InstallCommandName)
	assert.Equal(t, []string{"b", "--flagName=flagValue"}, project.InstallCommandArgs)
}

func TestGenerateConfigFromEnv(t *testing.T) {
	SetEnvAndAssert(t, map[string]string{
		JFrogUrlEnv:                 "",
		jfrogArtifactoryUrlEnv:      "http://127.0.0.1:8081/artifactory",
		jfrogXrayUrlEnv:             "http://127.0.0.1:8081/xray",
		JFrogUserEnv:                "admin",
		JFrogPasswordEnv:            "password",
		BranchNameTemplateEnv:       "branch-${BRANCH_NAME_HASH}",
		CommitMessageTemplateEnv:    "commit",
		PullRequestTitleTemplateEnv: "pr-title",
		InstallCommandEnv:           "nuget restore",
		UseWrapperEnv:               "false",
		RequirementsFileEnv:         "requirements.txt",
		WorkingDirectoryEnv:         "a/b",
		jfrogProjectEnv:             "projectKey",
		jfrogWatchesEnv:             "watch-1, watch-2, watch-3",
		DepsRepoEnv:                 "deps-remote",
		MinSeverityEnv:              "medium",
		FixableOnlyEnv:              "true",
		DetectionOnlyEnv:            "true",
		AllowedLicensesEnv:          "MIT, Apache-2.0",
	})
	defer func() {
		assert.NoError(t, SanitizeEnv())
	}()

	gitParams := Git{
		GitProvider: vcsutils.GitHub,
		VcsInfo: vcsclient.VcsInfo{
			APIEndpoint: "https://github.com",
			Token:       "123456789",
		},
		RepoName:           "repoName",
		Branches:           []string{"master"},
		RepoOwner:          "jfrog",
		PullRequestDetails: vcsclient.PullRequestInfo{ID: 17},
	}
	server := config.ServerDetails{
		ArtifactoryUrl: "http://127.0.0.1:8081/artifactory",
		XrayUrl:        "http://127.0.0.1:8081/xray",
		User:           "admin",
		Password:       "password",
	}
	repo, err := BuildRepository("xrayVersion", "xscVersion", nil, &gitParams, &server, ScanRepository)
	assert.NoError(t, err)
	validateBuildRepo(t, &repo, &gitParams, &server, ScanRepository)

	repo, err = BuildRepository("xrayVersion", "xscVersion", nil, &gitParams, &server, ScanPullRequest)
	assert.NoError(t, err)
	validateBuildRepo(t, &repo, &gitParams, &server, ScanPullRequest)
}

func validateBuildRepo(t *testing.T, repo *Repository, gitParams *Git, server *config.ServerDetails, commandName string) {
	assert.Equal(t, "repoName", repo.RepoName)
	assert.ElementsMatch(t, repo.Watches, []string{"watch-1", "watch-2", "watch-3"})
	assert.Equal(t, "Medium", repo.MinSeverity)
	assert.Equal(t, true, repo.FixableOnly)
	assert.Equal(t, true, repo.AddPrCommentOnSuccess)
	assert.Equal(t, true, repo.DetectionOnly)
	assert.ElementsMatch(t, []string{"MIT", "Apache-2.0"}, repo.AllowedLicenses)
	assert.Equal(t, gitParams.RepoOwner, repo.RepoOwner)
	assert.Equal(t, gitParams.Token, repo.Token)
	assert.Equal(t, gitParams.APIEndpoint, repo.APIEndpoint)
	assert.Equal(t, gitParams.GitProvider, repo.GitProvider)

	assert.Equal(t, server.ArtifactoryUrl, repo.Server.ArtifactoryUrl)
	assert.Equal(t, server.XrayUrl, repo.Server.XrayUrl)
	assert.Equal(t, server.User, repo.Server.User)
	assert.Equal(t, server.Password, repo.Server.Password)

	if commandName == ScanRepository {
		assert.ElementsMatch(t, gitParams.Branches, repo.Branches)
		assert.NotEmpty(t, repo.BranchNameTemplate)
		assert.NotEmpty(t, repo.CommitMessageTemplate)
		assert.NotEmpty(t, repo.PullRequestTitleTemplate)
	}

	if commandName == ScanPullRequest {
		assert.NotZero(t, repo.PullRequestDetails.ID)
		assert.Empty(t, repo.PullRequestCommentTitle)
	}

	project := repo.Projects[0]
	assert.Equal(t, []string{"a/b"}, project.WorkingDirs)
	assert.False(t, *project.UseWrapper)
	assert.Equal(t, "requirements.txt", project.PipRequirementsFile)
	assert.Equal(t, "nuget", project.InstallCommandName)
	assert.Equal(t, []string{"restore"}, project.InstallCommandArgs)
	assert.Equal(t, "deps-remote", project.DepsRepo)
}

func TestExtractProjectParamsFromEnv(t *testing.T) {
	project := &Project{}
	defer func() {
		assert.NoError(t, SanitizeEnv())
	}()

	// Test default values
	err := project.setDefaultsIfNeeded()
	assert.NoError(t, err)
	assert.True(t, *project.UseWrapper)
	assert.Equal(t, []string{RootDir}, project.WorkingDirs)
	assert.Equal(t, "", project.PipRequirementsFile)
	assert.Equal(t, "", project.InstallCommandName)
	assert.Equal(t, []string(nil), project.InstallCommandArgs)
	assert.True(t, project.IsRecursiveScan)

	// Test value extraction
	SetEnvAndAssert(t, map[string]string{
		WorkingDirectoryEnv: "b/c",
		RequirementsFileEnv: "r.txt",
		UseWrapperEnv:       "false",
		InstallCommandEnv:   "nuget restore",
		DepsRepoEnv:         "repository",
	})

	project = &Project{}
	err = project.setDefaultsIfNeeded()
	assert.NoError(t, err)
	assert.Equal(t, []string{"b/c"}, project.WorkingDirs)
	assert.Equal(t, "r.txt", project.PipRequirementsFile)
	assert.False(t, *project.UseWrapper)
	assert.Equal(t, "nuget", project.InstallCommandName)
	assert.Equal(t, []string{"restore"}, project.InstallCommandArgs)
	assert.Equal(t, "repository", project.DepsRepo)
	assert.False(t, project.IsRecursiveScan)
}

func TestVerifyValidApiEndpoint(t *testing.T) {
	testsCases := []struct {
		endpointUrl   string
		expectedError bool
	}{
		{endpointUrl: "https://git.company.info"},
		{endpointUrl: "http://git.company.info"},
		{endpointUrl: "justAString", expectedError: true},
		{endpointUrl: ""},
		{endpointUrl: "git.company.info", expectedError: true},
	}
	for _, test := range testsCases {
		t.Run(test.endpointUrl, func(t *testing.T) {
			err := verifyValidApiEndpoint(test.endpointUrl)
			if test.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestGetConfigProfileIfExistsAndValid(t *testing.T) {
	testcases := []struct {
		name            string
		xrayVersion     string
		failureExpected bool
		profileWithRepo bool
		mockRepoInfoErr bool
	}{
		{
			name:            "Deprecated Server - Xray version is too low",
			xrayVersion:     "3.110.0",
			failureExpected: true,
		},
		{
			name:            "Profile by URL - Valid ConfigProfile",
			xrayVersion:     services.ConfigProfileNewSchemaMinXrayVersion,
			failureExpected: false,
			profileWithRepo: true,
		},
		{
			name:            "Profile by URL - Failed fetching repository info",
			xrayVersion:     services.ConfigProfileNewSchemaMinXrayVersion,
			failureExpected: true,
			profileWithRepo: true,
			mockRepoInfoErr: true,
		},
	}

	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			mockServer, serverDetails := CreateXscMockServerForConfigProfile(t, testcase.xrayVersion)
			defer mockServer.Close()

			var mockVcsClient *testdata.MockVcsClient
			var mockGitParams *Git
			if testcase.profileWithRepo {
				mockVcsClient = createMockVcsClient(t, "myUser", "my-repo", testcase.mockRepoInfoErr)
				mockGitParams = &Git{
					RepoOwner: "myUser",
					RepoName:  "my-repo",
				}
			}

			configProfile, repoCloneUrl, err := getConfigProfileIfExistsAndValid(testcase.xrayVersion, serverDetails, mockVcsClient, mockGitParams, "")

			if testcase.failureExpected {
				assert.Error(t, err)
				return
			}

			require.NotNil(t, configProfile)
			assert.NoError(t, err)
			if testcase.profileWithRepo {
				assert.NotEmpty(t, repoCloneUrl)
			}
			configProfileContentForComparison, err := os.ReadFile(configProfileFile)
			assert.NoError(t, err)
			assert.NotEmpty(t, configProfileContentForComparison)
			var configProfileFromFile services.ConfigProfile
			err = json.Unmarshal(configProfileContentForComparison, &configProfileFromFile)
			assert.NoError(t, err)
			assert.Equal(t, configProfileFromFile, *configProfile)
		})
	}
}

func createMockVcsClient(t *testing.T, repoOwner, repoName string, withError bool) *testdata.MockVcsClient {
	mockVcsClient := testdata.NewMockVcsClient(gomock.NewController(t))
	if withError {
		mockVcsClient.EXPECT().GetRepositoryInfo(context.Background(), repoOwner, repoName).Return(vcsclient.RepositoryInfo{}, fmt.Errorf("failed to fetch repository info"))
	} else {
		mockVcsClient.EXPECT().GetRepositoryInfo(context.Background(), repoOwner, repoName).Return(
			vcsclient.RepositoryInfo{
				CloneInfo: vcsclient.CloneInfo{
					HTTP: "https://github.com/myUser/my-repo.git",
					SSH:  "git@github.com:myUser/my-repo.git",
				},
				RepositoryVisibility: 0,
			}, nil,
		)
	}
	return mockVcsClient
}
