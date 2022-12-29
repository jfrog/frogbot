package utils

import (
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/jfrog/froggit-go/vcsutils"
	"github.com/stretchr/testify/assert"
)

var configParamsTestFile = filepath.Join("..", "testdata", "config", "frogbot-config-test-params.yml")

func TestExtractParamsFromEnvError(t *testing.T) {
	SetEnvAndAssert(t, map[string]string{
		JFrogUrlEnv:      "",
		JFrogUserEnv:     "",
		JFrogPasswordEnv: "",
		JFrogTokenEnv:    "",
	})
	_, err := extractJFrogParamsFromEnv()
	assert.EqualError(t, err, "JF_URL or JF_XRAY_URL and JF_ARTIFACTORY_URL environment variables are missing")

	SetEnvAndAssert(t, map[string]string{JFrogUrlEnv: "http://127.0.0.1:8081"})
	_, err = extractJFrogParamsFromEnv()
	assert.EqualError(t, err, "JF_USER and JF_PASSWORD or JF_ACCESS_TOKEN environment variables are missing")
}

func TestExtractParamsFromEnvPlatform(t *testing.T) {
	SetEnvAndAssert(t, map[string]string{
		JFrogUrlEnv:         "http://127.0.0.1:8081",
		JFrogUserEnv:        "admin",
		JFrogPasswordEnv:    "password",
		GitProvider:         string(GitHub),
		GitRepoOwnerEnv:     "jfrog",
		GitRepoEnv:          "frogbot",
		GitTokenEnv:         "123456789",
		GitBaseBranchEnv:    "master",
		GitPullRequestIDEnv: "1",
	})
	extractAndAssertParamsFromEnv(t, true, true)
}

func TestExtractParamsFromEnvArtifactoryXray(t *testing.T) {
	SetEnvAndAssert(t, map[string]string{
		JFrogUrlEnv:            "",
		jfrogArtifactoryUrlEnv: "http://127.0.0.1:8081/artifactory",
		jfrogXrayUrlEnv:        "http://127.0.0.1:8081/xray",
		JFrogUserEnv:           "admin",
		JFrogPasswordEnv:       "password",
		GitProvider:            string(GitHub),
		GitRepoOwnerEnv:        "jfrog",
		GitRepoEnv:             "frogbot",
		GitTokenEnv:            "123456789",
		GitBaseBranchEnv:       "master",
		GitPullRequestIDEnv:    "1",
	})
	extractAndAssertParamsFromEnv(t, false, true)
}

func TestExtractParamsFromEnvToken(t *testing.T) {
	SetEnvAndAssert(t, map[string]string{
		JFrogUrlEnv:         "http://127.0.0.1:8081",
		JFrogUserEnv:        "",
		JFrogPasswordEnv:    "",
		JFrogTokenEnv:       "token",
		GitProvider:         string(GitHub),
		GitRepoOwnerEnv:     "jfrog",
		GitRepoEnv:          "frogbot",
		GitTokenEnv:         "123456789",
		GitBaseBranchEnv:    "master",
		GitPullRequestIDEnv: "1",
	})
	extractAndAssertParamsFromEnv(t, true, false)
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

func TestExtractGitParamsFromEnvErrors(t *testing.T) {
	defer func() {
		assert.NoError(t, SanitizeEnv())
	}()

	_, err := extractGitParamsFromEnv()
	assert.EqualError(t, err, "JF_GIT_PROVIDER should be one of: 'github', 'gitlab' or 'bitbucketServer'")

	SetEnvAndAssert(t, map[string]string{GitProvider: "github"})
	_, err = extractGitParamsFromEnv()
	assert.EqualError(t, err, "'JF_GIT_OWNER' environment variable is missing")

	SetEnvAndAssert(t, map[string]string{GitRepoOwnerEnv: "jfrog"})
	_, err = extractGitParamsFromEnv()
	assert.EqualError(t, err, "'JF_GIT_TOKEN' environment variable is missing")

	SetEnvAndAssert(t, map[string]string{GitPullRequestIDEnv: "illegal-id", GitTokenEnv: "123456", GitRepoEnv: "JfrogRepo"})
	_, err = extractGitParamsFromEnv()
	_, ok := err.(*strconv.NumError)
	assert.True(t, ok)
}

func TestExtractAndAssertRepoParams(t *testing.T) {
	SetEnvAndAssert(t, map[string]string{
		JFrogUrlEnv:         "http://127.0.0.1:8081",
		JFrogUserEnv:        "",
		JFrogPasswordEnv:    "",
		JFrogTokenEnv:       "token",
		GitProvider:         string(GitHub),
		GitRepoOwnerEnv:     "jfrog",
		GitRepoEnv:          "frogbot",
		GitTokenEnv:         "123456789",
		GitBaseBranchEnv:    "master",
		GitPullRequestIDEnv: "1",
	})
	defer func() {
		assert.NoError(t, SanitizeEnv())
	}()
	configFile, err := ReadConfig(configParamsTestFile)
	assert.NoError(t, err)
	for _, repo := range *configFile {
		for projectI, project := range repo.Projects {
			SetProjectInstallCommand(project.InstallCommand, &repo.Projects[projectI])
		}
		assert.Equal(t, true, repo.IncludeAllVulnerabilities)
		assert.Equal(t, true, *repo.FailOnSecurityIssues)
		assert.Equal(t, "proj", repo.JFrogProjectKey)
		assert.ElementsMatch(t, []string{"watch-2", "watch-1"}, repo.Watches)
		for _, project := range repo.Projects {
			testExtractAndAssertProjectParams(t, project)
		}
	}
}

func testExtractAndAssertProjectParams(t *testing.T, project Project) {
	assert.Equal(t, "npm", project.InstallCommandName)
	assert.Equal(t, []string{"i"}, project.InstallCommandArgs)
	assert.ElementsMatch(t, []string{"a/b", "b/c"}, project.WorkingDirs)
	assert.Equal(t, "", project.PipRequirementsFile)
}

func extractAndAssertParamsFromEnv(t *testing.T, platformUrl, basicAuth bool) {
	configFile, server, _, err := GetParamsAndClient()
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
	for _, configParams := range configFile {
		assert.Equal(t, vcsutils.GitHub, configParams.GitProvider)
		assert.Equal(t, "jfrog", configParams.RepoOwner)
		assert.Equal(t, "frogbot", configParams.RepoName)
		assert.Equal(t, "123456789", configParams.Token)
		assert.Equal(t, "master", configParams.Branches[0])
		assert.Equal(t, 1, configParams.PullRequestID)
	}
}

func TestExtractInstallationCommandFromEnv(t *testing.T) {
	defer func() {
		assert.NoError(t, SanitizeEnv())
	}()

	params := &Project{}
	err := extractProjectParamsFromEnv(params)
	assert.NoError(t, err)
	assert.Empty(t, params.InstallCommandName)
	assert.Empty(t, params.InstallCommandArgs)

	SetEnvAndAssert(t, map[string]string{InstallCommandEnv: "a"})
	params = &Project{}
	err = extractProjectParamsFromEnv(params)
	assert.NoError(t, err)
	assert.Equal(t, "a", params.InstallCommandName)
	assert.Empty(t, params.InstallCommandArgs)

	SetEnvAndAssert(t, map[string]string{InstallCommandEnv: "a b"})
	params = &Project{}
	err = extractProjectParamsFromEnv(params)
	assert.NoError(t, err)
	assert.Equal(t, "a", params.InstallCommandName)
	assert.Equal(t, []string{"b"}, params.InstallCommandArgs)

	SetEnvAndAssert(t, map[string]string{InstallCommandEnv: "a b --flagName=flagValue"})
	params = &Project{}
	err = extractProjectParamsFromEnv(params)
	assert.NoError(t, err)
	assert.Equal(t, "a", params.InstallCommandName)
	assert.Equal(t, []string{"b", "--flagName=flagValue"}, params.InstallCommandArgs)
}

func TestGenerateConfigAggregatorFromEnv(t *testing.T) {
	SetEnvAndAssert(t, map[string]string{
		JFrogUrlEnv:                  "",
		jfrogArtifactoryUrlEnv:       "http://127.0.0.1:8081/artifactory",
		jfrogXrayUrlEnv:              "http://127.0.0.1:8081/xray",
		JFrogUserEnv:                 "admin",
		JFrogPasswordEnv:             "password",
		InstallCommandEnv:            "npm i",
		UseWrapperEnv:                "false",
		RequirementsFileEnv:          "requirements.txt",
		WorkingDirectoryEnv:          "a/b",
		jfrogProjectEnv:              "projectKey",
		jfrogWatchesEnv:              "watch-1, watch-2, watch-3",
		IncludeAllVulnerabilitiesEnv: "true",
		FailOnSecurityIssuesEnv:      "false",
	})
	defer func() {
		assert.NoError(t, SanitizeEnv())
	}()

	gitParams := Git{
		GitProvider:   vcsutils.GitHub,
		RepoOwner:     "jfrog",
		Token:         "123456789",
		RepoName:      "repoName",
		Branches:      []string{"master"},
		ApiEndpoint:   "endpoint.com",
		PullRequestID: 1,
	}
	server := config.ServerDetails{
		ArtifactoryUrl: "http://127.0.0.1:8081/artifactory",
		XrayUrl:        "http://127.0.0.1:8081/xray",
		User:           "admin",
		Password:       "password",
	}
	configAggregator, err := generateConfigAggregatorFromEnv(&gitParams, &server)
	assert.NoError(t, err)
	repo := (*configAggregator)[0]
	assert.Equal(t, "repoName", repo.RepoName)
	assert.ElementsMatch(t, repo.Watches, []string{"watch-1", "watch-2", "watch-3"})
	assert.Equal(t, false, *repo.FailOnSecurityIssues)
	assert.Equal(t, gitParams.RepoOwner, repo.RepoOwner)
	assert.Equal(t, gitParams.Token, repo.Token)
	assert.Equal(t, gitParams.ApiEndpoint, repo.ApiEndpoint)
	assert.ElementsMatch(t, gitParams.Branches, repo.Branches)
	assert.Equal(t, gitParams.PullRequestID, repo.PullRequestID)
	assert.Equal(t, gitParams.GitProvider, repo.GitProvider)
	assert.Equal(t, server.ArtifactoryUrl, repo.Server.ArtifactoryUrl)
	assert.Equal(t, server.XrayUrl, repo.Server.XrayUrl)
	assert.Equal(t, server.User, repo.Server.User)
	assert.Equal(t, server.Password, repo.Server.Password)

	project := repo.Projects[0]
	assert.Equal(t, []string{"a/b"}, project.WorkingDirs)
	assert.False(t, project.UseWrapper)
	assert.Equal(t, "requirements.txt", project.PipRequirementsFile)
	assert.Equal(t, "npm", project.InstallCommandName)
	assert.Equal(t, []string{"i"}, project.InstallCommandArgs)
}

func TestExtractProjectParamsFromEnv(t *testing.T) {
	params := Project{}
	defer func() {
		assert.NoError(t, SanitizeEnv())
	}()

	// Test default values
	err := extractProjectParamsFromEnv(&params)
	assert.NoError(t, err)
	assert.True(t, params.UseWrapper)
	assert.Equal(t, []string{""}, params.WorkingDirs)
	assert.Equal(t, "", params.PipRequirementsFile)
	assert.Equal(t, "", params.InstallCommandName)
	assert.Equal(t, []string(nil), params.InstallCommandArgs)

	// Test value extraction
	SetEnvAndAssert(t, map[string]string{WorkingDirectoryEnv: "b/c", RequirementsFileEnv: "r.txt", UseWrapperEnv: "false", InstallCommandEnv: "nuget restore"})
	err = extractProjectParamsFromEnv(&params)
	assert.NoError(t, err)
	assert.Equal(t, []string{"b/c"}, params.WorkingDirs)
	assert.Equal(t, "r.txt", params.PipRequirementsFile)
	assert.False(t, params.UseWrapper)
	assert.Equal(t, "nuget", params.InstallCommandName)
	assert.Equal(t, []string{"restore"}, params.InstallCommandArgs)
}
