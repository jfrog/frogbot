package utils

import (
	"strconv"
	"testing"

	"github.com/jfrog/froggit-go/vcsutils"
	"github.com/stretchr/testify/assert"
)

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

	SetEnvAndAssert(t, map[string]string{GitPullRequestIDEnv: "illegal-id", GitTokenEnv: "123456"})
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
	config, _, _, err := GetParamsAndClient()
	assert.NoError(t, err)
	for _, repo := range config {
		assert.Equal(t, true, repo.IncludeAllVulnerabilities)
		assert.Equal(t, true, repo.FailOnSecurityIssues)
		assert.Equal(t, "proj", repo.ProjectKey)
		assert.ElementsMatch(t, []string{"watch-2", "watch-1"}, repo.Watches)
		for _, project := range repo.Projects {
			testExtractAndAssertProjectParams(t, project)
		}
	}
}

func testExtractAndAssertProjectParams(t *testing.T, project Project) {
	assert.Equal(t, "npm", project.InstallCommandName)
	assert.Equal(t, []string{"i"}, project.InstallCommandArgs)
	assert.ElementsMatch(t, []string{"a/b", "b/c"}, project.WorkingDir)
	assert.Equal(t, "", project.RequirementsFile)
}

func extractAndAssertParamsFromEnv(t *testing.T, platformUrl, basicAuth bool) {
	config, server, _, err := GetParamsAndClient()
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
	for _, configParams := range config {
		assert.Equal(t, vcsutils.GitHub, configParams.GitProvider)
		assert.Equal(t, "jfrog", configParams.RepoOwner)
		assert.Equal(t, "frogbot", configParams.RepoName)
		assert.Equal(t, "123456789", configParams.Token)
		assert.Equal(t, "master", configParams.BaseBranch)
		assert.Equal(t, 1, configParams.PullRequestID)
	}
}

func TestEmptyConfigFilePath(t *testing.T) {
	_, err := OpenAndParseConfigFile("")
	assert.Error(t, err)
	assert.Equal(t, emptyConfigFilePathErr, err.Error())
}
