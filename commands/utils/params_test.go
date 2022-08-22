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
	_, _, err := GetParamsAndClient()
	assert.EqualError(t, err, "JF_URL or JF_XRAY_URL and JF_ARTIFACTORY_URL environment variables are missing")

	SetEnvAndAssert(t, map[string]string{JFrogUrlEnv: "http://127.0.0.1:8081"})
	_, _, err = GetParamsAndClient()
	assert.EqualError(t, err, "JF_USER and JF_PASSWORD or JF_ACCESS_TOKEN environment variables are missing")
}

func TestExtractParamsFromEnvPlatform(t *testing.T) {
	SetEnvAndAssert(t, map[string]string{
		JFrogUrlEnv:         "http://127.0.0.1:8081",
		JFrogUserEnv:        "admin",
		JFrogPasswordEnv:    "password",
		jfrogWatchesEnv:     "watch-1,watch-2",
		jfrogProjectEnv:     "proj",
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
		jfrogWatchesEnv:        "watch-1,watch-2",
		jfrogProjectEnv:        "proj",
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
		jfrogWatchesEnv:     "watch-1,watch-2",
		jfrogProjectEnv:     "proj",
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
		assert.NoError(t, sanitizeEnv())
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

func TestExtractInstallationCommandFromEnv(t *testing.T) {
	defer func() {
		assert.NoError(t, sanitizeEnv())
	}()

	params := &FrogbotParams{}
	extractGeneralParamsFromEnv(params)
	assert.Empty(t, params.InstallCommandName)
	assert.Empty(t, params.InstallCommandArgs)

	SetEnvAndAssert(t, map[string]string{InstallCommandEnv: "a"})
	params = &FrogbotParams{}
	extractGeneralParamsFromEnv(params)
	assert.Equal(t, "a", params.InstallCommandName)
	assert.Empty(t, params.InstallCommandArgs)

	SetEnvAndAssert(t, map[string]string{InstallCommandEnv: "a b"})
	params = &FrogbotParams{}
	extractGeneralParamsFromEnv(params)
	assert.Equal(t, "a", params.InstallCommandName)
	assert.Equal(t, []string{"b"}, params.InstallCommandArgs)

	SetEnvAndAssert(t, map[string]string{InstallCommandEnv: "a b --flagName=flagValue"})
	params = &FrogbotParams{}
	extractGeneralParamsFromEnv(params)
	assert.Equal(t, "a", params.InstallCommandName)
	assert.Equal(t, []string{"b", "--flagName=flagValue"}, params.InstallCommandArgs)
}

func TestExtractGitParamsFromEnvErrors(t *testing.T) {
	params := &FrogbotParams{}
	defer func() {
		assert.NoError(t, sanitizeEnv())
	}()

	err := extractGitParamsFromEnv(params)
	assert.EqualError(t, err, "JF_GIT_PROVIDER should be one of: 'github', 'gitlab' or 'bitbucketServer'")

	SetEnvAndAssert(t, map[string]string{GitProvider: "github"})
	err = extractGitParamsFromEnv(params)
	assert.EqualError(t, err, "'JF_GIT_OWNER' environment variable is missing")

	SetEnvAndAssert(t, map[string]string{GitRepoOwnerEnv: "jfrog"})
	err = extractGitParamsFromEnv(params)
	assert.EqualError(t, err, "'JF_GIT_REPO' environment variable is missing")

	SetEnvAndAssert(t, map[string]string{GitRepoEnv: "frogit"})
	err = extractGitParamsFromEnv(params)
	assert.EqualError(t, err, "'JF_GIT_TOKEN' environment variable is missing")

	SetEnvAndAssert(t, map[string]string{GitPullRequestIDEnv: "illegal-id", GitTokenEnv: "123456"})
	err = extractGitParamsFromEnv(params)
	_, ok := err.(*strconv.NumError)
	assert.True(t, ok)
}

func extractAndAssertParamsFromEnv(t *testing.T, platformUrl, basicAuth bool) {
	params, _, err := GetParamsAndClient()
	assert.NoError(t, err)
	AssertSanitizedEnv(t)

	configServer := params.Server
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
	assert.Equal(t, "watch-1,watch-2", params.Watches)
	assert.Equal(t, "proj", params.Project)
	assert.Equal(t, vcsutils.GitHub, params.GitProvider)
	assert.Equal(t, "jfrog", params.RepoOwner)
	assert.Equal(t, "frogbot", params.Repo)
	assert.Equal(t, "123456789", params.Token)
	assert.Equal(t, "master", params.BaseBranch)
	assert.Equal(t, 1, params.PullRequestID)
}
