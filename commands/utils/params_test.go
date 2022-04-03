package utils

import (
	"fmt"
	"os"
	"strconv"
	"testing"

	"github.com/jfrog/froggit-go/vcsutils"
	"github.com/stretchr/testify/assert"
)

func init() {
	cleanUpEnv()
}

func TestExtractParamsFromEnvError(t *testing.T) {
	defer cleanUpEnv()
	_, _, err := GetParamsAndClient()
	assert.EqualError(t, err, "JF_URL or JF_XRAY_URL and JF_ARTIFACTORY_URL environment variables are missing")

	setEnvAndAssert(t, jfrogUrlEnv, "http://127.0.0.1:8081")
	_, _, err = GetParamsAndClient()
	assert.EqualError(t, err, "JF_USER and JF_PASSWORD or JF_ACCESS_TOKEN environment variables are missing")
}

func TestExtractParamsFromEnvPlatform(t *testing.T) {
	defer cleanUpEnv()
	setEnvAndAssert(t, jfrogUrlEnv, "http://127.0.0.1:8081")
	setEnvAndAssert(t, jfrogUserEnv, "admin")
	setEnvAndAssert(t, jfrogPasswordEnv, "password")
	setEnvAndAssert(t, jfrogWatchesEnv, "watch-1,watch-2")
	setEnvAndAssert(t, jfrogProjectEnv, "proj")
	setEnvAndAssert(t, gitProvider, "github")
	setEnvAndAssert(t, gitRepoOwnerEnv, "jfrog")
	setEnvAndAssert(t, gitRepoEnv, "frogbot")
	setEnvAndAssert(t, gitTokenEnv, "123456789")
	setEnvAndAssert(t, gitBaseBranchEnv, "master")
	setEnvAndAssert(t, gitPullRequestIDEnv, "1")

	extractAndAssertParamsFromEnv(t, true, true)
}

func TestExtractParamsFromEnvArtifactoryXray(t *testing.T) {
	defer cleanUpEnv()
	setEnvAndAssert(t, jfrogArtifactoryUrlEnv, "http://127.0.0.1:8081/artifactory")
	setEnvAndAssert(t, jfrogXrayUrlEnv, "http://127.0.0.1:8081/xray")
	setEnvAndAssert(t, jfrogUserEnv, "admin")
	setEnvAndAssert(t, jfrogPasswordEnv, "password")
	setEnvAndAssert(t, jfrogWatchesEnv, "watch-1,watch-2")
	setEnvAndAssert(t, jfrogProjectEnv, "proj")
	setEnvAndAssert(t, gitProvider, "github")
	setEnvAndAssert(t, gitRepoOwnerEnv, "jfrog")
	setEnvAndAssert(t, gitRepoEnv, "frogbot")
	setEnvAndAssert(t, gitTokenEnv, "123456789")
	setEnvAndAssert(t, gitBaseBranchEnv, "master")
	setEnvAndAssert(t, gitPullRequestIDEnv, "1")

	extractAndAssertParamsFromEnv(t, false, true)
}

func TestExtractParamsFromEnvToken(t *testing.T) {
	defer cleanUpEnv()
	setEnvAndAssert(t, jfrogUrlEnv, "http://127.0.0.1:8081")
	setEnvAndAssert(t, jfrogTokenEnv, "token")
	setEnvAndAssert(t, jfrogWatchesEnv, "watch-1,watch-2")
	setEnvAndAssert(t, jfrogProjectEnv, "proj")
	setEnvAndAssert(t, gitProvider, "github")
	setEnvAndAssert(t, gitRepoOwnerEnv, "jfrog")
	setEnvAndAssert(t, gitRepoEnv, "frogbot")
	setEnvAndAssert(t, gitTokenEnv, "123456789")
	setEnvAndAssert(t, gitBaseBranchEnv, "master")
	setEnvAndAssert(t, gitPullRequestIDEnv, "1")

	extractAndAssertParamsFromEnv(t, true, false)
}

func TestExtractVcsProviderFromEnv(t *testing.T) {
	defer cleanUpEnv()

	_, err := extractVcsProviderFromEnv()
	assert.Error(t, err)

	setEnvAndAssert(t, gitProvider, string(gitHub))
	vcsProvider, err := extractVcsProviderFromEnv()
	assert.NoError(t, err)
	assert.Equal(t, vcsutils.GitHub, vcsProvider)

	setEnvAndAssert(t, gitProvider, string(gitLab))
	vcsProvider, err = extractVcsProviderFromEnv()
	assert.NoError(t, err)
	assert.Equal(t, vcsutils.GitLab, vcsProvider)
}

func TestExtractInstallationCommandFromEnv(t *testing.T) {
	defer cleanUpEnv()

	params := &FrogbotParams{}
	extractInstallationCommandFromEnv(params)
	assert.Empty(t, params.InstallCommandName)
	assert.Empty(t, params.InstallCommandArgs)

	setEnvAndAssert(t, installCommandEnv, "a")
	params = &FrogbotParams{}
	extractInstallationCommandFromEnv(params)
	assert.Equal(t, "a", params.InstallCommandName)
	assert.Empty(t, params.InstallCommandArgs)

	setEnvAndAssert(t, installCommandEnv, "a b")
	params = &FrogbotParams{}
	extractInstallationCommandFromEnv(params)
	assert.Equal(t, "a", params.InstallCommandName)
	assert.Equal(t, []string{"b"}, params.InstallCommandArgs)

	setEnvAndAssert(t, installCommandEnv, "a b --flagName=flagValue")
	params = &FrogbotParams{}
	extractInstallationCommandFromEnv(params)
	assert.Equal(t, "a", params.InstallCommandName)
	assert.Equal(t, []string{"b", "--flagName=flagValue"}, params.InstallCommandArgs)
}

func TestExtractGitParamsFromEnvErrors(t *testing.T) {
	defer cleanUpEnv()
	params := &FrogbotParams{}

	err := extractGitParamsFromEnv(params)
	assert.EqualError(t, err, "JF_GIT_PROVIDER should be one of: 'github' or 'gitlab'")

	setEnvAndAssert(t, gitProvider, "github")
	err = extractGitParamsFromEnv(params)
	assert.EqualError(t, err, "'JF_GIT_OWNER' environment variable is missing")

	setEnvAndAssert(t, gitRepoOwnerEnv, "jfrog")
	err = extractGitParamsFromEnv(params)
	assert.EqualError(t, err, "'JF_GIT_REPO' environment variable is missing")

	setEnvAndAssert(t, gitRepoEnv, "frogit")
	err = extractGitParamsFromEnv(params)
	assert.EqualError(t, err, "'JF_GIT_TOKEN' environment variable is missing")

	setEnvAndAssert(t, gitTokenEnv, "123456")
	err = extractGitParamsFromEnv(params)
	assert.EqualError(t, err, "'JF_GIT_BASE_BRANCH' environment variable is missing")

	setEnvAndAssert(t, gitBaseBranchEnv, "master")
	err = extractGitParamsFromEnv(params)
	assert.EqualError(t, err, "'JF_GIT_PULL_REQUEST_ID' environment variable is missing")

	setEnvAndAssert(t, gitPullRequestIDEnv, "illegal-id")
	err = extractGitParamsFromEnv(params)
	_, ok := err.(*strconv.NumError)
	assert.True(t, ok)
}

func setEnvAndAssert(t *testing.T, key, value string) {
	assert.NoError(t, os.Setenv(key, value))
}

func extractAndAssertParamsFromEnv(t *testing.T, platformUrl, basicAuth bool) {
	params, _, err := GetParamsAndClient()
	assert.NoError(t, err)

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

func cleanUpEnv() {
	for _, key := range []string{jfrogUrlEnv, jfrogArtifactoryUrlEnv, jfrogXrayUrlEnv, jfrogUserEnv, installCommandEnv,
		jfrogPasswordEnv, jfrogTokenEnv, jfrogWatchesEnv, jfrogProjectEnv, gitProvider, gitRepoOwnerEnv, gitRepoEnv,
		gitTokenEnv, gitBaseBranchEnv, gitPullRequestIDEnv} {
		if err := os.Unsetenv(key); err != nil {
			fmt.Println("couldn't unset env " + key)
		}
	}
}
