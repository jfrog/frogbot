package utils

import (
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"os"
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
		GitProvider:         string(BitbucketServer),
		GitRepoOwnerEnv:     "jfrog",
		GitRepoEnv:          "frogbot",
		GitTokenEnv:         "123456789",
		GitBaseBranchEnv:    "dev",
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
		GitProvider:            string(BitbucketServer),
		GitRepoOwnerEnv:        "jfrog",
		GitRepoEnv:             "frogbot",
		GitTokenEnv:            "123456789",
		GitBaseBranchEnv:       "dev",
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
		GitProvider:         string(BitbucketServer),
		GitRepoOwnerEnv:     "jfrog",
		GitRepoEnv:          "frogbot",
		GitTokenEnv:         "123456789",
		GitBaseBranchEnv:    "dev",
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
		JFrogUrlEnv:          "http://127.0.0.1:8081",
		JFrogUserEnv:         "",
		JFrogPasswordEnv:     "",
		JFrogTokenEnv:        "token",
		GitProvider:          string(GitHub),
		GitRepoOwnerEnv:      "jfrog",
		GitRepoEnv:           "frogbot",
		GitTokenEnv:          "123456789",
		GitBaseBranchEnv:     "dev",
		GitPullRequestIDEnv:  "1",
		GitAggregateFixesEnv: "true",
		MinSeverityEnv:       "high",
		FixableOnlyEnv:       "true",
	})
	defer func() {
		assert.NoError(t, SanitizeEnv())
	}()
	server, gitParams, err := extractEnvParams()
	assert.NoError(t, err)
	configFileContent, err := ReadConfigFromFileSystem(configParamsTestFile)
	assert.NoError(t, err)
	configAggregator, err := NewConfigAggregatorFromFile(configFileContent, gitParams, server, "")
	assert.NoError(t, err)
	for _, repo := range configAggregator {
		for projectI, project := range repo.Projects {
			setProjectInstallCommand(project.InstallCommand, &repo.Projects[projectI])
		}
		assert.Equal(t, true, repo.IncludeAllVulnerabilities)
		assert.Equal(t, true, *repo.FailOnSecurityIssues)
		assert.Equal(t, "proj", repo.JFrogProjectKey)
		templates, err := loadCustomTemplates(repo.CommitMessageTemplate, repo.BranchNameTemplate, repo.PullRequestTitleTemplate)
		assert.NoError(t, err)
		assert.Equal(t, "myPullRequests", templates.pullRequestTitleTemplate)
		assert.Equal(t, "custom commit title", templates.commitMessageTemplate)
		assert.Equal(t, "this is my branch ${BRANCH_NAME_HASH}", templates.branchNameTemplate)
		assert.Equal(t, "High", repo.MinSeverity)
		assert.True(t, repo.FixableOnly)
		assert.Equal(t, true, repo.AggregateFixes)

		assert.ElementsMatch(t, []string{"watch-2", "watch-1"}, repo.Watches)
		for _, project := range repo.Projects {
			testExtractAndAssertProjectParams(t, project)
		}
	}
}

func testExtractAndAssertProjectParams(t *testing.T, project Project) {
	assert.Equal(t, "nuget", project.InstallCommandName)
	assert.Equal(t, []string{"restore"}, project.InstallCommandArgs)
	assert.ElementsMatch(t, []string{"a/b", "b/c"}, project.WorkingDirs)
	assert.Equal(t, "", project.PipRequirementsFile)
}

func extractAndAssertParamsFromEnv(t *testing.T, platformUrl, basicAuth bool) {
	server, gitParams, err := extractEnvParams()
	assert.NoError(t, err)
	configFile, err := newConfigAggregatorFromEnv(gitParams, server, "")
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
	for _, configParams := range configFile {
		assert.Equal(t, vcsutils.BitbucketServer, configParams.GitProvider)
		assert.Equal(t, "jfrog", configParams.RepoOwner)
		assert.Equal(t, "frogbot", configParams.RepoName)
		assert.Equal(t, "123456789", configParams.Token)
		assert.Equal(t, "dev", configParams.Branches[0])
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
		BranchNameTemplateEnv:        "branch",
		CommitMessageTemplateEnv:     "commit",
		PullRequestTitleTemplateEnv:  "pr-title",
		InstallCommandEnv:            "nuget restore",
		UseWrapperEnv:                "false",
		RequirementsFileEnv:          "requirements.txt",
		WorkingDirectoryEnv:          "a/b",
		jfrogProjectEnv:              "projectKey",
		jfrogWatchesEnv:              "watch-1, watch-2, watch-3",
		DepsRepoEnv:                  "deps-remote",
		IncludeAllVulnerabilitiesEnv: "true",
		FailOnSecurityIssuesEnv:      "false",
		MinSeverityEnv:               "medium",
		FixableOnlyEnv:               "true",
	})
	defer func() {
		assert.NoError(t, SanitizeEnv())
	}()

	gitParams := Git{
		GitProvider:              vcsutils.GitHub,
		RepoOwner:                "jfrog",
		Token:                    "123456789",
		RepoName:                 "repoName",
		Branches:                 []string{"master"},
		ApiEndpoint:              "endpoint.com",
		PullRequestID:            1,
		BranchNameTemplate:       "branch",
		CommitMessageTemplate:    "commit",
		PullRequestTitleTemplate: "pr-title",
	}
	server := config.ServerDetails{
		ArtifactoryUrl: "http://127.0.0.1:8081/artifactory",
		XrayUrl:        "http://127.0.0.1:8081/xray",
		User:           "admin",
		Password:       "password",
	}
	configAggregator, err := newConfigAggregatorFromEnv(&gitParams, &server, "releases-remote")
	assert.NoError(t, err)
	repo := configAggregator[0]
	assert.Equal(t, "repoName", repo.RepoName)
	assert.Equal(t, "releases-remote", repo.JfrogReleasesRepo)
	assert.ElementsMatch(t, repo.Watches, []string{"watch-1", "watch-2", "watch-3"})
	assert.Equal(t, false, *repo.FailOnSecurityIssues)
	assert.Equal(t, "Medium", repo.MinSeverity)
	assert.Equal(t, true, repo.FixableOnly)
	assert.Equal(t, gitParams.RepoOwner, repo.RepoOwner)
	assert.Equal(t, gitParams.Token, repo.Token)
	assert.Equal(t, gitParams.ApiEndpoint, repo.ApiEndpoint)
	assert.ElementsMatch(t, gitParams.Branches, repo.Branches)
	assert.Equal(t, gitParams.PullRequestID, repo.PullRequestID)
	assert.Equal(t, gitParams.GitProvider, repo.GitProvider)
	assert.Equal(t, gitParams.BranchNameTemplate, repo.BranchNameTemplate)
	assert.Equal(t, gitParams.CommitMessageTemplate, repo.CommitMessageTemplate)
	assert.Equal(t, gitParams.PullRequestTitleTemplate, repo.PullRequestTitleTemplate)
	assert.Equal(t, server.ArtifactoryUrl, repo.Server.ArtifactoryUrl)
	assert.Equal(t, server.XrayUrl, repo.Server.XrayUrl)
	assert.Equal(t, server.User, repo.Server.User)
	assert.Equal(t, server.Password, repo.Server.Password)

	project := repo.Projects[0]
	assert.Equal(t, []string{"a/b"}, project.WorkingDirs)
	assert.False(t, *project.UseWrapper)
	assert.Equal(t, "requirements.txt", project.PipRequirementsFile)
	assert.Equal(t, "nuget", project.InstallCommandName)
	assert.Equal(t, []string{"restore"}, project.InstallCommandArgs)
	assert.Equal(t, "deps-remote", project.Repository)
}

func TestExtractGitNamingTemplatesFromEnv(t *testing.T) {
	git := Git{}
	defer func() {
		assert.NoError(t, SanitizeEnv())
	}()

	// Test default values
	err := extractGitNamingTemplatesFromEnv(&git)
	assert.NoError(t, err)
	assert.Empty(t, git.BranchNameTemplate)
	assert.Empty(t, git.CommitMessageTemplate)
	assert.Empty(t, git.PullRequestTitleTemplate)
	assert.Empty(t, git.AggregateFixes)

	// Test value extraction
	SetEnvAndAssert(t, map[string]string{
		BranchNameTemplateEnv:       "branch",
		CommitMessageTemplateEnv:    "commit",
		PullRequestTitleTemplateEnv: "title",
		GitAggregateFixesEnv:        "true"})

	err = extractGitNamingTemplatesFromEnv(&git)
	assert.NoError(t, err)
	assert.Equal(t, git.BranchNameTemplate, "branch")
	assert.Equal(t, git.CommitMessageTemplate, "commit")
	assert.Equal(t, git.PullRequestTitleTemplate, "title")
	assert.Equal(t, git.AggregateFixes, true)
}

func TestExtractProjectParamsFromEnv(t *testing.T) {
	params := Project{}
	defer func() {
		assert.NoError(t, SanitizeEnv())
	}()

	// Test default values
	err := extractProjectParamsFromEnv(&params)
	assert.NoError(t, err)
	assert.True(t, *params.UseWrapper)
	assert.Equal(t, []string{RootDir}, params.WorkingDirs)
	assert.Equal(t, "", params.PipRequirementsFile)
	assert.Equal(t, "", params.InstallCommandName)
	assert.Equal(t, []string(nil), params.InstallCommandArgs)

	// Test value extraction
	SetEnvAndAssert(t, map[string]string{
		WorkingDirectoryEnv: "b/c",
		RequirementsFileEnv: "r.txt",
		UseWrapperEnv:       "false",
		InstallCommandEnv:   "nuget restore"})

	err = extractProjectParamsFromEnv(&params)
	assert.NoError(t, err)
	assert.Equal(t, []string{"b/c"}, params.WorkingDirs)
	assert.Equal(t, "r.txt", params.PipRequirementsFile)
	assert.False(t, *params.UseWrapper)
	assert.Equal(t, "nuget", params.InstallCommandName)
	assert.Equal(t, []string{"restore"}, params.InstallCommandArgs)
}

func TestFrogbotConfigAggregator_UnmarshalYaml(t *testing.T) {
	testFilePath := filepath.Join("..", "testdata", "config", "frogbot-config-test-unmarshal.yml")
	fileContent, err := os.ReadFile(testFilePath)
	assert.NoError(t, err)
	configAggregator := FrogbotConfigAggregator{}
	configAggregator, err = configAggregator.UnmarshalYaml(fileContent)
	assert.NoError(t, err)
	firstRepo := configAggregator[0]
	assert.Equal(t, "npm-repo", firstRepo.RepoName)
	assert.ElementsMatch(t, []string{"master", "main"}, firstRepo.Branches)
	assert.False(t, *firstRepo.FailOnSecurityIssues)
	firstRepoProject := firstRepo.Projects[0]
	assert.Equal(t, "nuget restore", firstRepoProject.InstallCommand)
	assert.False(t, *firstRepoProject.UseWrapper)
	assert.Equal(t, "test-repo", firstRepoProject.Repository)
	secondRepo := configAggregator[1]
	assert.Equal(t, "mvn-repo", secondRepo.RepoName)
	assert.Equal(t, []string{"dev"}, secondRepo.Branches)
	thirdRepo := configAggregator[2]
	assert.Equal(t, "pip-repo", thirdRepo.RepoName)
	assert.Equal(t, []string{"test"}, thirdRepo.Branches)
	assert.True(t, *thirdRepo.FailOnSecurityIssues)
	assert.False(t, thirdRepo.IncludeAllVulnerabilities)
	thirdRepoProject := thirdRepo.Projects[0]
	assert.Equal(t, "requirements.txt", thirdRepoProject.PipRequirementsFile)
	assert.ElementsMatch(t, []string{"a/b", "b/c"}, thirdRepoProject.WorkingDirs)
	assert.ElementsMatch(t, []string{"watch-1", "watch-2"}, thirdRepo.Watches)
	assert.Equal(t, "proj", thirdRepo.JFrogProjectKey)
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
