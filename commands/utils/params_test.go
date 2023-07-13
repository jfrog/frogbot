package utils

import (
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"os"
	"path/filepath"
	"testing"

	"github.com/jfrog/froggit-go/vcsutils"
	"github.com/stretchr/testify/assert"
)

var (
	configParamsTestFile          = filepath.Join("..", "testdata", "config", "frogbot-config-test-params.yml")
	configEmptyScanParamsTestFile = filepath.Join("..", "testdata", "config", "frogbot-config-empty-scan.yml")
)

func TestExtractParamsFromEnvError(t *testing.T) {
	SetEnvAndAssert(t, map[string]string{
		JFrogUrlEnv:      "",
		JFrogUserEnv:     "",
		JFrogPasswordEnv: "",
		JFrogTokenEnv:    "",
	})
	_, err := extractJFrogCredentialsFromEnv()
	assert.EqualError(t, err, "JF_URL or JF_XRAY_URL and JF_ARTIFACTORY_URL environment variables are missing")

	SetEnvAndAssert(t, map[string]string{JFrogUrlEnv: "http://127.0.0.1:8081"})
	_, err = extractJFrogCredentialsFromEnv()
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

func TestExtractClientInfo(t *testing.T) {
	defer func() {
		assert.NoError(t, SanitizeEnv())
	}()

	_, err := extractClientInfo()
	assert.EqualError(t, err, "JF_GIT_PROVIDER should be one of: 'github', 'gitlab' or 'bitbucketServer'")

	SetEnvAndAssert(t, map[string]string{GitProvider: "github"})
	_, err = extractClientInfo()
	assert.EqualError(t, err, "'JF_GIT_OWNER' environment variable is missing")

	SetEnvAndAssert(t, map[string]string{GitRepoOwnerEnv: "jfrog"})
	_, err = extractClientInfo()
	assert.EqualError(t, err, "'JF_GIT_TOKEN' environment variable is missing")
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
		GitEmailAuthorEnv:    "myemail@jfrog.com",
		MinSeverityEnv:       "high",
		FixableOnlyEnv:       "true",
	})
	defer func() {
		assert.NoError(t, SanitizeEnv())
	}()
	server, gitParams, err := extractClientServerParams()
	assert.NoError(t, err)
	configFileContent, err := ReadConfigFromFileSystem(configParamsTestFile)
	assert.NoError(t, err)
	configAggregator, err := BuildRepoAggregator(configFileContent, gitParams, server)
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
		assert.Equal(t, "myemail@jfrog.com", repo.EmailAuthor)
		assert.ElementsMatch(t, []string{"watch-2", "watch-1"}, repo.Watches)
		for _, project := range repo.Projects {
			testExtractAndAssertProjectParams(t, project)
		}
	}
}

func TestBuildRepoAggregatorWithEmptyScan(t *testing.T) {
	SetEnvAndAssert(t, map[string]string{
		JFrogUrlEnv:     "http://127.0.0.1:8081",
		JFrogTokenEnv:   "token",
		GitProvider:     string(GitHub),
		GitRepoOwnerEnv: "jfrog",
		GitRepoEnv:      "frogbot",
		GitTokenEnv:     "123456789",
	})
	defer func() {
		assert.NoError(t, SanitizeEnv())
	}()
	server, gitParams, err := extractClientServerParams()
	assert.NoError(t, err)
	configFileContent, err := ReadConfigFromFileSystem(configEmptyScanParamsTestFile)
	assert.NoError(t, err)
	configAggregator, err := BuildRepoAggregator(configFileContent, gitParams, server)
	assert.NoError(t, err)
	assert.Len(t, configAggregator, 1)
	assert.Equal(t, frogbotAuthorEmail, configAggregator[0].EmailAuthor)
	assert.False(t, configAggregator[0].AggregateFixes)
	scan := configAggregator[0].Scan
	assert.False(t, scan.IncludeAllVulnerabilities)
	assert.False(t, scan.FixableOnly)
	assert.Empty(t, scan.MinSeverity)
	assert.True(t, *scan.FailOnSecurityIssues)
	assert.Len(t, scan.Projects, 1)
	project := scan.Projects[0]
	assert.Empty(t, project.InstallCommandName)
	assert.Empty(t, project.InstallCommandArgs)
	assert.Empty(t, project.PipRequirementsFile)
	assert.Empty(t, project.Repository)
	assert.Len(t, project.WorkingDirs, 1)
	assert.Equal(t, RootDir, project.WorkingDirs[0])
	assert.True(t, *project.UseWrapper)
}

func testExtractAndAssertProjectParams(t *testing.T, project Project) {
	assert.Equal(t, "nuget", project.InstallCommandName)
	assert.Equal(t, []string{"restore"}, project.InstallCommandArgs)
	assert.ElementsMatch(t, []string{"a/b", "b/c"}, project.WorkingDirs)
	assert.Equal(t, "", project.PipRequirementsFile)
}

func extractAndAssertParamsFromEnv(t *testing.T, platformUrl, basicAuth bool) {
	server, gitParams, err := extractClientServerParams()
	assert.NoError(t, err)
	configFile, err := BuildRepoAggregator(nil, gitParams, server)
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

func TestGenerateConfigAggregatorFromEnv(t *testing.T) {
	SetEnvAndAssert(t, map[string]string{
		JFrogUrlEnv:                  "",
		jfrogArtifactoryUrlEnv:       "http://127.0.0.1:8081/artifactory",
		jfrogXrayUrlEnv:              "http://127.0.0.1:8081/xray",
		JFrogUserEnv:                 "admin",
		JFrogPasswordEnv:             "password",
		BranchNameTemplateEnv:        "branch-${BRANCH_NAME_HASH}",
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
		ClientInfo: ClientInfo{
			GitProvider: vcsutils.GitHub,
			VcsInfo: vcsclient.VcsInfo{
				APIEndpoint: "endpoint.com",
				Token:       "123456789",
			},
			RepoName:  "repoName",
			Branches:  []string{"master"},
			RepoOwner: "jfrog",
		},
	}
	server := config.ServerDetails{
		ArtifactoryUrl: "http://127.0.0.1:8081/artifactory",
		XrayUrl:        "http://127.0.0.1:8081/xray",
		User:           "admin",
		Password:       "password",
	}
	repoAggregator, err := BuildRepoAggregator(nil, &gitParams, &server)
	assert.NoError(t, err)
	repo := repoAggregator[0]
	assert.Equal(t, "repoName", repo.RepoName)
	assert.ElementsMatch(t, repo.Watches, []string{"watch-1", "watch-2", "watch-3"})
	assert.Equal(t, false, *repo.FailOnSecurityIssues)
	assert.Equal(t, "Medium", repo.MinSeverity)
	assert.Equal(t, true, repo.FixableOnly)
	assert.Equal(t, gitParams.RepoOwner, repo.RepoOwner)
	assert.Equal(t, gitParams.Token, repo.Token)
	assert.Equal(t, gitParams.APIEndpoint, repo.APIEndpoint)
	assert.ElementsMatch(t, gitParams.Branches, repo.Branches)
	assert.Equal(t, repo.PullRequestID, repo.PullRequestID)
	assert.Equal(t, gitParams.GitProvider, repo.GitProvider)
	assert.Equal(t, repo.BranchNameTemplate, repo.BranchNameTemplate)
	assert.Equal(t, repo.CommitMessageTemplate, repo.CommitMessageTemplate)
	assert.Equal(t, repo.PullRequestTitleTemplate, repo.PullRequestTitleTemplate)
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
	assert.Equal(t, "repository", project.Repository)
}

func TestFrogbotConfigAggregator_unmarshalFrogbotConfigYaml(t *testing.T) {
	testFilePath := filepath.Join("..", "testdata", "config", "frogbot-config-test-unmarshal.yml")
	fileContent, err := os.ReadFile(testFilePath)
	assert.NoError(t, err)
	configAggregator, err := unmarshalFrogbotConfigYaml(fileContent)
	assert.NoError(t, err)
	firstRepo := configAggregator[0]
	assert.Equal(t, "npm-repo", firstRepo.RepoName)
	assert.Equal(t, "myemail@jfrog.com", firstRepo.EmailAuthor)
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

func TestBuildMergedRepoAggregator(t *testing.T) {
	SetEnvAndAssert(t, map[string]string{
		RequirementsFileEnv:          "r.txt",
		UseWrapperEnv:                "false",
		InstallCommandEnv:            "nuget restore",
		IncludeAllVulnerabilitiesEnv: "false",
		DepsRepoEnv:                  "repository",
		CommitMessageTemplateEnv:     "commit-msg",
		FailOnSecurityIssuesEnv:      "true",
		jfrogWatchesEnv:              "watch-1,watch-2",
	})
	testFilePath := filepath.Join("..", "testdata", "config", "frogbot-config-test-params-merge.yml")
	fileContent, err := os.ReadFile(testFilePath)
	assert.NoError(t, err)
	gitParams := Git{
		ClientInfo: ClientInfo{
			GitProvider: vcsutils.GitHub,
			VcsInfo: vcsclient.VcsInfo{
				APIEndpoint: "endpoint.com",
				Token:       "123456789",
			},
			RepoName:  "repoName",
			Branches:  []string{"master"},
			RepoOwner: "jfrog",
		},
	}
	server := config.ServerDetails{
		ArtifactoryUrl: "http://127.0.0.1:8081/artifactory",
		XrayUrl:        "http://127.0.0.1:8081/xray",
		User:           "admin",
		Password:       "password",
	}
	repoAggregator, err := BuildRepoAggregator(fileContent, &gitParams, &server)
	assert.NoError(t, err)
	repo := repoAggregator[0]
	assert.Equal(t, repo.AggregateFixes, false)
	assert.True(t, repo.IncludeAllVulnerabilities)
	assert.True(t, repo.FixableOnly)
	assert.True(t, *repo.FailOnSecurityIssues)
	assert.Equal(t, "High", repo.MinSeverity)
	assert.Equal(t, "commit-msg", repo.CommitMessageTemplate)
	assert.Equal(t, "proj", repo.JFrogProjectKey)
	assert.Equal(t, "myPullRequests", repo.PullRequestTitleTemplate)
	assert.ElementsMatch(t, []string{"watch-1", "watch-2"}, repo.Watches)
	project := repo.Projects[0]
	assert.ElementsMatch(t, []string{"a/b"}, project.WorkingDirs)
	assert.Equal(t, "r.txt", project.PipRequirementsFile)
	assert.Equal(t, "repository", project.Repository)
	assert.Equal(t, "nuget", project.InstallCommandName)
	assert.Equal(t, []string{"restore"}, project.InstallCommandArgs)
	assert.False(t, *project.UseWrapper)
}
