package utils

import (
	"github.com/jfrog/frogbot/v2/utils/outputwriter"
)

type vcsProvider string
type ciProvider string

const (
	// MaxConcurrentScanners represents the maximum number of threads for running JFrog CLI scanners concurrently
	MaxConcurrentScanners = 5

	// VCS providers params
	GitHub          vcsProvider = "github"
	GitLab          vcsProvider = "gitlab"
	BitbucketServer vcsProvider = "bitbucketServer"
	AzureRepos      vcsProvider = "azureRepos"

	// CI providers params
	githubActions  ciProvider = "github-actions"
	jenkins        ciProvider = "jenkins"
	gitlab         ciProvider = "gitlab"
	azurePipelines ciProvider = "azure-pipelines"

	// JFrog platform environment variables
	JFrogUserEnv           = "JF_USER"
	JFrogUrlEnv            = "JF_URL"
	jfrogXrayUrlEnv        = "JF_XRAY_URL"
	jfrogArtifactoryUrlEnv = "JF_ARTIFACTORY_URL"
	jfrogReleasesRepoEnv   = "JF_RELEASES_REPO"
	JFrogPasswordEnv       = "JF_PASSWORD"
	JFrogTokenEnv          = "JF_ACCESS_TOKEN"
	jfrogProjectEnv        = "JF_PROJECT"

	// Git environment variables
	GitProvider                     = "JF_GIT_PROVIDER"
	GitRepoOwnerEnv                 = "JF_GIT_OWNER"
	GitRepoEnv                      = "JF_GIT_REPO"
	GitAzureProjectEnv              = "JF_GIT_AZURE_PROJECT"
	GitUsernameEnv                  = "JF_GIT_USERNAME"
	GitDependencyGraphSubmissionEnv = "JF_UPLOAD_SBOM_TO_VCS"

	//#nosec G101 -- False positive - no hardcoded credentials.
	GitTokenEnv         = "JF_GIT_TOKEN"
	GitBaseBranchEnv    = "JF_GIT_BASE_BRANCH"
	GitPullRequestIDEnv = "JF_GIT_PULL_REQUEST_ID"
	GitApiEndpointEnv   = "JF_GIT_API_ENDPOINT"

	// The 'GITHUB_ACTIONS' environment variable exists when the CI is GitHub Actions
	GitHubActionsEnv = "GITHUB_ACTIONS" // TODO WHAT IS THIS?

	// Placeholders for templates
	PackagePlaceHolder    = "{IMPACTED_PACKAGE}"
	FixVersionPlaceHolder = "{FIX_VERSION}"
	BranchHashPlaceHolder = "{BRANCH_NAME_HASH}"

	// Default naming templates
	BranchNameTemplate                       = "frogbot-" + PackagePlaceHolder + "-" + BranchHashPlaceHolder
	AggregatedBranchNameTemplate             = "frogbot-update-" + BranchHashPlaceHolder + "-dependencies"
	CommitMessageTemplate                    = "Upgrade " + PackagePlaceHolder + " to " + FixVersionPlaceHolder
	PullRequestTitleTemplate                 = outputwriter.FrogbotTitlePrefix + " Update version of " + PackagePlaceHolder + " to " + FixVersionPlaceHolder
	AggregatePullRequestTitleDefaultTemplate = outputwriter.FrogbotTitlePrefix + " Update %s dependencies"
	// Frogbot Git author details showed in commits
	frogbotAuthorName  = "JFrog-Frogbot"
	frogbotAuthorEmail = "frogbot@jfrog.com"
)

type UnsupportedErrorType string

const (
	IndirectDependencyFixNotSupported   UnsupportedErrorType = "IndirectDependencyFixNotSupported"
	BuildToolsDependencyFixNotSupported UnsupportedErrorType = "BuildToolsDependencyFixNotSupported"
	UnsupportedForFixVulnerableVersion  UnsupportedErrorType = "UnsupportedForFixVulnerableVersion"
)
