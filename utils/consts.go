package utils

import (
	"github.com/jfrog/frogbot/v3/utils/outputwriter"
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
	BitbucketCloud  vcsProvider = "bitbucketCloud"
	AzureRepos      vcsProvider = "azureRepos"

	// CI providers params
	githubActions  ciProvider = "github-actions"
	jenkins        ciProvider = "jenkins"
	gitlab         ciProvider = "gitlab"
	azurePipelines ciProvider = "azure-pipelines"

	// JFrog platform environment variables
	JFrogUrlEnv            = "JF_URL"
	jfrogXrayUrlEnv        = "JF_XRAY_URL"
	jfrogArtifactoryUrlEnv = "JF_ARTIFACTORY_URL"
	jfrogReleasesRepoEnv   = "JF_RELEASES_REPO"
	JFrogUserEnv           = "JF_USER"
	JFrogPasswordEnv       = "JF_PASSWORD"
	JFrogTokenEnv          = "JF_ACCESS_TOKEN"
	jfrogProjectEnv        = "JF_PROJECT_KEY"

	// Git environment variables
	GitProvider                     = "JF_GIT_PROVIDER"
	GitRepoOwnerEnv                 = "JF_GIT_OWNER"
	GitRepoEnv                      = "JF_GIT_REPO"
	GitAzureProjectEnv              = "JF_GIT_AZURE_PROJECT"
	GitBitBucketUsernameEnv         = "JF_GIT_BB_USERNAME"
	GitDependencyGraphSubmissionEnv = "JF_UPLOAD_SBOM_TO_VCS"
	UploadPrSecurityResultsToVcsEnv = "JF_UPLOAD_PR_SECURITY_RESULTS_TO_VCS"

	//#nosec G101 -- False positive - no hardcoded credentials.
	GitTokenEnv                   = "JF_GIT_TOKEN"
	GitBaseBranchEnv              = "JF_GIT_BASE_BRANCH"
	GitPullRequestIDEnv           = "JF_GIT_PULL_REQUEST_ID"
	GitApiEndpointEnv             = "JF_GIT_API_ENDPOINT"
	GitlabScanResultsOutputDirEnv = "JF_SCAN_RESULTS_OUTPUT_DIR"
	GitWorkspaceEnv               = "JF_GIT_WORKSPACE"

	// The 'GITHUB_ACTIONS' environment variable exists when the CI is GitHub Actions
	GitHubActionsEnv = "GITHUB_ACTIONS"
	// The 'GITHUB_WORKFLOW_REF' environment variable contains the ref path to the workflow file, e.g. owner/repo/.github/workflows/frogbot.yml@refs/heads/main
	GitHubWorkflowRefEnv = "GITHUB_WORKFLOW_REF"

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
