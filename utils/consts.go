package utils

import (
	"github.com/jfrog/frogbot/v2/utils/outputwriter"
)

type vcsProvider string
type ciProvider string

const (
	// Errors
	errUnsupportedMultiRepo = "multi repository configuration isn't supported. Only one repository configuration is allowed"

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

	// Git environment variables
	GitProvider                     = "JF_GIT_PROVIDER"
	GitRepoOwnerEnv                 = "JF_GIT_OWNER"
	GitRepoEnv                      = "JF_GIT_REPO"
	GitProjectEnv                   = "JF_GIT_PROJECT"
	GitUsernameEnv                  = "JF_GIT_USERNAME"
	GitUseLocalRepositoryEnv        = "JF_USE_LOCAL_REPOSITORY"
	GitDependencyGraphSubmissionEnv = "JF_UPLOAD_SBOM_TO_VCS"

	// Git naming template environment variables
	BranchNameTemplateEnv       = "JF_BRANCH_NAME_TEMPLATE"
	CommitMessageTemplateEnv    = "JF_COMMIT_MESSAGE_TEMPLATE"
	PullRequestTitleTemplateEnv = "JF_PULL_REQUEST_TITLE_TEMPLATE"
	PullRequestCommentTitleEnv  = "JF_PR_COMMENT_TITLE"
	//#nosec G101 -- not a secret
	PullRequestSecretCommentsEnv = "JF_PR_SHOW_SECRETS_COMMENTS"

	// Repository environment variables
	InstallCommandEnv   = "JF_INSTALL_DEPS_CMD"
	MaxPnpmTreeDepthEnv = "JF_PNPM_MAX_TREE_DEPTH"
	RequirementsFileEnv = "JF_REQUIREMENTS_FILE"
	WorkingDirectoryEnv = "JF_WORKING_DIR"
	PathExclusionsEnv   = "JF_PATH_EXCLUSIONS"
	jfrogWatchesEnv     = "JF_WATCHES"
	jfrogProjectEnv     = "JF_PROJECT"
	// To include vulnerabilities and violations
	IncludeVulnerabilitiesEnv = "JF_INCLUDE_VULNERABILITIES"
	// To include all the vulnerabilities in the source branch at PR scan
	IncludeAllVulnerabilitiesEnv = "JF_INCLUDE_ALL_VULNERABILITIES"
	AddPrCommentOnSuccessEnv     = "JF_PR_ADD_SUCCESS_COMMENT"
	FailOnSecurityIssuesEnv      = "JF_FAIL"
	UseWrapperEnv                = "JF_USE_WRAPPER"
	DepsRepoEnv                  = "JF_DEPS_REPO"
	MinSeverityEnv               = "JF_MIN_SEVERITY"
	FixableOnlyEnv               = "JF_FIXABLE_ONLY"
	DetectionOnlyEnv             = "JF_SKIP_AUTOFIX"
	AllowedLicensesEnv           = "JF_ALLOWED_LICENSES"
	SkipAutoInstallEnv           = "JF_SKIP_AUTO_INSTALL"
	AllowPartialResultsEnv       = "JF_ALLOW_PARTIAL_RESULTS"
	WatchesDelimiter             = ","

	//#nosec G101 -- False positive - no hardcoded credentials.
	GitTokenEnv          = "JF_GIT_TOKEN"
	GitBaseBranchEnv     = "JF_GIT_BASE_BRANCH"
	GitPullRequestIDEnv  = "JF_GIT_PULL_REQUEST_ID"
	GitApiEndpointEnv    = "JF_GIT_API_ENDPOINT"
	GitAggregateFixesEnv = "JF_GIT_AGGREGATE_FIXES"

	// The 'GITHUB_ACTIONS' environment variable exists when the CI is GitHub Actions
	GitHubActionsEnv = "GITHUB_ACTIONS"

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
