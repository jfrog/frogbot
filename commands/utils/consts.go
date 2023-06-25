package utils

type IconName string
type ImageSource string
type vcsProvider string

const (
	baseResourceUrl = "https://raw.githubusercontent.com/jfrog/frogbot/master/resources/"

	// Errors
	errUnsupportedMultiRepo        = "multi repository configuration isn't supported. Only one repository configuration is allowed"
	ErrScanPullRequestSameBranches = "scan pull request command triggered on the same branch: %s, Please check your configuration"

	// Images
	NoVulnerabilityBannerSource ImageSource = "noVulnerabilityBanner.png"
	VulnerabilitiesBannerSource ImageSource = "vulnerabilitiesBanner.png"
	criticalSeveritySource      ImageSource = "criticalSeverity.png"
	highSeveritySource          ImageSource = "highSeverity.png"
	mediumSeveritySource        ImageSource = "mediumSeverity.png"
	lowSeveritySource           ImageSource = "lowSeverity.png"

	// VCS providers params
	GitHub          vcsProvider = "github"
	GitLab          vcsProvider = "gitlab"
	BitbucketServer vcsProvider = "bitbucketServer"
	AzureRepos      vcsProvider = "azureRepos"

	// Frogbot comments
	RescanRequestComment = "rescan"

	// JFrog platform environment variables
	JFrogUserEnv           = "JF_USER"
	JFrogUrlEnv            = "JF_URL"
	jfrogXrayUrlEnv        = "JF_XRAY_URL"
	jfrogArtifactoryUrlEnv = "JF_ARTIFACTORY_URL"
	jfrogReleasesRepoEnv   = "JF_RELEASES_REPO"
	JFrogPasswordEnv       = "JF_PASSWORD"
	JFrogTokenEnv          = "JF_ACCESS_TOKEN"

	// Git environment variables
	GitProvider     = "JF_GIT_PROVIDER"
	GitRepoOwnerEnv = "JF_GIT_OWNER"
	GitRepoEnv      = "JF_GIT_REPO"
	GitProjectEnv   = "JF_GIT_PROJECT"
	GitUsernameEnv  = "JF_GIT_USERNAME"

	// Git naming template environment variables
	BranchNameTemplateEnv       = "JF_BRANCH_NAME_TEMPLATE"
	CommitMessageTemplateEnv    = "JF_COMMIT_MESSAGE_TEMPLATE"
	PullRequestTitleTemplateEnv = "JF_PULL_REQUEST_TITLE_TEMPLATE"

	// Repository environment variables - Ignored if the frogbot-config.yml file is used
	InstallCommandEnv            = "JF_INSTALL_DEPS_CMD"
	RequirementsFileEnv          = "JF_REQUIREMENTS_FILE"
	WorkingDirectoryEnv          = "JF_WORKING_DIR"
	jfrogWatchesEnv              = "JF_WATCHES"
	jfrogProjectEnv              = "JF_PROJECT"
	IncludeAllVulnerabilitiesEnv = "JF_INCLUDE_ALL_VULNERABILITIES"
	FailOnSecurityIssuesEnv      = "JF_FAIL"
	UseWrapperEnv                = "JF_USE_WRAPPER"
	DepsRepoEnv                  = "JF_DEPS_REPO"
	MinSeverityEnv               = "JF_MIN_SEVERITY"
	FixableOnlyEnv               = "JF_FIXABLE_ONLY"
	WatchesDelimiter             = ","

	//#nosec G101 -- False positive - no hardcoded credentials.
	GitTokenEnv          = "JF_GIT_TOKEN"
	GitBaseBranchEnv     = "JF_GIT_BASE_BRANCH"
	GitPullRequestIDEnv  = "JF_GIT_PULL_REQUEST_ID"
	GitApiEndpointEnv    = "JF_GIT_API_ENDPOINT"
	GitAggregateFixesEnv = "JF_GIT_AGGREGATE_FIXES"

	// Comment
	tableHeader = "\n| SEVERITY | DIRECT DEPENDENCIES | DIRECT DEPENDENCIES VERSIONS | IMPACTED DEPENDENCY NAME | IMPACTED DEPENDENCY VERSION | FIXED VERSIONS | CVE\n" +
		":--: | -- | -- | -- | -- | :--: | --"
	simplifiedTableHeader = "\n| SEVERITY | DIRECT DEPENDENCIES | IMPACTED DEPENDENCY NAME | IMPACTED DEPENDENCY VERSION | FIXED VERSIONS | CVE\n" + ":--: | -- | -- | -- | :--: | --"
	WhatIsFrogbotMd       = "\n\n[What is Frogbot?](https://github.com/jfrog/frogbot#readme)\n"

	// Product ID for usage reporting
	productId = "frogbot"

	// The 'GITHUB_ACTIONS' environment variable exists when the CI is GitHub Actions
	GitHubActionsEnv = "GITHUB_ACTIONS"

	// Placeholders for templates
	PackagePlaceHolder    = "${IMPACTED_PACKAGE}"
	FixVersionPlaceHolder = "${FIX_VERSION}"
	BranchHashPlaceHolder = "${BRANCH_NAME_HASH}"

	// Default naming templates
	BranchNameTemplate                 = "frogbot-" + PackagePlaceHolder + "-" + BranchHashPlaceHolder
	AggregatedBranchNameTemplate       = "frogbot-update-dependencies-" + BranchHashPlaceHolder
	CommitMessageTemplate              = "Upgrade " + PackagePlaceHolder + " to " + FixVersionPlaceHolder
	AggregatedPullRequestTitleTemplate = "[🐸 Frogbot] Update dependencies versions"
	PullRequestTitleTemplate           = "[🐸 Frogbot] Update version of " + PackagePlaceHolder + " to " + FixVersionPlaceHolder
	// Frogbot Git author details showed in commits
	frogbotAuthorName  = "JFrog-Frogbot"
	frogbotAuthorEmail = "eco-system+frogbot@jfrog.com"

	AggregateFixesDefaultValue = false
)

type UnsupportedErrorType string

const (
	IndirectDependencyFixNotSupported   UnsupportedErrorType = "IndirectDependencyFixNotSupported"
	BuildToolsDependencyFixNotSupported UnsupportedErrorType = "BuildToolsDependencyFixNotSupported"
)
