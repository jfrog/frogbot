package utils

type IconName string
type ImageSource string
type vcsProvider string

const (
	FrogbotVersion  = "2.5.8"
	baseResourceUrl = "https://raw.githubusercontent.com/jfrog/frogbot/master/resources/"

	// Errors
	errUnsupportedMultiRepo = "multi repository configuration isn't supported. only one repository configuration is allowed"

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
	jfrogRemoteRepo        = "JF_FROGBOT_REPO"
	JFrogPasswordEnv       = "JF_PASSWORD"
	JFrogTokenEnv          = "JF_ACCESS_TOKEN"

	// Git environment variables
	GitProvider     = "JF_GIT_PROVIDER"
	GitRepoOwnerEnv = "JF_GIT_OWNER"
	GitRepoEnv      = "JF_GIT_REPO"
	GitProjectEnv   = "JF_GIT_PROJECT"
	GitUsernameEnv  = "JF_GIT_USERNAME"

	// Repository environment variables - Ignored if the frogbot-config.yml file is used
	InstallCommandEnv            = "JF_INSTALL_DEPS_CMD"
	RequirementsFileEnv          = "JF_REQUIREMENTS_FILE"
	WorkingDirectoryEnv          = "JF_WORKING_DIR"
	jfrogWatchesEnv              = "JF_WATCHES"
	jfrogProjectEnv              = "JF_PROJECT"
	IncludeAllVulnerabilitiesEnv = "JF_INCLUDE_ALL_VULNERABILITIES"
	FailOnSecurityIssuesEnv      = "JF_FAIL"
	UseWrapperEnv                = "JF_USE_WRAPPER"
	WatchesDelimiter             = ","

	//#nosec G101 -- False positive - no hardcoded credentials.
	GitTokenEnv         = "JF_GIT_TOKEN"
	GitBaseBranchEnv    = "JF_GIT_BASE_BRANCH"
	GitPullRequestIDEnv = "JF_GIT_PULL_REQUEST_ID"
	GitApiEndpointEnv   = "JF_GIT_API_ENDPOINT"

	// Comment
	tableHeader = "\n| SEVERITY | DIRECT DEPENDENCIES | DIRECT DEPENDENCIES VERSIONS | IMPACTED DEPENDENCY NAME | IMPACTED DEPENDENCY VERSION | FIXED VERSIONS | CVE\n" +
		":--: | -- | -- | -- | -- | :--: | --"
	simplifiedTableHeader = "\n| SEVERITY | DIRECT DEPENDENCIES | IMPACTED DEPENDENCY NAME | IMPACTED DEPENDENCY VERSION | FIXED VERSIONS | CVE\n" + ":--: | -- | -- | -- | :--: | --"
	WhatIsFrogbotMd       = "\n\n[What is Frogbot?](https://github.com/jfrog/frogbot#readme)\n"

	// Product ID for usage reporting
	productId = "frogbot"

	// The 'GITHUB_ACTIONS' environment variable exists when the CI is GitHub Actions
	GitHubActionsEnv = "GITHUB_ACTIONS"
)
