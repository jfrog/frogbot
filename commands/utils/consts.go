package utils

type IconName string
type ImageSource string
type vcsProvider string

// GetGetTitleFunc, a func to determine the title of Frogbot comment
type GetTitleFunc func(ImageSource) string

// GetGetTitleFunc, a func to determine the table's severity tag in the Frogbot comment
type GetSeverityTagFunc func(IconName) string

const (
	baseResourceUrl = "https://raw.githubusercontent.com/jfrog/frogbot/master/resources/"

	// Errors
	UnsupportedMultiRepoErr = "multi repository configuration isn't supported. only one repository configuration is allowed"

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
	JFrogPasswordEnv       = "JF_PASSWORD"
	JFrogTokenEnv          = "JF_ACCESS_TOKEN"

	// Git environment variables
	GitProvider          = "JF_GIT_PROVIDER"
	GitRepoOwnerEnv      = "JF_GIT_OWNER"
	GitRepoEnv           = "JF_GIT_REPO"
	GitProjectEnv        = "JF_GIT_PROJECT"
	FrogbotConfigRepoEnv = "FROGBOT_CONFIG_REPO"

	// Single repository scan environment variables - Ignored if config file is used
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
	TableHeader = "\n| SEVERITY | IMPACTED PACKAGE | VERSION | FIXED VERSIONS | COMPONENT | COMPONENT VERSION | CVE\n" +
		":--: | -- | -- | -- | -- | :--: | --"
	WhatIsFrogbotMd = "\n\n[What is Frogbot?](https://github.com/jfrog/frogbot#readme)\n"

	// Product ID for usage reporting
	productId = "frogbot"
)
