package utils

type imageSource string
type vcsProvider string
type frogbotLabel string

const (
	baseResourceUrl = "https://raw.githubusercontent.com/jfrog/frogbot/master/resources/"

	// Images
	NoVulnerabilityBannerSource imageSource = "noVulnerabilityBanner.png"
	VulnerabilitiesBannerSource imageSource = "vulnerabilitiesBanner.png"
	criticalSeveritySource      imageSource = "criticalSeverity.png"
	highSeveritySource          imageSource = "highSeverity.png"
	mediumSeveritySource        imageSource = "mediumSeverity.png"
	lowSeveritySource           imageSource = "lowSeverity.png"

	// VCS providers params
	GitHub vcsProvider = "github"
	GitLab vcsProvider = "gitlab"

	// Frogbot label
	LabelName        frogbotLabel = "🐸 frogbot scan"
	LabelDescription frogbotLabel = "triggers frogbot scan"
	LabelColor       frogbotLabel = "4AB548"

	InstallCommandEnv   = "JF_INSTALL_DEPS_CMD"
	WorkingDirectoryEnv = "JF_WORKING_DIR"

	// JFrog platform environment varialbes
	JFrogUserEnv           = "JF_USER"
	JFrogUrlEnv            = "JF_URL"
	jfrogXrayUrlEnv        = "JF_XRAY_URL"
	jfrogArtifactoryUrlEnv = "JF_ARTIFACTORY_URL"
	JFrogPasswordEnv       = "JF_PASSWORD"
	JFrogTokenEnv          = "JF_ACCESS_TOKEN"
	jfrogWatchesEnv        = "JF_WATCHES"
	jfrogProjectEnv        = "JF_PROJECT"

	// Git environment variables
	GitProvider     = "JF_GIT_PROVIDER"
	GitRepoOwnerEnv = "JF_GIT_OWNER"
	GitRepoEnv      = "JF_GIT_REPO"
	//#nosec G101 -- False positive - no hardcoded credentials.
	GitTokenEnv         = "JF_GIT_TOKEN"
	GitBaseBranchEnv    = "JF_GIT_BASE_BRANCH"
	GitPullRequestIDEnv = "JF_GIT_PULL_REQUEST_ID"
	GitApiEndpointEnv   = "JF_GIT_API_ENDPOINT"
	WatchesDelimiter    = ","

	// Comment
	TableHeder = "\n| SEVERITY | IMPACTED PACKAGE | VERSION | FIXED VERSIONS | COMPONENT | COMPONENT VERSION | CVE\n" +
		":--: | -- | -- | -- | -- | :--: | --"
	WhatIsFrogbotMd = "\n\n[What is Frogbot?](https://github.com/jfrog/frogbot#frogbot)"
)
