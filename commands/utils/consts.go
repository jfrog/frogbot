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
	gitHub vcsProvider = "github"
	gitLab vcsProvider = "gitlab"

	// Frogbot label
	LabelName        frogbotLabel = "🐸 frogbot scan"
	LabelDescription frogbotLabel = "triggers frogbot scan"
	LabelColor       frogbotLabel = "4AB548"

	installCommandEnv = "JF_INSTALL_DEPS_CMD"

	// JFrog platform environment varialbes
	jfrogUserEnv           = "JF_USER"
	jfrogUrlEnv            = "JF_URL"
	jfrogXrayUrlEnv        = "JF_XRAY_URL"
	jfrogArtifactoryUrlEnv = "JF_ARTIFACTORY_URL"
	jfrogPasswordEnv       = "JF_PASSWORD"
	jfrogTokenEnv          = "JF_TOKEN"
	jfrogWatchesEnv        = "JF_WATCHES"
	jfrogProjectEnv        = "JF_PROJECT"

	// Git environment variables
	gitProvider     = "JF_GIT_PROVIDER"
	gitRepoOwnerEnv = "JF_GIT_OWNER"
	gitRepoEnv      = "JF_GIT_REPO"
	//#nosec G101 -- False positive - no hardcoded credentials.
	gitTokenEnv         = "JF_GIT_TOKEN"
	gitBaseBranchEnv    = "JF_GIT_BASE_BRANCH"
	gitPullRequestIDEnv = "JF_GIT_PULL_REQUEST_ID"
	WatchesDelimiter    = ","

	// Comment
	TableHeder = "\n| SEVERITY | IMPACTED PACKAGE | VERSION | FIXED VERSIONS | COMPONENT | COMPONENT VERSION | CVE\n" +
		":--: | -- | -- | -- | -- | :--: | --"
	WhatIsFrogbotMd = "\n\n[What is Frogbot?](https://github.com/jfrog/frogbot#frogbot)"
)
