package utils

type IconName string
type ImageSource string
type vcsProvider string

const (
	baseResourceUrl = "https://raw.githubusercontent.com/jfrog/frogbot/master/resources/"

	// Errors
	errUnsupportedMultiRepo = "multi repository configuration isn't supported. Only one repository configuration is allowed"

	// Images
	NoVulnerabilityPrBannerSource       ImageSource = "v2/noVulnerabilityBannerPR.png"
	NoVulnerabilityMrBannerSource       ImageSource = "v2/noVulnerabilityBannerMR.png"
	VulnerabilitiesPrBannerSource       ImageSource = "v2/vulnerabilitiesBannerPR.png"
	VulnerabilitiesMrBannerSource       ImageSource = "v2/vulnerabilitiesBannerMR.png"
	VulnerabilitiesFixPrBannerSource    ImageSource = "v2/vulnerabilitiesFixBannerPR.png"
	VulnerabilitiesFixMrBannerSource    ImageSource = "v2/vulnerabilitiesFixBannerMR.png"
	criticalSeveritySource              ImageSource = "v2/applicableCriticalSeverity.png"
	notApplicableCriticalSeveritySource ImageSource = "v2/notApplicableCritical.png"
	highSeveritySource                  ImageSource = "v2/applicableHighSeverity.png"
	notApplicableHighSeveritySource     ImageSource = "v2/notApplicableHigh.png"
	mediumSeveritySource                ImageSource = "v2/applicableMediumSeverity.png"
	notApplicableMediumSeveritySource   ImageSource = "v2/notApplicableMedium.png"
	lowSeveritySource                   ImageSource = "v2/applicableLowSeverity.png"
	notApplicableLowSeveritySource      ImageSource = "v2/notApplicableLow.png"
	unknownSeveritySource               ImageSource = "v2/applicableUnknownSeverity.png"
	notApplicableUnknownSeveritySource  ImageSource = "v2/notApplicableUnknown.png"

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

	// Email related environment variables
	SmtpServer     = "JF_SMTP_SERVER"
	SmtpPort       = "JF_SMTP_PORT"
	SmtpAuthUser   = "JF_SMTP_AUTH_USER"
	SmtpAuthPass   = "JF_SMTP_AUTH_PASS"
	EmailReceivers = "JF_EMAIL_RECEIVERS"

	//#nosec G101 -- False positive - no hardcoded credentials.
	GitTokenEnv          = "JF_GIT_TOKEN"
	GitBaseBranchEnv     = "JF_GIT_BASE_BRANCH"
	GitPullRequestIDEnv  = "JF_GIT_PULL_REQUEST_ID"
	GitApiEndpointEnv    = "JF_GIT_API_ENDPOINT"
	GitAggregateFixesEnv = "JF_GIT_AGGREGATE_FIXES"
	GitEmailAuthorEnv    = "JF_GIT_EMAIL_AUTHOR"

	// Comment
	vulnerabilitiesTableHeader                       = "\n| SEVERITY                | DIRECT DEPENDENCIES                  | IMPACTED DEPENDENCY                   | FIXED VERSIONS                       |\n| :---------------------: | :----------------------------------: | :-----------------------------------: | :---------------------------------: |"
	vulnerabilitiesTableHeaderWithContextualAnalysis = "| SEVERITY                | CONTEXTUAL ANALYSIS                  | DIRECT DEPENDENCIES                  | IMPACTED DEPENDENCY                   | FIXED VERSIONS                       |\n| :---------------------: | :----------------------------------: | :----------------------------------: | :-----------------------------------: | :---------------------------------: |"
	iacTableHeader                                   = "\n| SEVERITY                | FILE                  | LINE:COLUMN                   | FINDING                       |\n| :---------------------: | :----------------------------------: | :-----------------------------------: | :---------------------------------: |"
	CommentGeneratedByFrogbot                        = "[JFrog Frogbot](https://github.com/jfrog/frogbot#readme)"
	secretsEmailCSS                                  = `body {
            text-align: center;
            font-family: Arial, sans-serif;
        }
        a img {
            display: block;
            margin: 0 auto;
            max-width: 100%;
        }
        table {
            margin: 20px auto;
            border-collapse: collapse;
            width: 80%;
        }
        th, td {
            padding: 10px;
            border: 1px solid #ccc;
            text-align: center;
        }
        th {
            background-color: #f2f2f2;
        }
        tr:nth-child(even) {
            background-color: #f9f9f9;
        }
        tr:hover {
            background-color: #f5f5f5;
        }
        img.severity-icon {
            max-height: 30px;
            vertical-align: middle;
        }
        h1 {
            font-size: 24px;
            color: #333;
            margin-bottom: 20px;
        }
        .table-container {
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
            border-radius: 10px;
            overflow: hidden;
            background-color: #fff;
        }`
	secretsEmailHTMLTemplate = `
<!DOCTYPE html>
<html>
<head>
    <title>Frogbot Secret Detection</title>
    <style>
        %s
    </style>
</head>
<body>
    <div class="table-container">
        <a href="https://github.com/jfrog/frogbot#readme">
            <img src="%s" alt="Banner">
        </a>
        <table>
            <thead>
                <tr>
                    <th>SEVERITY</th>
                    <th>FILE</th>
                    <th>LINE:COLUMN</th>
                    <th>TEXT</th>
                </tr>
            </thead>
            <tbody>
                %s
            </tbody>
        </table>
    </div>
</body>
</html>`
	secretsEmailTableRow = `
				<tr>
					<td><img class="severity-icon" src="%s" alt="severity"> %s </td>
					<td> %s </td>
					<td> %s </td>
					<td> %s </td>
				</tr>`

	// Product ID for usage reporting
	productId = "frogbot"

	// The 'GITHUB_ACTIONS' environment variable exists when the CI is GitHub Actions
	GitHubActionsEnv = "GITHUB_ACTIONS"

	// Placeholders for templates
	PackagePlaceHolder    = "${IMPACTED_PACKAGE}"
	FixVersionPlaceHolder = "${FIX_VERSION}"
	BranchHashPlaceHolder = "${BRANCH_NAME_HASH}"

	// Default naming templates
	BranchNameTemplate            = "frogbot-" + PackagePlaceHolder + "-" + BranchHashPlaceHolder
	AggregatedBranchNameTemplate  = "frogbot-update-" + BranchHashPlaceHolder + "-dependencies"
	CommitMessageTemplate         = "Upgrade " + PackagePlaceHolder + " to " + FixVersionPlaceHolder
	FrogbotPullRequestTitlePrefix = "[🐸 Frogbot]"
	PullRequestTitleTemplate      = FrogbotPullRequestTitlePrefix + " Update version of " + PackagePlaceHolder + " to " + FixVersionPlaceHolder
	// Frogbot Git author details showed in commits
	frogbotAuthorName  = "JFrog-Frogbot"
	frogbotAuthorEmail = "eco-system+frogbot@jfrog.com"
)

type UnsupportedErrorType string

const (
	IndirectDependencyFixNotSupported   UnsupportedErrorType = "IndirectDependencyFixNotSupported"
	BuildToolsDependencyFixNotSupported UnsupportedErrorType = "BuildToolsDependencyFixNotSupported"
)
