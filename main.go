package main

import (
	"context"
	"fmt"
	"os"
	"path"
	"strconv"

	"github.com/jfrog/frogbot/icons"
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/froggit-go/vcsutils"
	coreconfig "github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/log"
	audit "github.com/jfrog/jfrog-cli-core/v2/xray/commands/audit/generic"
	xrayutils "github.com/jfrog/jfrog-cli-core/v2/xray/utils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	clientLog "github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray/services"
	clitool "github.com/urfave/cli/v2"
)

const (
	frogbotVersion = "0.0.0"
	// Env
	jfrogUser           = "FROGBOT_JF_USER"
	jfrogUrl            = "FROGBOT_JF_URL"
	jfrogXrayUrl        = "FROGBOT_JF_XRAY_URL"
	jfrogArtifactoryUrl = "FROGBOT_JF_ARTIFACTORY_URL"
	jfrogPassword       = "FROGBOT_JF_PASSWORD"
	jfrogToken          = "FROGBOT_JF_TOKEN"
	gitRepoOwner        = "FROGBOT_GIT_OWNER"
	gitRepo             = "FROGBOT_GIT_REPO"
	gitToken            = "FROGBOT_GIT_TOKEN"
	gitBaseBranch       = "FROGBOT_GIT_BASE_BRANCH"
	prID                = "FROGBOT_PR"
)

func main() {
	log.SetDefaultLogger()
	err := execMain()
	if cleanupErr := fileutils.CleanOldDirs(); cleanupErr != nil {
		clientLog.Warn(cleanupErr)
	}
	coreutils.ExitOnErr(err)
}

func execMain() error {

	app := clitool.App{
		Name:     "Frogbot",
		Usage:    "See https://github.com/jfrog/frogbot for usage instructions.",
		Commands: getCommands(),
		Version:  frogbotVersion,
	}

	err := app.Run(os.Args)
	return err
}

func getCommands() []*clitool.Command {
	return []*clitool.Command{
		{
			Name:     "scan-pull-request",
			HideHelp: true,
			Hidden:   true,
			Action:   scanPullRequest,
		},
	}
}

func scanPullRequest(c *clitool.Context) error {
	server, repoOwner, token, repo, baseBranch, pullRequestID, err := extractParamsFromEnv()
	if err != nil {
		return err
	}
	client, err := vcsclient.NewClientBuilder(vcsutils.GitHub).Token(token).Build()
	if err != nil {
		return err
	}

	// Audit PR code
	// TODO - fill contex according to env/flags
	xrayScanParams := services.XrayGraphScanParams{IncludeVulnerabilities: true}
	wd, err := os.Getwd()
	if err != nil {
		return err
	}
	clientLog.Info("Auditing " + wd)
	currentScan, err := runAudit(xrayScanParams, &server, wd)
	if err != nil {
		return err
	}
	// Audit target code
	clientLog.Info("Auditing " + repo + " " + baseBranch)
	previousScan, err := auditTarget(client, xrayScanParams, &server, repoOwner, repo, baseBranch)
	if err != nil {
		return err
	}
	// Get only the new issues added by this PR
	var vulnerabilitiesRows []xrayutils.VulnerabilityRow
	// TODO - handle array of scan results!
	if len(currentScan[0].Violations) > 0 {
		vulnerabilitiesRows = getNewViolations(previousScan[0], currentScan[0])
	} else if len(currentScan[0].Vulnerabilities) > 0 {
		vulnerabilitiesRows = getNewVulnerabilities(previousScan[0], currentScan[0])
	}
	// Comment frogbot message on the PR
	message := createPullRequestMessage(vulnerabilitiesRows)
	return client.AddPullRequestComment(context.Background(), repoOwner, repo, message, pullRequestID)

}

func extractParamsFromEnv() (server coreconfig.ServerDetails, repoOwner, token, repo, baseBranch string, pullRequestID int, err error) {
	url := os.Getenv(jfrogUrl)
	xrUrl := os.Getenv(jfrogXrayUrl)
	rtUrl := os.Getenv(jfrogArtifactoryUrl)
	if xrUrl != "" && rtUrl != "" {
		server.XrayUrl = xrUrl
		server.ArtifactoryUrl = rtUrl
	} else {
		if url == "" {
			err = fmt.Errorf("%s or %s and %s are missing", url, xrUrl, rtUrl)
			return
		}
		server.Url = url
		server.XrayUrl = url + "/xray/"
		server.ArtifactoryUrl = path.Join(url, "artifactory") + "/"
	}

	password := os.Getenv(jfrogPassword)
	user := os.Getenv(jfrogUser)
	if password != "" && user != "" {
		server.User = user
		server.Password = password
	} else if accessToken := os.Getenv(jfrogToken); accessToken != "" {
		server.AccessToken = accessToken
	} else {
		err = fmt.Errorf("%s and %s or %s are missing", jfrogUser, jfrogPassword, jfrogToken)
		return
	}
	if repoOwner = os.Getenv(gitRepoOwner); repoOwner == "" {
		err = fmt.Errorf("%s is missing", gitRepoOwner)
		return
	}
	if repo = os.Getenv(gitRepo); repo == "" {
		err = fmt.Errorf("%s is missing", gitRepo)
		return
	}
	if token = os.Getenv(gitToken); token == "" {
		err = fmt.Errorf("%s is missing", gitToken)
		return
	}
	if baseBranch = os.Getenv(gitBaseBranch); baseBranch == "" {
		err = fmt.Errorf("%s is missing", gitBaseBranch)
		return
	}
	pullRequestIDString := os.Getenv(prID)
	if pullRequestIDString == "" {
		err = fmt.Errorf("%s is missing", prID)
		return
	}
	pullRequestID, err = strconv.Atoi(pullRequestIDString)
	if err != nil {
		return
	}
	return
}

func runAudit(xrayScanParams services.XrayGraphScanParams, server *coreconfig.ServerDetails, workDir string) (res []services.ScanResponse, err error) {
	wd, err := os.Getwd()
	if err != nil {
		return
	}
	err = os.Chdir(workDir)
	if err != nil {
		return
	}
	defer func(originDir string) {
		e := os.Chdir(originDir)
		if err == nil {
			err = e
		}
	}(wd)
	// TODO - handle audit params better
	return audit.GenericAudit(xrayScanParams, server, false, false, false, []string{})
}

func auditTarget(client vcsclient.VcsClient, xrayScanParams services.XrayGraphScanParams, server *coreconfig.ServerDetails, owner, repo, branch string) (res []services.ScanResponse, err error) {
	// First download the target repo to temp dir
	tempWorkdir, err := fileutils.CreateTempDir()
	if err != nil {
		return
	}
	clientLog.Debug("Created temp working directory: " + tempWorkdir)
	defer fileutils.RemoveTempDir(tempWorkdir)
	clientLog.Debug(fmt.Sprintf("Downloading %s/%s , branch:%s to:%s", owner, repo, branch, tempWorkdir))
	err = client.DownloadRepository(context.Background(), owner, repo, branch, tempWorkdir)
	if err != nil {
		return
	}
	clientLog.Debug("Downloaded target repository")
	return runAudit(xrayScanParams, server, tempWorkdir)
}

func getNewViolations(previousScan, currentScan services.ScanResponse) (newViolationsRows []xrayutils.VulnerabilityRow) {
	existsViolationsMap := make(map[string]xrayutils.VulnerabilityRow)
	violationsRows, _, err := xrayutils.CreateViolationsRows(previousScan.Violations, false, false)
	if err != nil {
		return
	}
	for _, violation := range violationsRows {
		existsViolationsMap[GetUniqueID(violation)] = violation
	}
	violationsRows, _, err = xrayutils.CreateViolationsRows(currentScan.Violations, false, false)
	if err != nil {
		return
	}
	for _, violation := range violationsRows {
		if _, exists := existsViolationsMap[GetUniqueID(violation)]; !exists {
			newViolationsRows = append(newViolationsRows, violation)
		}
	}
	return
}

func getNewVulnerabilities(previousScan, currentScan services.ScanResponse) (newVulnerabilitiesRows []xrayutils.VulnerabilityRow) {
	existsVulnerabilitiesMap := make(map[string]xrayutils.VulnerabilityRow)
	vulnerabilitiesRows, err := xrayutils.CreateVulnerabilitiesRows(previousScan.Vulnerabilities, false, false)
	if err != nil {
		return
	}
	for i, vulnerability := range vulnerabilitiesRows {
		clientLog.Debug("Prev #:" + strconv.FormatInt(int64(i), 10) + GetUniqueID(vulnerability))
		existsVulnerabilitiesMap[GetUniqueID(vulnerability)] = vulnerability
	}
	vulnerabilitiesRows, err = xrayutils.CreateVulnerabilitiesRows(currentScan.Vulnerabilities, false, false)
	if err != nil {
		return
	}
	for i, vulnerability := range vulnerabilitiesRows {
		clientLog.Debug("new #:" + strconv.FormatInt(int64(i), 10) + GetUniqueID(vulnerability))
		if _, exists := existsVulnerabilitiesMap[GetUniqueID(vulnerability)]; !exists {
			clientLog.Debug(GetUniqueID(vulnerability))
			newVulnerabilitiesRows = append(newVulnerabilitiesRows, vulnerability)
		}
	}
	return

}

func GetUniqueID(vulnerability xrayutils.VulnerabilityRow) string {
	return vulnerability.ImpactedPackageName + vulnerability.ImpactedPackageVersion + vulnerability.IssueId

}

func createPullRequestMessage(vulnerabilitiesRows []xrayutils.VulnerabilityRow) string {
	if len(vulnerabilitiesRows) == 0 {
		return icons.GetIconTag(icons.NoVulnerabilityBannerSource)
	}
	tableHeder := "\n| SEVERITY | IMPACTED PACKAGE | IMPACTED PACKAGE  VERSION | FIXED VERSIONS | COMPONENT | COMPONENT VERSION | CVE\n" +
		":--: | -- | -- | -- | -- | :--: | --"
	var tableContent string
	for _, vulnerability := range vulnerabilitiesRows {
		tableContent += fmt.Sprintf("\n| %s | %s | %s | %s | %s | %s | %s ", icons.GetIconTag(icons.GetIconSource(vulnerability.Severity)), vulnerability.ImpactedPackageName,
			vulnerability.ImpactedPackageVersion, vulnerability.FixedVersions, vulnerability.Components[0].Name, vulnerability.Components[0].Version, vulnerability.Cves[0].Id)
	}
	return icons.GetIconTag(icons.VulnerabilitiesBannerSource) + tableHeder + tableContent
}

func commentPullRequestGithub(client vcsclient.VcsClient, owner, repository, content string) error {

	return client.AddPullRequestComment(context.Background(), owner, repository, content, 1)
}
