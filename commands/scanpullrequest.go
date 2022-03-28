package commands

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/jfrog/frogbot/commands/utils"
	"github.com/jfrog/froggit-go/vcsclient"
	audit "github.com/jfrog/jfrog-cli-core/v2/xray/commands/audit/generic"
	xrayutils "github.com/jfrog/jfrog-cli-core/v2/xray/utils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	clientLog "github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray/services"
	clitool "github.com/urfave/cli/v2"
)

func ScanPullRequest(c *clitool.Context) error {
	params, client, err := utils.GetParamsAndClient()
	if err != nil {
		return err
	}

	if err = beforeScan(params, client); err != nil {
		return err
	}

	return scanPullRequest(params, client)
}

// Run before scan, to make sure the Xray scan will be run only after adding the frogbot label.
// If label is missing - create the label and do nothing
// If pr isn't labeled - do nothing
// If pr is labeled - remove label and allow running Xray scan (return nil)
// params - Frogbot parameters retreived from the environment variables
// client - The VCS client
func beforeScan(params *utils.FrogbotParams, client vcsclient.VcsClient) error {
	labelInfo, err := client.GetLabel(context.Background(), params.RepoOwner, params.Repo, string(utils.LabelName))
	if err != nil {
		return err
	}
	if labelInfo == nil {
		clientLog.Info("Creating label " + string(utils.LabelName))
		err = client.CreateLabel(context.Background(), params.RepoOwner, params.Repo, vcsclient.LabelInfo{
			Name:        string(utils.LabelName),
			Description: string(utils.LabelDescription),
			Color:       string(utils.LabelColor),
		})
		if err != nil {
			return err
		}
		return utils.ErrLabelCreated
	}

	labels, err := client.ListPullRequestLabels(context.Background(), params.RepoOwner, params.Repo, params.PullRequestID)
	if err != nil {
		return err
	}
	clientLog.Debug("The following labels found in the pull request: ", labels)
	for _, label := range labels {
		if label == string(utils.LabelName) {
			clientLog.Info("Unlabeling '"+utils.LabelName+"' from pull request", params.PullRequestID)
			err = client.UnlabelPullRequest(context.Background(), params.RepoOwner, params.Repo, string(utils.LabelName), params.PullRequestID)
			// Trigger scan or return err
			return err
		}
	}
	return utils.ErrUnlabele
}

// Scan a pull request by auditing the source and the target branches.
// If errors were added in the source branch, print them in a comment.
func scanPullRequest(params *utils.FrogbotParams, client vcsclient.VcsClient) error {
	// Audit PR code
	xrayScanParams := createXrayScanParams(params.Watches, params.Project)
	currentScan, err := auditSource(xrayScanParams, params)
	if err != nil {
		return err
	}

	// Audit target code
	previousScan, err := auditTarget(client, xrayScanParams, params)
	if err != nil {
		return err
	}
	clientLog.Info("Xray scan completed")
	// Get only the new issues added by this PR
	var vulnerabilitiesRows []xrayutils.VulnerabilityRow
	for i := 0; i < len(currentScan); i += 1 {
		if len(currentScan[i].Violations) > 0 {
			vulnerabilitiesRows = append(vulnerabilitiesRows, getNewViolations(previousScan[i], currentScan[i])...)
		} else if len(currentScan[i].Vulnerabilities) > 0 {
			vulnerabilitiesRows = append(vulnerabilitiesRows, getNewVulnerabilities(previousScan[i], currentScan[i])...)
		}
	}
	// Comment frogbot message on the PR
	message := createPullRequestMessage(vulnerabilitiesRows)
	return client.AddPullRequestComment(context.Background(), params.RepoOwner, params.Repo, message, params.PullRequestID)
}

func createXrayScanParams(watches, project string) (params services.XrayGraphScanParams) {
	params.ScanType = services.Dependency
	params.IncludeLicenses = false
	if watches != "" {
		params.Watches = strings.Split(watches, utils.WatchesDelimiter)
		return
	}
	if project != "" {
		params.ProjectKey = project
		return
	}
	// No context was supplied, request from Xray to return all known vulnerabilities.
	params.IncludeVulnerabilities = true
	return
}

func auditSource(xrayScanParams services.XrayGraphScanParams, params *utils.FrogbotParams) ([]services.ScanResponse, error) {
	wd, err := os.Getwd()
	if err != nil {
		return []services.ScanResponse{}, err
	}
	clientLog.Info("Auditing " + wd)
	return runInstallAndAudit(xrayScanParams, params, wd, true)
}

func auditTarget(client vcsclient.VcsClient, xrayScanParams services.XrayGraphScanParams, params *utils.FrogbotParams) (res []services.ScanResponse, err error) {
	clientLog.Info("Auditing " + params.Repo + " " + params.BaseBranch)
	// First download the target repo to temp dir
	tempWorkdir, err := fileutils.CreateTempDir()
	if err != nil {
		return
	}
	clientLog.Debug("Created temp working directory: " + tempWorkdir)
	defer fileutils.RemoveTempDir(tempWorkdir)
	clientLog.Debug(fmt.Sprintf("Downloading %s/%s , branch:%s to:%s", params.RepoOwner, params.Repo, params.BaseBranch, tempWorkdir))
	err = client.DownloadRepository(context.Background(), params.RepoOwner, params.Repo, params.BaseBranch, tempWorkdir)
	if err != nil {
		return
	}
	clientLog.Debug("Downloaded target repository")
	return runInstallAndAudit(xrayScanParams, params, tempWorkdir, false)
}

func runInstallAndAudit(xrayScanParams services.XrayGraphScanParams, params *utils.FrogbotParams, workDir string, failOnInstallationErrors bool) ([]services.ScanResponse, error) {
	restoreDir, err := utils.Chdir(workDir)
	if err != nil {
		return []services.ScanResponse{}, err
	}
	defer restoreDir()
	if params.InstallCommandName != "" {
		clientLog.Info("Executing '"+params.InstallCommandName+"'", params.InstallCommandArgs, "at ", workDir)
		//#nosec G204 -- False positive - the subprocess only run after the user's approval.
		if err = exec.Command(params.InstallCommandName, params.InstallCommandArgs...).Run(); err != nil {
			if failOnInstallationErrors {
				return []services.ScanResponse{}, err
			}
			clientLog.Info("Couldn't run the installation command on the base branch. Assuming new project in the source branch: " + err.Error())
			return []services.ScanResponse{}, nil
		}
	}
	return audit.GenericAudit(xrayScanParams, &params.Server, false, false, false, []string{})
}

func getNewViolations(previousScan, currentScan services.ScanResponse) (newViolationsRows []xrayutils.VulnerabilityRow) {
	existsViolationsMap := make(map[string]xrayutils.VulnerabilityRow)
	violationsRows, _, err := xrayutils.CreateViolationsRows(previousScan.Violations, false, false)
	if err != nil {
		return
	}
	for _, violation := range violationsRows {
		existsViolationsMap[getUniqueID(violation)] = violation
	}
	violationsRows, _, err = xrayutils.CreateViolationsRows(currentScan.Violations, false, false)
	if err != nil {
		return
	}
	for _, violation := range violationsRows {
		if _, exists := existsViolationsMap[getUniqueID(violation)]; !exists {
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
	for _, vulnerability := range vulnerabilitiesRows {
		existsVulnerabilitiesMap[getUniqueID(vulnerability)] = vulnerability
	}
	vulnerabilitiesRows, err = xrayutils.CreateVulnerabilitiesRows(currentScan.Vulnerabilities, false, false)
	if err != nil {
		return
	}
	for _, vulnerability := range vulnerabilitiesRows {
		if _, exists := existsVulnerabilitiesMap[getUniqueID(vulnerability)]; !exists {
			newVulnerabilitiesRows = append(newVulnerabilitiesRows, vulnerability)
		}
	}
	return
}

func getUniqueID(vulnerability xrayutils.VulnerabilityRow) string {
	return vulnerability.ImpactedPackageName + vulnerability.ImpactedPackageVersion + vulnerability.IssueId
}

func createPullRequestMessage(vulnerabilitiesRows []xrayutils.VulnerabilityRow) string {
	if len(vulnerabilitiesRows) == 0 {
		return utils.GetNoVulnerabilitiesBanner()
	}
	tableHeder := "\n| SEVERITY | IMPACTED PACKAGE | IMPACTED PACKAGE  VERSION | FIXED VERSIONS | COMPONENT | COMPONENT VERSION | CVE\n" +
		":--: | -- | -- | -- | -- | :--: | --"
	var tableContent string
	for _, vulnerability := range vulnerabilitiesRows {
		tableContent += fmt.Sprintf("\n| %s | %s | %s | %s | %s | %s | %s ", utils.GetSeverityTag(vulnerability.Severity)+" "+vulnerability.Severity, vulnerability.ImpactedPackageName,
			vulnerability.ImpactedPackageVersion, vulnerability.FixedVersions, vulnerability.Components[0].Name, vulnerability.Components[0].Version, vulnerability.Cves[0].Id)
	}
	return utils.GetVulnerabilitiesBanner() + tableHeder + tableContent
}
