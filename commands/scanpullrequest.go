package commands

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/jfrog/frogbot/commands/utils"
	"github.com/jfrog/froggit-go/vcsclient"
	audit "github.com/jfrog/jfrog-cli-core/v2/xray/commands/audit/generic"
	"github.com/jfrog/jfrog-cli-core/v2/xray/formats"
	xrayutils "github.com/jfrog/jfrog-cli-core/v2/xray/utils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	clientLog "github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray/services"
	clitool "github.com/urfave/cli/v2"
)

func ScanPullRequest(c *clitool.Context) error {
	// Get params and VCS client
	params, client, err := utils.GetParamsAndClient()
	if err != nil {
		return err
	}
	// Send usage report
	usageReportSent := make(chan error)
	go utils.ReportUsage(c.Command.Name, &params.Server, usageReportSent)

	// Do scan pull request
	err = scanPullRequest(params, client)

	// Wait for usage report
	<-usageReportSent
	return err
}

// Scan a pull request by as follows:
// a. Audit the dependencies of the source and the target branches.
// b. Compare the vulnerabilities found in source and target branches, and show only the new vulnerabilities added by the pull request.
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

	// Comment frogbot message on the PR
	message := createPullRequestMessage(createVulnerabilitiesRows(previousScan, currentScan))
	return client.AddPullRequestComment(context.Background(), params.RepoOwner, params.Repo, message, params.PullRequestID)
}

// Create vulnerabilities rows. The rows should contain only the new issues added by this PR
func createVulnerabilitiesRows(previousScan, currentScan []services.ScanResponse) []formats.VulnerabilityOrViolationRow {
	var vulnerabilitiesRows []formats.VulnerabilityOrViolationRow
	for i := 0; i < len(currentScan); i += 1 {
		if len(currentScan[i].Violations) > 0 {
			vulnerabilitiesRows = append(vulnerabilitiesRows, getNewViolations(previousScan[i], currentScan[i])...)
		} else if len(currentScan[i].Vulnerabilities) > 0 {
			vulnerabilitiesRows = append(vulnerabilitiesRows, getNewVulnerabilities(previousScan[i], currentScan[i])...)
		}
	}
	return vulnerabilitiesRows
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
	if params.WorkingDirectory != "" {
		wd = filepath.Join(wd, params.WorkingDirectory)
	}
	clientLog.Info("Auditing " + wd)
	return runInstallAndAudit(xrayScanParams, params, wd, true)
}

func auditTarget(client vcsclient.VcsClient, xrayScanParams services.XrayGraphScanParams, params *utils.FrogbotParams) (res []services.ScanResponse, err error) {
	clientLog.Info("Auditing " + params.Repo + " " + params.BaseBranch)
	// First download the target repo to temp dir
	wd, err := fileutils.CreateTempDir()
	if err != nil {
		return
	}
	clientLog.Debug("Created temp working directory: " + wd)
	defer func() {
		e := fileutils.RemoveTempDir(wd)
		if err == nil {
			err = e
		}
	}()
	clientLog.Debug(fmt.Sprintf("Downloading %s/%s , branch:%s to:%s", params.RepoOwner, params.Repo, params.BaseBranch, wd))
	err = client.DownloadRepository(context.Background(), params.RepoOwner, params.Repo, params.BaseBranch, wd)
	if err != nil {
		return
	}
	clientLog.Debug("Downloaded target repository")
	if params.WorkingDirectory != "" {
		wd = filepath.Join(wd, params.WorkingDirectory)
	}
	return runInstallAndAudit(xrayScanParams, params, wd, false)
}

func runInstallAndAudit(xrayScanParams services.XrayGraphScanParams, params *utils.FrogbotParams, workDir string, failOnInstallationErrors bool) (results []services.ScanResponse, err error) {
	restoreDir, err := utils.Chdir(workDir)
	if err != nil {
		return
	}
	defer func() {
		e := restoreDir()
		if err == nil {
			err = e
		}
	}()
	if err = runInstallIfNeeded(params, workDir, failOnInstallationErrors); err != nil {
		return
	}
	results, _, err = audit.GenericAudit(xrayScanParams, &params.Server, false, false, false, []string{})
	return
}

func runInstallIfNeeded(params *utils.FrogbotParams, workDir string, failOnInstallationErrors bool) error {
	if params.InstallCommandName == "" {
		return nil
	}
	clientLog.Info("Executing '"+params.InstallCommandName+"'", params.InstallCommandArgs, "at ", workDir)
	//#nosec G204 -- False positive - the subprocess only run after the user's approval.
	if err := exec.Command(params.InstallCommandName, params.InstallCommandArgs...).Run(); err != nil {
		if failOnInstallationErrors {
			return err
		}
		clientLog.Info("Couldn't run the installation command on the base branch. Assuming new project in the source branch: " + err.Error())
		return nil
	}
	return nil
}

func getNewViolations(previousScan, currentScan services.ScanResponse) (newViolationsRows []formats.VulnerabilityOrViolationRow) {
	existsViolationsMap := make(map[string]formats.VulnerabilityOrViolationRow)
	violationsRows, _, _, err := xrayutils.PrepareViolations(previousScan.Violations, false, false)
	if err != nil {
		return
	}
	for _, violation := range violationsRows {
		existsViolationsMap[getUniqueID(violation)] = violation
	}
	violationsRows, _, _, err = xrayutils.PrepareViolations(currentScan.Violations, false, false)
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

func getNewVulnerabilities(previousScan, currentScan services.ScanResponse) (newVulnerabilitiesRows []formats.VulnerabilityOrViolationRow) {
	existsVulnerabilitiesMap := make(map[string]formats.VulnerabilityOrViolationRow)
	vulnerabilitiesRows, err := xrayutils.PrepareVulnerabilities(previousScan.Vulnerabilities, false, false)
	if err != nil {
		return
	}
	for _, vulnerability := range vulnerabilitiesRows {
		existsVulnerabilitiesMap[getUniqueID(vulnerability)] = vulnerability
	}
	vulnerabilitiesRows, err = xrayutils.PrepareVulnerabilities(currentScan.Vulnerabilities, false, false)
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

func getUniqueID(vulnerability formats.VulnerabilityOrViolationRow) string {
	return vulnerability.ImpactedPackageName + vulnerability.ImpactedPackageVersion + vulnerability.IssueId
}

func createPullRequestMessage(vulnerabilitiesRows []formats.VulnerabilityOrViolationRow) string {
	if len(vulnerabilitiesRows) == 0 {
		return utils.GetBanner(utils.NoVulnerabilityBannerSource) + utils.WhatIsFrogbotMd
	}
	var tableContent string
	for _, vulnerability := range vulnerabilitiesRows {
		var componentName, componentVersion, cve string
		if len(vulnerability.Components) > 0 {
			componentName = vulnerability.Components[0].Name
			componentVersion = vulnerability.Components[0].Version
		}
		if len(vulnerability.Cves) > 0 {
			cve = vulnerability.Cves[0].Id
		}
		fixedVersionString := strings.Join(vulnerability.FixedVersions, " ")
		tableContent += fmt.Sprintf("\n| %s<br>%8s | %s | %s | %s | %s | %s | %s ", utils.GetSeverityTag(utils.IconName(vulnerability.Severity)), vulnerability.Severity, vulnerability.ImpactedPackageName,
			vulnerability.ImpactedPackageVersion, fixedVersionString, componentName, componentVersion, cve)
	}
	return utils.GetBanner(utils.VulnerabilitiesBannerSource) + utils.WhatIsFrogbotMd + utils.TableHeader + tableContent
}
