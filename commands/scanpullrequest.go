package commands

import (
	"context"
	"errors"
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
)

const (
	securityIssueFoundErr = "security issues were detected by Frogbot. (You can avoid marking the Frogbot scan as failed by setting JF_FAIL to FALSE)"
)

type ScanPullRequestCmd struct {
}

func (cmd ScanPullRequestCmd) Run(params *utils.FrogbotParams, client vcsclient.VcsClient) error {
	return scanPullRequest(params, client)
}

// By default, JF_INCLUDE_ALL_VULNERABILITIES is set to false and the scan goes as follow:
// a. Audit the dependencies of the source and the target branches.
// b. Compare the vulnerabilities found in source and target branches, and show only the new vulnerabilities added by the pull request.
// Otherwise, only the source branch is scanned and all found vulnerabilities are being displayed.
func scanPullRequest(params *utils.FrogbotParams, client vcsclient.VcsClient) error {
	// Validate scan params
	if params.BaseBranch == "" {
		return &utils.ErrMissingEnv{VariableName: utils.GitBaseBranchEnv}
	}
	// Audit PR code
	xrayScanParams := createXrayScanParams(params.Watches, params.Project)
	clientLog.Info("Auditing pull request")
	currentScan, err := auditSource(xrayScanParams, params)
	if err != nil {
		return err
	}
	var vulnerabilitiesRows []formats.VulnerabilityOrViolationRow
	if params.IncludeAllVulnerabilities {
		clientLog.Info("Frogbot is configured to show all vulnerabilities")
		vulnerabilitiesRows, err = createAllIssuesRows(currentScan)
		if err != nil {
			return err
		}
	} else {
		// Audit base branch
		clientLog.Info("\nAuditing base branch:", params.Repo, params.BaseBranch)
		previousScan, err := auditTarget(client, xrayScanParams, params)
		if err != nil {
			return err
		}
		vulnerabilitiesRows, err = createNewIssuesRows(previousScan, currentScan)
		if err != nil {
			return err
		}
	}
	clientLog.Info("JFrog Xray scan completed")

	// Frogbot adds a comment on the PR.
	getTitleFunc, getSeverityTagFunc := getCommentFunctions(params.SimplifiedOutput)
	message := createPullRequestMessage(vulnerabilitiesRows, getTitleFunc, getSeverityTagFunc)
	err = client.AddPullRequestComment(context.Background(), params.RepoOwner, params.Repo, message, params.PullRequestID)
	if err != nil {
		return errors.New("couldn't add pull request comment: " + err.Error())
	}
	// Fail the Frogbot task, if a security issue is found and Frogbot isn't configured to avoid the failure.
	if params.FailOnSecurityIssues && len(vulnerabilitiesRows) > 0 {
		err = errors.New(securityIssueFoundErr)
	}
	return err
}

func getCommentFunctions(simplifiedOutput bool) (utils.GetTitleFunc, utils.GetSeverityTagFunc) {
	if simplifiedOutput {
		return utils.GetSimplifiedTitle, utils.GetEmojiSeverityTag
	}
	return utils.GetBanner, utils.GetSeverityTag
}

// Create vulnerabilities rows. The rows should contain only the new issues added by this PR
func createNewIssuesRows(previousScan, currentScan []services.ScanResponse) (vulnerabilitiesRows []formats.VulnerabilityOrViolationRow, err error) {
	previousScanAggregatedResults := aggregateScanResults(previousScan)
	currentScanAggregatedResults := aggregateScanResults(currentScan)

	if len(currentScanAggregatedResults.Violations) > 0 {
		newViolations, err := getNewViolations(previousScanAggregatedResults, currentScanAggregatedResults)
		if err != nil {
			return vulnerabilitiesRows, err
		}
		vulnerabilitiesRows = append(vulnerabilitiesRows, newViolations...)
	} else if len(currentScanAggregatedResults.Vulnerabilities) > 0 {
		newVulnerabilities, err := getNewVulnerabilities(previousScanAggregatedResults, currentScanAggregatedResults)
		if err != nil {
			return vulnerabilitiesRows, err
		}
		vulnerabilitiesRows = append(vulnerabilitiesRows, newVulnerabilities...)
	}

	return vulnerabilitiesRows, nil
}

func aggregateScanResults(scanResults []services.ScanResponse) services.ScanResponse {
	aggregateResults := services.ScanResponse{
		Violations:      []services.Violation{},
		Vulnerabilities: []services.Vulnerability{},
	}
	for _, scanResult := range scanResults {
		aggregateResults.Violations = append(aggregateResults.Violations, scanResult.Violations...)
		aggregateResults.Vulnerabilities = append(aggregateResults.Vulnerabilities, scanResult.Vulnerabilities...)
	}
	return aggregateResults
}

// Create vulnerabilities rows. The rows should contain All the issues that were found in this module scan.
func getScanVulnerabilitiesRows(currentScan services.ScanResponse) ([]formats.VulnerabilityOrViolationRow, error) {
	if len(currentScan.Violations) > 0 {
		violationsRows, _, _, err := xrayutils.PrepareViolations(currentScan.Violations, false)
		return violationsRows, err
	} else if len(currentScan.Vulnerabilities) > 0 {
		return xrayutils.PrepareVulnerabilities(currentScan.Vulnerabilities, false)
	}
	return []formats.VulnerabilityOrViolationRow{}, nil
}

// Create vulnerabilities rows. The rows should contain All the issues that were found in this PR
func createAllIssuesRows(currentScan []services.ScanResponse) ([]formats.VulnerabilityOrViolationRow, error) {
	var vulnerabilitiesRows []formats.VulnerabilityOrViolationRow
	for i := 0; i < len(currentScan); i += 1 {
		newVulnerabilitiesRows, err := getScanVulnerabilitiesRows(currentScan[i])
		if err != nil {
			return vulnerabilitiesRows, err
		}
		vulnerabilitiesRows = append(vulnerabilitiesRows, newVulnerabilitiesRows...)
	}
	return vulnerabilitiesRows, nil
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
	clientLog.Info("Working directory:", wd)
	return runInstallAndAudit(xrayScanParams, params, wd, true)
}

func auditTarget(client vcsclient.VcsClient, xrayScanParams services.XrayGraphScanParams, params *utils.FrogbotParams) (res []services.ScanResponse, err error) {
	// First download the target repo to temp dir
	wd, cleanup, err := downloadRepoToTempDir(client, params)
	if err != nil {
		return
	}
	// Cleanup
	defer func() {
		e := cleanup()
		if err == nil {
			err = e
		}
	}()
	return runInstallAndAudit(xrayScanParams, params, wd, false)
}

func downloadRepoToTempDir(client vcsclient.VcsClient, params *utils.FrogbotParams) (wd string, cleanup func() error, err error) {
	wd, err = fileutils.CreateTempDir()
	if err != nil {
		return
	}
	cleanup = func() error {
		e := fileutils.RemoveTempDir(wd)
		return e
	}
	clientLog.Debug("Created temp working directory:", wd)
	clientLog.Debug(fmt.Sprintf("Downloading %s/%s from branch:<%s>", params.RepoOwner, params.Repo, params.BaseBranch))
	err = client.DownloadRepository(context.Background(), params.RepoOwner, params.Repo, params.BaseBranch, wd)
	if err != nil {
		return
	}
	clientLog.Debug("Downloading repository completed")
	if params.WorkingDirectory != "" {
		wd = filepath.Join(wd, params.WorkingDirectory)
	}
	return
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
	results, _, err = audit.GenericAudit(xrayScanParams,
		&params.Server,
		false,
		false,
		false,
		nil,
		nil,
		params.RequirementsFile,
		true,
		[]string{})
	return
}

func runInstallIfNeeded(params *utils.FrogbotParams, workDir string, failOnInstallationErrors bool) error {
	if params.InstallCommandName == "" {
		return nil
	}
	clientLog.Info(fmt.Sprintf("Executing '%s %s' at %s", params.InstallCommandName, strings.Join(params.InstallCommandArgs, " "), workDir))
	//#nosec G204 -- False positive - the subprocess only run after the user's approval.
	output, err := exec.Command(params.InstallCommandName, params.InstallCommandArgs...).CombinedOutput() // #nosec G204
	if err != nil {
		err = fmt.Errorf("'%s %s' command failed: %s - %s", params.InstallCommandName, strings.Join(params.InstallCommandArgs, " "), err.Error(), output)
		if failOnInstallationErrors {
			return err
		}
		clientLog.Info("Couldn't run the installation command on the base branch. Assuming new project in the source branch: " + err.Error())
	}
	return nil
}

func getNewViolations(previousScan, currentScan services.ScanResponse) (newViolationsRows []formats.VulnerabilityOrViolationRow, err error) {
	existsViolationsMap := make(map[string]formats.VulnerabilityOrViolationRow)
	violationsRows, _, _, err := xrayutils.PrepareViolations(previousScan.Violations, false)
	if err != nil {
		return violationsRows, err
	}
	for _, violation := range violationsRows {
		existsViolationsMap[getUniqueID(violation)] = violation
	}
	violationsRows, _, _, err = xrayutils.PrepareViolations(currentScan.Violations, false)
	if err != nil {
		return newViolationsRows, err
	}
	for _, violation := range violationsRows {
		if _, exists := existsViolationsMap[getUniqueID(violation)]; !exists {
			newViolationsRows = append(newViolationsRows, violation)
		}
	}
	return
}

func getNewVulnerabilities(previousScan, currentScan services.ScanResponse) (newVulnerabilitiesRows []formats.VulnerabilityOrViolationRow, err error) {
	existsVulnerabilitiesMap := make(map[string]formats.VulnerabilityOrViolationRow)
	vulnerabilitiesRows, err := xrayutils.PrepareVulnerabilities(previousScan.Vulnerabilities, false)
	if err != nil {
		return newVulnerabilitiesRows, err
	}
	for _, vulnerability := range vulnerabilitiesRows {
		existsVulnerabilitiesMap[getUniqueID(vulnerability)] = vulnerability
	}
	vulnerabilitiesRows, err = xrayutils.PrepareVulnerabilities(currentScan.Vulnerabilities, false)
	if err != nil {
		return newVulnerabilitiesRows, err
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

func createPullRequestMessage(vulnerabilitiesRows []formats.VulnerabilityOrViolationRow, getBanner utils.GetTitleFunc, getSeverityTag utils.GetSeverityTagFunc) string {
	if len(vulnerabilitiesRows) == 0 {
		return getBanner(utils.NoVulnerabilityBannerSource) + utils.WhatIsFrogbotMd
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
		tableContent += fmt.Sprintf("\n| %s%8s | %s | %s | %s | %s | %s | %s ", getSeverityTag(utils.IconName(vulnerability.Severity)), vulnerability.Severity, vulnerability.ImpactedPackageName,
			vulnerability.ImpactedPackageVersion, fixedVersionString, componentName, componentVersion, cve)
	}
	return getBanner(utils.VulnerabilitiesBannerSource) + utils.WhatIsFrogbotMd + utils.TableHeader + tableContent
}
