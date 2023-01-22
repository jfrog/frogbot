package commands

import (
	"context"
	"errors"
	"fmt"
	coreconfig "github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/jfrog/frogbot/commands/utils"
	"github.com/jfrog/froggit-go/vcsclient"
	audit "github.com/jfrog/jfrog-cli-core/v2/xray/commands/audit/generic"
	"github.com/jfrog/jfrog-cli-core/v2/xray/formats"
	xrayutils "github.com/jfrog/jfrog-cli-core/v2/xray/utils"
	clientLog "github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray/services"
)

const (
	securityIssueFoundErr    = "issues were detected by Frogbot\n You can avoid marking the Frogbot scan as failed by setting failOnSecurityIssues to false in the " + utils.FrogbotConfigFile + " file"
	installationCmdFailedErr = "Couldn't run the installation command on the base branch. Assuming new project in the source branch: "
)

type ScanPullRequestCmd struct {
}

// Run ScanPullRequest method only works for single repository scan.
// Therefore, the first repository config represents the repository on which Frogbot runs, and it is the only one that matters.
func (cmd ScanPullRequestCmd) Run(configAggregator utils.FrogbotConfigAggregator, client vcsclient.VcsClient) error {
	if err := utils.ValidateSingleRepoConfiguration(&configAggregator); err != nil {
		return err
	}
	return scanPullRequest(&(configAggregator)[0], client)
}

// By default, includeAllVulnerabilities is set to false and the scan goes as follows:
// a. Audit the dependencies of the source and the target branches.
// b. Compare the vulnerabilities found in source and target branches, and show only the new vulnerabilities added by the pull request.
// Otherwise, only the source branch is scanned and all found vulnerabilities are being displayed.
func scanPullRequest(repoConfig *utils.FrogbotRepoConfig, client vcsclient.VcsClient) error {
	// Validate scan params
	if len(repoConfig.Branches) == 0 {
		return &utils.ErrMissingEnv{VariableName: utils.GitBaseBranchEnv}
	}
	// Audit PR code
	xrayScanParams := createXrayScanParams(repoConfig.Watches, repoConfig.JFrogProjectKey)
	var vulnerabilitiesRows []formats.VulnerabilityOrViolationRow
	for _, project := range repoConfig.Projects {
		currentScan, isMultipleRoot, err := auditSource(xrayScanParams, project, &repoConfig.Server)
		if err != nil {
			return err
		}
		if repoConfig.IncludeAllVulnerabilities {
			clientLog.Info("Frogbot is configured to show all vulnerabilities")
			allIssuesRows, err := createAllIssuesRows(currentScan, isMultipleRoot)
			if err != nil {
				return err
			}
			vulnerabilitiesRows = append(vulnerabilitiesRows, allIssuesRows...)
			continue
		}
		// Audit target code
		previousScan, isMultipleRoot, err := auditTarget(client, xrayScanParams, project, repoConfig.Branches[0], &repoConfig.Git, &repoConfig.Server)
		if err != nil {
			return err
		}
		newIssuesRows, err := createNewIssuesRows(previousScan, currentScan, isMultipleRoot)
		if err != nil {
			return err
		}
		vulnerabilitiesRows = append(vulnerabilitiesRows, newIssuesRows...)
	}

	clientLog.Info("Xray scan completed")

	// Frogbot adds a comment on the PR.
	getTitleFunc, getSeverityTagFunc := getCommentFunctions(repoConfig.SimplifiedOutput)
	message := createPullRequestMessage(vulnerabilitiesRows, getTitleFunc, getSeverityTagFunc)
	err := client.AddPullRequestComment(context.Background(), repoConfig.RepoOwner, repoConfig.RepoName, message, repoConfig.PullRequestID)
	if err != nil {
		return errors.New("couldn't add pull request comment: " + err.Error())
	}
	// Fail the Frogbot task, if a security issue is found and Frogbot isn't configured to avoid the failure.
	if repoConfig.FailOnSecurityIssues != nil && *repoConfig.FailOnSecurityIssues && len(vulnerabilitiesRows) > 0 {
		err = errors.New(securityIssueFoundErr)
	}
	return err
}

func getCommentFunctions(simplifiedOutput bool) (utils.GetTitleFunc, utils.GetSeverityTagFunc) {
	if simplifiedOutput {
		return utils.GetSimplifiedTitle, func(name utils.IconName) string {
			return ""
		}
	}
	return utils.GetBanner, utils.GetSeverityTag
}

// Create vulnerabilities rows. The rows should contain only the new issues added by this PR
func createNewIssuesRows(previousScan, currentScan []services.ScanResponse, isMultipleRoot bool) (vulnerabilitiesRows []formats.VulnerabilityOrViolationRow, err error) {
	previousScanAggregatedResults := aggregateScanResults(previousScan)
	currentScanAggregatedResults := aggregateScanResults(currentScan)

	if len(currentScanAggregatedResults.Violations) > 0 {
		newViolations, err := getNewViolations(previousScanAggregatedResults, currentScanAggregatedResults, isMultipleRoot)
		if err != nil {
			return vulnerabilitiesRows, err
		}
		vulnerabilitiesRows = append(vulnerabilitiesRows, newViolations...)
	} else if len(currentScanAggregatedResults.Vulnerabilities) > 0 {
		newVulnerabilities, err := getNewVulnerabilities(previousScanAggregatedResults, currentScanAggregatedResults, isMultipleRoot)
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

// Create vulnerabilities rows. The rows should contain all the issues that were found in this module scan.
func getScanVulnerabilitiesRows(violations []services.Violation, vulnerabilities []services.Vulnerability, isMultipleRoot bool) ([]formats.VulnerabilityOrViolationRow, error) {
	if len(violations) > 0 {
		violationsRows, _, _, err := xrayutils.PrepareViolations(violations, isMultipleRoot, true)
		return violationsRows, err
	}
	if len(vulnerabilities) > 0 {
		return xrayutils.PrepareVulnerabilities(vulnerabilities, isMultipleRoot, true)
	}
	return []formats.VulnerabilityOrViolationRow{}, nil
}

// Create vulnerabilities rows. The rows should contain all the issues that were found in this PR
func createAllIssuesRows(currentScan []services.ScanResponse, isMultipleRoot bool) ([]formats.VulnerabilityOrViolationRow, error) {
	violations, vulnerabilities, _ := xrayutils.SplitScanResults(currentScan)
	return getScanVulnerabilitiesRows(violations, vulnerabilities, isMultipleRoot)
}

func createXrayScanParams(watches []string, project string) (params services.XrayGraphScanParams) {
	params.ScanType = services.Dependency
	params.IncludeLicenses = false
	if len(watches) > 0 {
		params.Watches = watches
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

func auditSource(xrayScanParams services.XrayGraphScanParams, project utils.Project, server *coreconfig.ServerDetails) ([]services.ScanResponse, bool, error) {
	wd, err := os.Getwd()
	if err != nil {
		return []services.ScanResponse{}, false, err
	}
	fullPathWds := getFullPathWorkingDirs(&project, wd)
	return runInstallAndAudit(xrayScanParams, &project, server, true, fullPathWds...)
}

func getFullPathWorkingDirs(project *utils.Project, baseWd string) []string {
	var fullPathWds []string
	if len(project.WorkingDirs) != 0 {
		for _, workDir := range project.WorkingDirs {
			if workDir == utils.RootDir {
				fullPathWds = append(fullPathWds, baseWd)
				continue
			}
			fullPathWds = append(fullPathWds, filepath.Join(baseWd, workDir))
		}
	} else {
		fullPathWds = append(fullPathWds, baseWd)
	}
	return fullPathWds
}

func auditTarget(client vcsclient.VcsClient, xrayScanParams services.XrayGraphScanParams, project utils.Project, branch string, git *utils.Git, server *coreconfig.ServerDetails) (res []services.ScanResponse, isMultipleRoot bool, err error) {
	// First download the target repo to temp dir
	clientLog.Info("Auditing " + git.RepoName + " " + branch)
	wd, cleanup, err := utils.DownloadRepoToTempDir(client, branch, git)
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
	fullPathWds := getFullPathWorkingDirs(&project, wd)
	return runInstallAndAudit(xrayScanParams, &project, server, false, fullPathWds...)
}

func runInstallAndAudit(xrayScanParams services.XrayGraphScanParams, project *utils.Project, server *coreconfig.ServerDetails, failOnInstallationErrors bool, workDirs ...string) (results []services.ScanResponse, isMultipleRoot bool, err error) {
	for _, wd := range workDirs {
		if err = runInstallIfNeeded(project, wd, failOnInstallationErrors); err != nil {
			return nil, false, err
		}
	}

	results, isMultipleRoot, err = audit.GenericAudit(xrayScanParams, server, false, project.UseWrapper, false,
		nil, nil, project.PipRequirementsFile, false, workDirs, []string{}...)
	if err != nil {
		return nil, false, err
	}
	return results, isMultipleRoot, err
}

func runInstallIfNeeded(project *utils.Project, workDir string, failOnInstallationErrors bool) (err error) {
	if project.InstallCommandName == "" {
		return nil
	}
	restoreDir, err := utils.Chdir(workDir)
	defer func() {
		restoreErr := restoreDir()
		if err == nil {
			err = restoreErr
		}
	}()
	clientLog.Info("Executing", "'"+project.InstallCommandName+"'", project.InstallCommandArgs, "at", workDir)
	//#nosec G204 -- False positive - the subprocess only run after the user's approval.
	if err = exec.Command(project.InstallCommandName, project.InstallCommandArgs...).Run(); err != nil {
		if failOnInstallationErrors {
			return err
		}
		clientLog.Info(installationCmdFailedErr, err.Error())
		// failOnInstallationErrors set to 'false'
		err = nil
	}
	return
}

func getNewViolations(previousScan, currentScan services.ScanResponse, isMultipleRoot bool) (newViolationsRows []formats.VulnerabilityOrViolationRow, err error) {
	existsViolationsMap := make(map[string]formats.VulnerabilityOrViolationRow)
	violationsRows, _, _, err := xrayutils.PrepareViolations(previousScan.Violations, isMultipleRoot, true)
	if err != nil {
		return violationsRows, err
	}
	for _, violation := range violationsRows {
		existsViolationsMap[getUniqueID(violation)] = violation
	}
	violationsRows, _, _, err = xrayutils.PrepareViolations(currentScan.Violations, isMultipleRoot, true)
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

func getNewVulnerabilities(previousScan, currentScan services.ScanResponse, isMultipleRoot bool) (newVulnerabilitiesRows []formats.VulnerabilityOrViolationRow, err error) {
	existsVulnerabilitiesMap := make(map[string]formats.VulnerabilityOrViolationRow)
	vulnerabilitiesRows, err := xrayutils.PrepareVulnerabilities(previousScan.Vulnerabilities, isMultipleRoot, true)
	if err != nil {
		return newVulnerabilitiesRows, err
	}
	for _, vulnerability := range vulnerabilitiesRows {
		existsVulnerabilitiesMap[getUniqueID(vulnerability)] = vulnerability
	}
	vulnerabilitiesRows, err = xrayutils.PrepareVulnerabilities(currentScan.Vulnerabilities, isMultipleRoot, true)
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
		var cve string
		var directDependencies, directDependenciesVersions strings.Builder
		if len(vulnerability.Components) > 0 {
			for _, dependency := range vulnerability.Components {
				directDependencies.WriteString(fmt.Sprintf("%s; ", dependency.Name))
				directDependenciesVersions.WriteString(fmt.Sprintf("%s; ", dependency.Version))
			}
		}
		if len(vulnerability.Cves) > 0 {
			cve = vulnerability.Cves[0].Id
		}
		fixedVersionString := strings.Join(vulnerability.FixedVersions, " ")
		tableContent += fmt.Sprintf("\n| %s%8s | %s | %s | %s | %s | %s | %s ",
			getSeverityTag(utils.IconName(vulnerability.Severity)),
			vulnerability.Severity,
			strings.TrimSuffix(directDependencies.String(), "; "),
			strings.TrimSuffix(directDependenciesVersions.String(), "; "),
			vulnerability.ImpactedPackageName,
			vulnerability.ImpactedPackageVersion,
			fixedVersionString,
			cve)
	}
	return getBanner(utils.VulnerabilitiesBannerSource) + utils.WhatIsFrogbotMd + utils.TableHeader + tableContent
}
