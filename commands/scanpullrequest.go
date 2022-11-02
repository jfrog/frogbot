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
	securityIssueFoundErr = "issues were detected by Frogbot\n You can avoid marking the Frogbot scan as failed by setting failOnSecurityIssues to false"
	rootDir               = "."
)

type ScanPullRequestCmd struct {
}

// ScanPullRequest Run method only works for GitHub and Gitlab git providers. 'scanpullrequests' is used for Bitbucket Server.
// Therefore, the first repository config represents the repository on which Frogbot runs, and it is the only one that matters.
func (cmd ScanPullRequestCmd) Run(configAggregator utils.FrogbotConfigAggregator, client vcsclient.VcsClient) error {
	return scanPullRequest(&(configAggregator)[0], client)
}

// By default, includeAllVulnerabilities is set to false and the scan goes as follow:
// a. Audit the dependencies of the source and the target branches.
// b. Compare the vulnerabilities found in source and target branches, and show only the new vulnerabilities added by the pull request.
// Otherwise, only the source branch is scanned and all found vulnerabilities are being displayed.
func scanPullRequest(repoConfig *utils.FrogbotRepoConfig, client vcsclient.VcsClient) error {
	if len(repoConfig.Projects) == 0 {
		repoConfig.Projects = []utils.Project{{}}
	}
	// Validate scan params
	if repoConfig.BaseBranch == "" {
		return &utils.ErrMissingEnv{VariableName: utils.GitBaseBranchEnv}
	}
	// Audit PR code
	xrayScanParams := createXrayScanParams(repoConfig.Watches, repoConfig.ProjectKey)
	var vulnerabilitiesRows []formats.VulnerabilityOrViolationRow
	for _, project := range repoConfig.Projects {
		currentScan, err := auditSource(xrayScanParams, project, &repoConfig.Server)
		if err != nil {
			return err
		}
		if repoConfig.IncludeAllVulnerabilities {
			clientLog.Info("Frogbot is configured to show all vulnerabilities")
			allIssuesRows, err := createAllIssuesRows(currentScan)
			if err != nil {
				return err
			}
			vulnerabilitiesRows = append(vulnerabilitiesRows, allIssuesRows...)
		} else {
			// Audit target code
			previousScan, err := auditTarget(client, xrayScanParams, project, repoConfig.RepoName, &repoConfig.GitParams, &repoConfig.Server)
			if err != nil {
				return err
			}
			newIssuesRows, err := createNewIssuesRows(previousScan, currentScan)
			if err != nil {
				return err
			}
			vulnerabilitiesRows = append(vulnerabilitiesRows, newIssuesRows...)
		}
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
	if repoConfig.FailOnSecurityIssues && len(vulnerabilitiesRows) > 0 {
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

func auditSource(xrayScanParams services.XrayGraphScanParams, project utils.Project, server *coreconfig.ServerDetails) ([]services.ScanResponse, error) {
	wd, err := os.Getwd()
	if err != nil {
		return []services.ScanResponse{}, err
	}
	fullPathWds := getFullPathWorkingDirs(&project, wd)
	return runInstallAndAudit(xrayScanParams, &project, server, true, fullPathWds...)
}

func getFullPathWorkingDirs(project *utils.Project, baseWd string) []string {
	var fullPathWds []string
	if len(project.WorkingDir) != 0 {
		for _, workDir := range project.WorkingDir {
			if workDir == rootDir {
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

func auditTarget(client vcsclient.VcsClient, xrayScanParams services.XrayGraphScanParams, project utils.Project, repoName string, git *utils.GitParams, server *coreconfig.ServerDetails) (res []services.ScanResponse, err error) {
	// First download the target repo to temp dir
	clientLog.Info("Auditing " + repoName + " " + git.BaseBranch)
	wd, cleanup, err := utils.DownloadRepoToTempDir(client, repoName, git)
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

func runInstallAndAudit(xrayScanParams services.XrayGraphScanParams, project *utils.Project, server *coreconfig.ServerDetails, failOnInstallationErrors bool, workDirs ...string) (results []services.ScanResponse, err error) {
	for _, wd := range workDirs {
		restoreDir, err := utils.Chdir(wd)
		if err != nil {
			e := restoreDir()
			return nil, fmt.Errorf("%s\n%s", err, e)
		}
		if err = runInstallIfNeeded(project, wd, failOnInstallationErrors); err != nil {
			e := restoreDir()
			return nil, fmt.Errorf("%s\n%s", err, e)
		}

		err = restoreDir()
		if err != nil {
			return nil, err
		}
	}

	results, _, err = audit.GenericAudit(xrayScanParams,
		server,
		false,
		project.UseWrapper,
		false,
		nil,
		nil,
		project.RequirementsFile,
		false,
		workDirs,
		[]string{}...)
	if err != nil {
		return nil, err
	}
	return results, err
}

func runInstallIfNeeded(project *utils.Project, workDir string, failOnInstallationErrors bool) error {
	if project.InstallCommandName == "" {
		return nil
	}
	clientLog.Info("Executing '"+project.InstallCommandName+"'", project.InstallCommandArgs, "at ", workDir)
	//#nosec G204 -- False positive - the subprocess only run after the user's approval.
	if err := exec.Command(project.InstallCommandName, project.InstallCommandArgs...).Run(); err != nil {
		if failOnInstallationErrors {
			return err
		}
		clientLog.Info("Couldn't run the installation command on the base branch. Assuming new project in the source branch: " + err.Error())
		return nil
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
