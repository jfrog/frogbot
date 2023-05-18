package commands

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/jfrog/frogbot/commands/utils"
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/froggit-go/vcsutils"
	audit "github.com/jfrog/jfrog-cli-core/v2/xray/commands/audit/generic"
	"github.com/jfrog/jfrog-cli-core/v2/xray/formats"
	xrayutils "github.com/jfrog/jfrog-cli-core/v2/xray/utils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray/services"
)

const (
	securityIssueFoundErr    = "issues were detected by Frogbot\n You can avoid marking the Frogbot scan as failed by setting failOnSecurityIssues to false in the " + utils.FrogbotConfigFile + " file"
	installationCmdFailedErr = "Couldn't run the installation command on the base branch. Assuming new project in the source branch: "
	noGitHubEnvErr           = "frogbot did not scan this PR, because a GitHub Environment named 'frogbot' does not exist. Please refer to the Frogbot documentation for instructions on how to create the Environment"
	noGitHubEnvReviewersErr  = "frogbot did not scan this PR, because the existing GitHub Environment named 'frogbot' doesn't have reviewers selected. Please refer to the Frogbot documentation for instructions on how to create the Environment"
)

type ScanPullRequestCmd struct{}

// Run ScanPullRequest method only works for single repository scan.
// Therefore, the first repository config represents the repository on which Frogbot runs, and it is the only one that matters.
func (cmd *ScanPullRequestCmd) Run(configAggregator utils.FrogbotConfigAggregator, client vcsclient.VcsClient) error {
	if err := utils.ValidateSingleRepoConfiguration(&configAggregator); err != nil {
		return err
	}
	repoConfig := &(configAggregator)[0]
	if repoConfig.GitProvider == vcsutils.GitHub {
		if err := verifyGitHubFrogbotEnvironment(client, repoConfig); err != nil {
			return err
		}
	}
	return scanPullRequest(repoConfig, client)
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
	vulnerabilitiesRows, err := auditPullRequest(repoConfig, client)
	if err != nil {
		return err
	}

	// Create pull request message
	message := createPullRequestMessage(vulnerabilitiesRows, repoConfig.OutputWriter)

	// Add comment to the pull request
	if err = client.AddPullRequestComment(context.Background(), repoConfig.RepoOwner, repoConfig.RepoName, message, repoConfig.PullRequestID); err != nil {
		return errors.New("couldn't add pull request comment: " + err.Error())
	}

	// Fail the Frogbot task, if a security issue is found and Frogbot isn't configured to avoid the failure.
	if repoConfig.FailOnSecurityIssues != nil && *repoConfig.FailOnSecurityIssues && len(vulnerabilitiesRows) > 0 {
		err = errors.New(securityIssueFoundErr)
	}
	return err
}

func auditPullRequest(repoConfig *utils.FrogbotRepoConfig, client vcsclient.VcsClient) ([]formats.VulnerabilityOrViolationRow, error) {
	var vulnerabilitiesRows []formats.VulnerabilityOrViolationRow
	for i := range repoConfig.Projects {
		scanDetails := utils.NewScanDetails(client, &repoConfig.Server, &repoConfig.Git).
			SetProject(&repoConfig.Projects[i]).
			SetBranch(repoConfig.Branches[0]).
			SetReleasesRepo(repoConfig.JfrogReleasesRepo).
			SetXrayGraphScanParams(repoConfig.Watches, repoConfig.JFrogProjectKey).
			SetMinSeverity(repoConfig.MinSeverity).
			SetFixableOnly(repoConfig.FixableOnly)
		currentScan, isMultipleRoot, err := auditSource(scanDetails)
		if err != nil {
			return nil, err
		}
		if repoConfig.IncludeAllVulnerabilities {
			log.Info("Frogbot is configured to show all vulnerabilities")
			allIssuesRows, err := createAllIssuesRows(currentScan, isMultipleRoot)
			if err != nil {
				return nil, err
			}
			vulnerabilitiesRows = append(vulnerabilitiesRows, allIssuesRows...)
			continue
		}
		// Audit target code
		scanDetails.SetFailOnInstallationErrors(*repoConfig.FailOnSecurityIssues)
		previousScan, isMultipleRoot, err := auditTarget(scanDetails)
		if err != nil {
			return nil, err
		}
		newIssuesRows, err := createNewIssuesRows(previousScan, currentScan, isMultipleRoot)
		if err != nil {
			return nil, err
		}
		vulnerabilitiesRows = append(vulnerabilitiesRows, newIssuesRows...)
	}
	log.Info("Xray scan completed")
	return vulnerabilitiesRows, nil
}

// Verify that the 'frogbot' GitHub environment was properly configured on the repository
func verifyGitHubFrogbotEnvironment(client vcsclient.VcsClient, repoConfig *utils.FrogbotRepoConfig) error {
	if repoConfig.ApiEndpoint != "" && repoConfig.ApiEndpoint != "https://api.github.com" {
		// Don't verify 'frogbot' environment on GitHub on-prem
		return nil
	}
	if _, exist := os.LookupEnv(utils.GitHubActionsEnv); !exist {
		// Don't verify 'frogbot' environment on non GitHub Actions CI
		return nil
	}

	// If repository is not public, using 'frogbot' environment is not mandatory
	repoInfo, err := client.GetRepositoryInfo(context.Background(), repoConfig.RepoOwner, repoConfig.RepoName)
	if err != nil {
		return err
	}
	if repoInfo.RepositoryVisibility != vcsclient.Public {
		return nil
	}

	// Get the 'frogbot' environment info and make sure it exists and includes reviewers
	repoEnvInfo, err := client.GetRepositoryEnvironmentInfo(context.Background(), repoConfig.RepoOwner, repoConfig.RepoName, "frogbot")
	if err != nil {
		return errors.New(err.Error() + "/n" + noGitHubEnvErr)
	}
	if len(repoEnvInfo.Reviewers) == 0 {
		return errors.New(noGitHubEnvReviewersErr)
	}

	return nil
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
func getScanVulnerabilitiesRows(violations []services.Violation, vulnerabilities []services.Vulnerability, isMultipleRoot bool, extendedScanResults *xrayutils.ExtendedScanResults) ([]formats.VulnerabilityOrViolationRow, error) {
	if len(violations) > 0 {
		violationsRows, _, _, err := xrayutils.PrepareViolations(violations, extendedScanResults, isMultipleRoot, true)
		return violationsRows, err
	}
	if len(vulnerabilities) > 0 {
		return xrayutils.PrepareVulnerabilities(vulnerabilities, extendedScanResults, isMultipleRoot, true)
	}
	return []formats.VulnerabilityOrViolationRow{}, nil
}

// Create vulnerabilities rows. The rows should contain all the issues that were found in this PR
func createAllIssuesRows(currentScan []services.ScanResponse, isMultipleRoot bool) ([]formats.VulnerabilityOrViolationRow, error) {
	violations, vulnerabilities, _ := xrayutils.SplitScanResults(currentScan)
	return getScanVulnerabilitiesRows(violations, vulnerabilities, isMultipleRoot, &xrayutils.ExtendedScanResults{XrayResults: currentScan})
}

func auditSource(scanSetup *utils.ScanDetails) ([]services.ScanResponse, bool, error) {
	wd, err := os.Getwd()
	if err != nil {
		return []services.ScanResponse{}, false, err
	}
	fullPathWds := getFullPathWorkingDirs(scanSetup.WorkingDirs, wd)
	return runInstallAndAudit(scanSetup, fullPathWds...)
}

func getFullPathWorkingDirs(workingDirs []string, baseWd string) []string {
	var fullPathWds []string
	if len(workingDirs) != 0 {
		for _, workDir := range workingDirs {
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

func auditTarget(scanSetup *utils.ScanDetails) (res []services.ScanResponse, isMultipleRoot bool, err error) {
	// First download the target repo to temp dir
	log.Info("Auditing the", scanSetup.Git.RepoName, "repository on the", scanSetup.Branch(), "branch")
	wd, cleanup, err := utils.DownloadRepoToTempDir(scanSetup.Client(), scanSetup.Branch(), scanSetup.Git)
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
	fullPathWds := getFullPathWorkingDirs(scanSetup.Project.WorkingDirs, wd)
	return runInstallAndAudit(scanSetup, fullPathWds...)
}

func runInstallAndAudit(scanSetup *utils.ScanDetails, workDirs ...string) (results []services.ScanResponse, isMultipleRoot bool, err error) {
	for _, wd := range workDirs {
		if err = runInstallIfNeeded(scanSetup, wd); err != nil {
			return nil, false, err
		}
	}
	graphBasicParams := (&xrayutils.GraphBasicParams{}).
		SetPipRequirementsFile(scanSetup.PipRequirementsFile).
		SetUseWrapper(*scanSetup.UseWrapper).
		SetDepsRepo(scanSetup.Repository).
		SetIgnoreConfigFile(true).
		SetServerDetails(scanSetup.ServerDetails)
	auditParams := audit.NewAuditParams().
		SetXrayGraphScanParams(scanSetup.XrayGraphScanParams).
		SetWorkingDirs(workDirs).
		SetMinSeverityFilter(scanSetup.MinSeverityFilter()).
		SetFixableOnly(scanSetup.FixableOnly()).
		SetReleasesRepo(scanSetup.ReleasesRepo())
	auditParams.GraphBasicParams = graphBasicParams

	results, isMultipleRoot, err = audit.GenericAudit(auditParams)
	if err != nil {
		return nil, false, err
	}
	return results, isMultipleRoot, err
}

func runInstallIfNeeded(scanSetup *utils.ScanDetails, workDir string) (err error) {
	if scanSetup.InstallCommandName == "" {
		return nil
	}
	restoreDir, err := utils.Chdir(workDir)
	defer func() {
		restoreErr := restoreDir()
		if err == nil {
			err = restoreErr
		}
	}()
	log.Info(fmt.Sprintf("Executing '%s %s' at %s", scanSetup.InstallCommandName, scanSetup.InstallCommandArgs, workDir))
	output, err := runInstallCommand(scanSetup)
	if err != nil && !scanSetup.FailOnInstallationErrors() {
		log.Info(installationCmdFailedErr, err.Error(), "\n", string(output))
		// failOnInstallationErrors set to 'false'
		err = nil
	}
	return
}

func runInstallCommand(scanSetup *utils.ScanDetails) ([]byte, error) {
	if scanSetup.Repository == "" {
		//#nosec G204 -- False positive - the subprocess only run after the user's approval.
		return exec.Command(scanSetup.InstallCommandName, scanSetup.InstallCommandArgs...).CombinedOutput()
	}

	if _, exists := utils.MapTechToResolvingFunc[scanSetup.InstallCommandName]; !exists {
		return nil, fmt.Errorf(scanSetup.InstallCommandName, "isn't recognized as an install command")
	}
	log.Info("Resolving dependencies from", scanSetup.ServerDetails.Url, "from repo", scanSetup.Repository)
	return utils.MapTechToResolvingFunc[scanSetup.InstallCommandName](scanSetup)
}

func getNewViolations(previousScan, currentScan services.ScanResponse, isMultipleRoot bool) (newViolationsRows []formats.VulnerabilityOrViolationRow, err error) {
	existsViolationsMap := make(map[string]formats.VulnerabilityOrViolationRow)
	violationsRows, _, _, err := xrayutils.PrepareViolations(previousScan.Violations, &xrayutils.ExtendedScanResults{XrayResults: []services.ScanResponse{previousScan}}, isMultipleRoot, true)
	if err != nil {
		return violationsRows, err
	}
	for _, violation := range violationsRows {
		existsViolationsMap[getUniqueID(violation)] = violation
	}
	violationsRows, _, _, err = xrayutils.PrepareViolations(currentScan.Violations, &xrayutils.ExtendedScanResults{XrayResults: []services.ScanResponse{currentScan}}, isMultipleRoot, true)
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
	vulnerabilitiesRows, err := xrayutils.PrepareVulnerabilities(previousScan.Vulnerabilities, &xrayutils.ExtendedScanResults{XrayResults: []services.ScanResponse{previousScan}}, isMultipleRoot, true)
	if err != nil {
		return newVulnerabilitiesRows, err
	}
	for _, vulnerability := range vulnerabilitiesRows {
		existsVulnerabilitiesMap[getUniqueID(vulnerability)] = vulnerability
	}
	vulnerabilitiesRows, err = xrayutils.PrepareVulnerabilities(currentScan.Vulnerabilities, &xrayutils.ExtendedScanResults{XrayResults: []services.ScanResponse{currentScan}}, isMultipleRoot, true)
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
	return vulnerability.ImpactedDependencyName + vulnerability.ImpactedDependencyVersion + vulnerability.IssueId
}

func createPullRequestMessage(vulnerabilitiesRows []formats.VulnerabilityOrViolationRow, writer utils.OutputWriter) string {
	if len(vulnerabilitiesRows) == 0 {
		return writer.NoVulnerabilitiesTitle()
	}
	tableContent := getTableContent(vulnerabilitiesRows, writer)
	return writer.VulnerabiltiesTitle() + writer.TableHeader() + tableContent
}

func getTableContent(vulnerabilitiesRows []formats.VulnerabilityOrViolationRow, writer utils.OutputWriter) string {
	var tableContent string
	for _, vulnerability := range vulnerabilitiesRows {
		tableContent += writer.TableRow(vulnerability)
	}
	return tableContent
}
