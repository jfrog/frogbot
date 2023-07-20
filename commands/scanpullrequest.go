package commands

import (
	"context"
	"errors"
	"fmt"
	"github.com/go-git/go-git/v5"
	"github.com/jfrog/gofrog/datastructures"
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

// Run ScanPullRequest method only works for a single repository scan.
// Therefore, the first repository config represents the repository on which Frogbot runs, and it is the only one that matters.
func (cmd *ScanPullRequestCmd) Run(configAggregator utils.RepoAggregator, client vcsclient.VcsClient) error {
	if err := utils.ValidateSingleRepoConfiguration(&configAggregator); err != nil {
		return err
	}
	repoConfig := &(configAggregator)[0]
	if repoConfig.GitProvider == vcsutils.GitHub {
		if err := verifyGitHubFrogbotEnvironment(client, repoConfig); err != nil {
			return err
		}
	}
	if err := cmd.verifyDifferentBranches(repoConfig); err != nil {
		return err
	}
	return scanPullRequest(repoConfig, client)
}

// Verifies current branch and target branch are not the same.
// The Current branch is the branch the action is triggered on.
// The Target branch is the branch to open pull request to.
func (cmd *ScanPullRequestCmd) verifyDifferentBranches(repoConfig *utils.Repository) error {
	repo, err := git.PlainOpen(".")
	if err != nil {
		return err
	}
	ref, err := repo.Head()
	if err != nil {
		return err
	}
	currentBranch := ref.Name().Short()
	defaultBranch := repoConfig.Branches[0]
	if currentBranch == defaultBranch {
		return fmt.Errorf(utils.ErrScanPullRequestSameBranches, currentBranch)
	}
	return nil
}

// By default, includeAllVulnerabilities is set to false and the scan goes as follows:
// a. Audit the dependencies of the source and the target branches.
// b. Compare the vulnerabilities found in source and target branches, and show only the new vulnerabilities added by the pull request.
// Otherwise, only the source branch is scanned and all found vulnerabilities are being displayed.
func scanPullRequest(repoConfig *utils.Repository, client vcsclient.VcsClient) error {
	// Validate scan params
	if len(repoConfig.Branches) == 0 {
		return &utils.ErrMissingEnv{VariableName: utils.GitBaseBranchEnv}
	}

	// Audit PR code
	vulnerabilitiesRows, iacRows, err := auditPullRequest(repoConfig, client)
	if err != nil {
		return err
	}

	// Create a pull request message
	message := createPullRequestMessage(vulnerabilitiesRows, iacRows, repoConfig.OutputWriter)

	// Add comment to the pull request
	if err = client.AddPullRequestComment(context.Background(), repoConfig.RepoOwner, repoConfig.RepoName, message, repoConfig.PullRequestID); err != nil {
		return errors.New("couldn't add pull request comment: " + err.Error())
	}

	// Fail the Frogbot task if a security issue is found and Frogbot isn't configured to avoid the failure.
	if repoConfig.FailOnSecurityIssues != nil && *repoConfig.FailOnSecurityIssues && len(vulnerabilitiesRows) > 0 {
		err = errors.New(securityIssueFoundErr)
	}
	return err
}

func auditPullRequest(repoConfig *utils.Repository, client vcsclient.VcsClient) ([]formats.VulnerabilityOrViolationRow, []formats.IacSecretsRow, error) {
	var vulnerabilitiesRows []formats.VulnerabilityOrViolationRow
	var iacRows []formats.IacSecretsRow
	targetBranch := repoConfig.Branches[0]
	for i := range repoConfig.Projects {
		scanDetails := utils.NewScanDetails(client, &repoConfig.Server, &repoConfig.Git).
			SetProject(&repoConfig.Projects[i]).
			SetXrayGraphScanParams(repoConfig.Watches, repoConfig.JFrogProjectKey).
			SetMinSeverity(repoConfig.MinSeverity).
			SetFixableOnly(repoConfig.FixableOnly)
		sourceResults, err := auditSource(scanDetails)
		if err != nil {
			return nil, nil, err
		}
		repoConfig.SetEntitledForJas(sourceResults.ExtendedScanResults.EntitledForJas)
		if repoConfig.IncludeAllVulnerabilities {
			log.Info("Frogbot is configured to show all vulnerabilities")
			allIssuesRows, err := getScanVulnerabilitiesRows(sourceResults)
			if err != nil {
				return nil, nil, err
			}
			vulnerabilitiesRows = append(vulnerabilitiesRows, allIssuesRows...)
			iacRows = append(iacRows, xrayutils.PrepareIacs(sourceResults.ExtendedScanResults.IacScanResults)...)
			continue
		}
		// Audit target code
		scanDetails.SetFailOnInstallationErrors(*repoConfig.FailOnSecurityIssues).SetBranch(targetBranch)
		targetResults, err := auditTarget(scanDetails)
		if err != nil {
			return nil, nil, err
		}
		newIssuesRows, err := createNewIssuesRows(targetResults, sourceResults)
		if err != nil {
			return nil, nil, err
		}
		vulnerabilitiesRows = append(vulnerabilitiesRows, newIssuesRows...)
		iacRows = append(iacRows, createNewIacRows(targetResults.ExtendedScanResults.IacScanResults, sourceResults.ExtendedScanResults.IacScanResults)...)
	}
	log.Info("Xray scan completed")
	return vulnerabilitiesRows, iacRows, nil
}

func createNewIacRows(targetIacResults, sourceIacResults []xrayutils.IacOrSecretResult) []formats.IacSecretsRow {
	targetIacRows := xrayutils.PrepareIacs(targetIacResults)
	sourceIacRows := xrayutils.PrepareIacs(sourceIacResults)
	targetIacVulnerabilitiesKeys := datastructures.MakeSet[string]()
	for _, row := range targetIacRows {
		targetIacVulnerabilitiesKeys.Add(row.File + row.Text)
	}
	var addedIacVulnerabilities []formats.IacSecretsRow
	for _, row := range sourceIacRows {
		if !targetIacVulnerabilitiesKeys.Exists(row.File + row.Text) {
			addedIacVulnerabilities = append(addedIacVulnerabilities, row)
		}
	}
	return addedIacVulnerabilities
}

// Verify that the 'frogbot' GitHub environment was properly configured on the repository
func verifyGitHubFrogbotEnvironment(client vcsclient.VcsClient, repoConfig *utils.Repository) error {
	if repoConfig.APIEndpoint != "" && repoConfig.APIEndpoint != "https://api.github.com" {
		// Don't verify 'frogbot' environment on GitHub on-prem
		return nil
	}
	if _, exist := os.LookupEnv(utils.GitHubActionsEnv); !exist {
		// Don't verify 'frogbot' environment on non GitHub Actions CI
		return nil
	}

	// If the repository is not public, using 'frogbot' environment is not mandatory
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
func createNewIssuesRows(targetResults, sourceResults *audit.Results) (vulnerabilitiesRows []formats.VulnerabilityOrViolationRow, err error) {
	targetScanAggregatedResults := aggregateScanResults(targetResults.ExtendedScanResults.XrayResults)
	sourceScanAggregatedResults := aggregateScanResults(sourceResults.ExtendedScanResults.XrayResults)

	if len(sourceScanAggregatedResults.Violations) > 0 {
		newViolations, err := getNewViolations(targetScanAggregatedResults, sourceScanAggregatedResults, sourceResults)
		if err != nil {
			return vulnerabilitiesRows, err
		}
		vulnerabilitiesRows = append(vulnerabilitiesRows, newViolations...)
	} else if len(sourceScanAggregatedResults.Vulnerabilities) > 0 {
		newVulnerabilities, err := getNewVulnerabilities(targetScanAggregatedResults, sourceScanAggregatedResults, sourceResults)
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

// Create vulnerability rows. The rows should contain all the issues that were found in this module scan.
func getScanVulnerabilitiesRows(auditResults *audit.Results) ([]formats.VulnerabilityOrViolationRow, error) {
	violations, vulnerabilities, _ := xrayutils.SplitScanResults(auditResults.ExtendedScanResults.XrayResults)
	if len(violations) > 0 {
		violationsRows, _, _, err := xrayutils.PrepareViolations(violations, auditResults.ExtendedScanResults, auditResults.IsMultipleRootProject, true)
		return violationsRows, err
	}
	if len(vulnerabilities) > 0 {
		return xrayutils.PrepareVulnerabilities(vulnerabilities, auditResults.ExtendedScanResults, auditResults.IsMultipleRootProject, true)
	}
	return []formats.VulnerabilityOrViolationRow{}, nil
}

func auditSource(scanSetup *utils.ScanDetails) (auditResults *audit.Results, err error) {
	wd, err := os.Getwd()
	if err != nil {
		return
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

func auditTarget(scanSetup *utils.ScanDetails) (auditResults *audit.Results, err error) {
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

func runInstallAndAudit(scanSetup *utils.ScanDetails, workDirs ...string) (auditResults *audit.Results, err error) {
	for _, wd := range workDirs {
		if err = runInstallIfNeeded(scanSetup, wd); err != nil {
			return nil, err
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
		SetGraphBasicParams(graphBasicParams)

	auditResults, err = audit.RunAudit(auditParams)
	if auditResults != nil {
		err = errors.Join(err, auditResults.AuditError)
	}
	return
}

func runInstallIfNeeded(scanSetup *utils.ScanDetails, workDir string) (err error) {
	if scanSetup.InstallCommandName == "" {
		return nil
	}
	restoreDir, err := utils.Chdir(workDir)
	defer func() {
		err = errors.Join(err, restoreDir())
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
		//#nosec G204 -- False positive - the subprocess only runs after the user's approval.
		return exec.Command(scanSetup.InstallCommandName, scanSetup.InstallCommandArgs...).CombinedOutput()
	}

	if _, exists := utils.MapTechToResolvingFunc[scanSetup.InstallCommandName]; !exists {
		return nil, fmt.Errorf(scanSetup.InstallCommandName, "isn't recognized as an install command")
	}
	log.Info("Resolving dependencies from", scanSetup.ServerDetails.Url, "from repo", scanSetup.Repository)
	return utils.MapTechToResolvingFunc[scanSetup.InstallCommandName](scanSetup)
}

func getNewViolations(targetScan, sourceScan services.ScanResponse, auditResults *audit.Results) (newViolationsRows []formats.VulnerabilityOrViolationRow, err error) {
	existsViolationsMap := make(map[string]formats.VulnerabilityOrViolationRow)
	violationsRows, _, _, err := xrayutils.PrepareViolations(targetScan.Violations, auditResults.ExtendedScanResults, auditResults.IsMultipleRootProject, true)
	if err != nil {
		return violationsRows, err
	}
	for _, violation := range violationsRows {
		existsViolationsMap[utils.GetUniqueID(violation)] = violation
	}
	violationsRows, _, _, err = xrayutils.PrepareViolations(sourceScan.Violations, auditResults.ExtendedScanResults, auditResults.IsMultipleRootProject, true)
	if err != nil {
		return newViolationsRows, err
	}
	for _, violation := range violationsRows {
		if _, exists := existsViolationsMap[utils.GetUniqueID(violation)]; !exists {
			newViolationsRows = append(newViolationsRows, violation)
		}
	}
	return
}

func getNewVulnerabilities(targetScan, sourceScan services.ScanResponse, auditResults *audit.Results) (newVulnerabilitiesRows []formats.VulnerabilityOrViolationRow, err error) {
	targetVulnerabilitiesMap := make(map[string]formats.VulnerabilityOrViolationRow)
	targetVulnerabilitiesRows, err := xrayutils.PrepareVulnerabilities(targetScan.Vulnerabilities, auditResults.ExtendedScanResults, auditResults.IsMultipleRootProject, true)
	if err != nil {
		return newVulnerabilitiesRows, err
	}
	for _, vulnerability := range targetVulnerabilitiesRows {
		targetVulnerabilitiesMap[utils.GetUniqueID(vulnerability)] = vulnerability
	}
	sourceVulnerabilitiesRows, err := xrayutils.PrepareVulnerabilities(sourceScan.Vulnerabilities, auditResults.ExtendedScanResults, auditResults.IsMultipleRootProject, true)
	if err != nil {
		return newVulnerabilitiesRows, err
	}
	for _, vulnerability := range sourceVulnerabilitiesRows {
		if _, exists := targetVulnerabilitiesMap[utils.GetUniqueID(vulnerability)]; !exists {
			newVulnerabilitiesRows = append(newVulnerabilitiesRows, vulnerability)
		}
	}
	return
}

func createPullRequestMessage(vulnerabilitiesRows []formats.VulnerabilityOrViolationRow, iacRows []formats.IacSecretsRow, writer utils.OutputWriter) string {
	if len(vulnerabilitiesRows) == 0 && len(iacRows) == 0 {
		return writer.NoVulnerabilitiesTitle() + writer.UntitledForJasMsg() + writer.Footer()
	}
	return writer.VulnerabiltiesTitle(true) + writer.VulnerabilitiesContent(vulnerabilitiesRows) + writer.IacContent(iacRows) + writer.UntitledForJasMsg() + writer.Footer()
}
