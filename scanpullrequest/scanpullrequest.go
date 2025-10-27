package scanpullrequest

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/jfrog/frogbot/v2/utils"
	"github.com/jfrog/frogbot/v2/utils/issues"
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/froggit-go/vcsutils"
	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/results/conversion"
	"github.com/jfrog/jfrog-cli-security/utils/xsc"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/owenrumney/go-sarif/v3/pkg/report/v210/sarif"
)

const (
	SecurityIssueFoundErr = "issues were detected by Frogbot\n" +
		"You can avoid marking the Frogbot scan as failed by setting failOnSecurityIssues to false in the " + utils.FrogbotConfigFile + " file or by setting the " + utils.FailOnSecurityIssuesEnv + " environment variable to false\n" +
		"Note that even if failOnSecurityIssues/" + utils.FailOnSecurityIssuesEnv + " are set to false, but a security violation with 'fail-pull-request' rule is found, Frogbot scan will fail as well"
	noGitHubEnvErr                       = "frogbot did not scan this PR, because a GitHub Environment named 'frogbot' does not exist. Please refer to the Frogbot documentation for instructions on how to create the Environment"
	noGitHubEnvReviewersErr              = "frogbot did not scan this PR, because the existing GitHub Environment named 'frogbot' doesn't have reviewers selected. Please refer to the Frogbot documentation for instructions on how to create the Environment"
	analyticsScanPrScanType              = "PR"
	vulnerabilitiesFilteringErrorMessage = "%s scan has completed with errors. Vulnerabilities results will be removed from final report"
	violationsFilteringErrorMessage      = "%s scan has completed with errors. Violations results will be removed from final report"
)

type ScanPullRequestCmd struct{}

// Run ScanPullRequest method only works for a single repository scan.
// Therefore, the first repository config represents the repository on which Frogbot runs, and it is the only one that matters.
func (cmd *ScanPullRequestCmd) Run(configAggregator utils.RepoAggregator, client vcsclient.VcsClient, frogbotRepoConnection *utils.UrlAccessChecker) (err error) {
	if err = utils.ValidateSingleRepoConfiguration(&configAggregator); err != nil {
		return
	}
	repoConfig := &(configAggregator)[0]
	if repoConfig.GitProvider == vcsutils.GitHub {
		if err = verifyGitHubFrogbotEnvironment(client, repoConfig); err != nil {
			return
		}
	}
	repoConfig.OutputWriter.SetHasInternetConnection(frogbotRepoConnection.IsConnected())
	if repoConfig.PullRequestDetails, err = client.GetPullRequestByID(context.Background(), repoConfig.RepoOwner, repoConfig.RepoName, int(repoConfig.PullRequestDetails.ID)); err != nil {
		return
	}
	return scanPullRequest(repoConfig, client)
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
		return errors.New(err.Error() + "\n" + noGitHubEnvErr)
	}
	if len(repoEnvInfo.Reviewers) == 0 {
		return errors.New(noGitHubEnvReviewersErr)
	}

	return nil
}

// By default, includeAllVulnerabilities is set to false and the scan goes as follows:
// a. Audit the dependencies of the source and the target branches.
// b. Compare the vulnerabilities found in source and target branches, and show only the new vulnerabilities added by the pull request.
// Otherwise, only the source branch is scanned and all found vulnerabilities are being displayed.
func scanPullRequest(repo *utils.Repository, client vcsclient.VcsClient) (err error) {
	pullRequestDetails := repo.PullRequestDetails
	log.Info(fmt.Sprintf("Scanning Pull Request #%d (from source branch: <%s/%s/%s> to target branch: <%s/%s/%s>)",
		pullRequestDetails.ID,
		pullRequestDetails.Source.Owner, pullRequestDetails.Source.Repository, pullRequestDetails.Source.Name,
		pullRequestDetails.Target.Owner, pullRequestDetails.Target.Repository, pullRequestDetails.Target.Name))
	log.Info("-----------------------------------------------------------")

	// Audit PR code
	issues, resultContext, err := auditPullRequestAndReport(repo, client)
	if err != nil {
		return
	}

	// Output results
	shouldSendExposedSecretsEmail := issues.SecretsIssuesExists() && repo.SmtpServer != ""
	if shouldSendExposedSecretsEmail {
		secretsEmailDetails := utils.NewSecretsEmailDetails(client, repo, append(issues.SecretsVulnerabilities, issues.SecretsViolations...))
		if err = utils.AlertSecretsExposed(secretsEmailDetails); err != nil {
			return
		}
	}

	// Handle PR comments for scan output
	if err = utils.HandlePullRequestCommentsAfterScan(issues, resultContext, repo, client, int(pullRequestDetails.ID)); err != nil {
		return
	}

	// Fail the Frogbot task if a security issue is found and Frogbot isn't configured to avoid the failure.
	if toFailTaskStatus(repo, issues) {
		err = errors.New(SecurityIssueFoundErr)
		return
	}
	return
}

func toFailTaskStatus(repo *utils.Repository, issues *issues.ScansIssuesCollection) bool {
	failFlagSet := repo.FailOnSecurityIssues != nil && *repo.FailOnSecurityIssues
	if failFlagSet {
		// If the fail flag is set to true (JF_FAIL), we check if any security ISSUE exists (not just violations), and if so, we fail the build.
		return issues.IssuesExists(repo.PullRequestSecretComments)
	} else {
		// When fail flag is set to false, we check for fail-pr rule in existing VIOLATIONS. If one exists, we fail the build as well.
		return issues.IsFailPrRuleApplied()
	}
}

func auditPullRequestAndReport(repoConfig *utils.Repository, client vcsclient.VcsClient) (issuesCollection *issues.ScansIssuesCollection, resultContext results.ResultContext, err error) {
	// Prepare
	scanDetails, err := createBaseScanDetails(repoConfig, client)
	if err != nil {
		return
	}
	resultContext = scanDetails.ResultContext
	sourceBranchWd, targetBranchWd, cleanup, err := prepareSourceCodeForScan(repoConfig, scanDetails)
	if err != nil {
		return
	}
	defer func() {
		err = errors.Join(err, cleanup())
	}()
	// Report
	scanDetails.MultiScanId, scanDetails.StartTime = xsc.SendNewScanEvent(
		scanDetails.XrayVersion,
		scanDetails.XscVersion,
		scanDetails.ServerDetails,
		utils.CreateScanEvent(scanDetails.ServerDetails, scanDetails.XscGitInfoContext, analyticsScanPrScanType),
		repoConfig.JFrogProjectKey,
	)
	defer func() {
		if issuesCollection != nil {
			xsc.SendScanEndedEvent(
				scanDetails.XrayVersion,
				scanDetails.XscVersion,
				scanDetails.ServerDetails,
				scanDetails.MultiScanId, scanDetails.StartTime, issuesCollection.GetAllIssuesCount(true), &scanDetails.ResultContext, err,
			)
		}
	}()
	// Audit PR code
	issuesCollection, err = auditPullRequestCode(repoConfig, scanDetails, sourceBranchWd, targetBranchWd)
	return
}

func createBaseScanDetails(repoConfig *utils.Repository, client vcsclient.VcsClient) (scanDetails *utils.ScanDetails, err error) {
	repositoryCloneUrl, err := repoConfig.GetRepositoryHttpsCloneUrl(client)
	if err != nil {
		return
	}
	scanDetails = utils.NewScanDetails(client, &repoConfig.Server, &repoConfig.Git).
		SetJfrogVersions(repoConfig.XrayVersion, repoConfig.XscVersion).
		SetResultsContext(repositoryCloneUrl, repoConfig.Watches, repoConfig.JFrogProjectKey, repoConfig.IncludeVulnerabilities, len(repoConfig.AllowedLicenses) > 0).
		SetFixableOnly(repoConfig.FixableOnly).
		SetConfigProfile(repoConfig.ConfigProfile).
		SetSkipAutoInstall(repoConfig.SkipAutoInstall).
		SetDisableJas(repoConfig.DisableJas).
		SetXscPRGitInfoContext(repoConfig.Project, client, repoConfig.PullRequestDetails).
		SetDiffScan(!repoConfig.IncludeAllVulnerabilities).
		SetAllowedLicenses(repoConfig.AllowedLicenses)
	return scanDetails.SetMinSeverity(repoConfig.MinSeverity)
}

func prepareSourceCodeForScan(repoConfig *utils.Repository, scanDetails *utils.ScanDetails) (sourceBranchWd, targetBranchWd string, cleanup func() error, err error) {
	cleanupSource := func() error { return nil }
	cleanupTarget := func() error { return nil }
	cleanup = func() error { return errors.Join(cleanupSource(), cleanupTarget()) }

	log.Info("Downloading source branch code...")
	if sourceBranchWd, cleanupSource, err = utils.DownloadRepoToTempDir(scanDetails.Client(),
		scanDetails.PullRequestDetails.Source.Owner,
		scanDetails.PullRequestDetails.Source.Repository,
		scanDetails.PullRequestDetails.Source.Name,
	); err != nil {
		err = fmt.Errorf("failed to download source branch code. Error: %s", err.Error())
		return
	}
	if repoConfig.IncludeAllVulnerabilities {
		// No need to download target branch
		log.Info("Frogbot is configured to show all issues at source branch")
		return
	}
	if targetBranchWd, cleanupTarget, err = prepareTargetForScan(repoConfig.Git, scanDetails); err != nil {
		err = fmt.Errorf("failed to download target branch code. Error: %s", err.Error())
		return
	}
	return
}

func auditPullRequestCode(repoConfig *utils.Repository, scanDetails *utils.ScanDetails, sourceBranchWd, targetBranchWd string) (issuesCollection *issues.ScansIssuesCollection, err error) {
	issuesCollection = &issues.ScansIssuesCollection{}

	for i := range repoConfig.Projects {
		// Reset scan details for each project
		scanDetails.SetProject(&repoConfig.Projects[i]).SetResultsToCompare(nil)
		// Scan target branch of the project
		if !repoConfig.IncludeAllVulnerabilities {
			log.Debug("Scanning target branch code...")
			if targetScanResults, e := auditPullRequestTargetCode(scanDetails, targetBranchWd); e != nil {
				issuesCollection.AppendStatus(getResultScanStatues(targetScanResults))
				err = errors.Join(err, fmt.Errorf("failed to audit target branch code for %v project. Error: %s", repoConfig.Projects[i].WorkingDirs, e.Error()))
				continue
			} else {
				scanDetails.SetResultsToCompare(targetScanResults)
			}
		}
		// Scan source branch of the project
		log.Debug("Scanning source branch code...")
		if issues, e := auditPullRequestSourceCode(repoConfig, scanDetails, sourceBranchWd, targetBranchWd); e == nil {
			issuesCollection.Append(issues)
			continue
		} else {
			if issues != nil {
				// Scan error, report the scan status
				issuesCollection.AppendStatus(issues.ScanStatus)
			}
			err = errors.Join(err, fmt.Errorf("failed to audit source branch code for %v project. Error: %s", repoConfig.Projects[i].WorkingDirs, e.Error()))
		}
	}

	return
}

func auditPullRequestTargetCode(scanDetails *utils.ScanDetails, targetBranchWd string) (scanResults *results.SecurityCommandResults, err error) {
	scanResults = scanDetails.RunInstallAndAudit(utils.GetFullPathWorkingDirs(scanDetails.Project.WorkingDirs, targetBranchWd)...)
	err = scanResults.GetErrors()
	return
}

func auditPullRequestSourceCode(repoConfig *utils.Repository, scanDetails *utils.ScanDetails, sourceBranchWd, targetBranchWd string) (issuesCollection *issues.ScansIssuesCollection, err error) {
	scanResults := scanDetails.RunInstallAndAudit(utils.GetFullPathWorkingDirs(scanDetails.Project.WorkingDirs, sourceBranchWd)...)
	if err = scanResults.GetErrors(); err != nil {
		issuesCollection = &issues.ScansIssuesCollection{ScanStatus: getResultScanStatues(scanResults)}
		return
	}
	// Set JAS output flags based on the scan results
	repoConfig.OutputWriter.SetJasOutputFlags(scanResults.EntitledForJas, scanResults.HasJasScansResults(jasutils.Applicability))
	workingDirs := []string{strings.TrimPrefix(sourceBranchWd, string(filepath.Separator))}
	if !repoConfig.IncludeAllVulnerabilities && targetBranchWd != "" && scanDetails.ResultsToCompare != nil {
		// Diff scan - calculated at audit source scan, make sure to include target branch working dir when converting to issues
		log.Debug("Diff scan - converting to new issues...")
		workingDirs = append(workingDirs, strings.TrimPrefix(targetBranchWd, string(filepath.Separator)))
	}

	if err = filterOutFailedScansIfAllowPartialResultsEnabled(scanDetails.ResultsToCompare, scanResults, repoConfig.AllowPartialResults); err != nil {
		return
	}

	// Convert to issues
	if issues, e := scanResultsToIssuesCollection(scanResults, scanDetails.AllowedLicenses, workingDirs...); e == nil {
		issuesCollection = issues
		return
	} else {
		err = errors.Join(err, fmt.Errorf("failed to get all issues for %v project. Error: %s", scanDetails.Project.WorkingDirs, e.Error()))
	}
	return
}

// When allowPartialResults is enabled, and we are performing a diff scan (both source & target results exist), we filter out a scanner results
// if we found any error in any of its results (non-zero status code) in either source or target results.
// This logic prevents us from presenting incorrect results due to an incomplete scan that produced incomplete results that might affect the diff process.
func filterOutFailedScansIfAllowPartialResultsEnabled(targetResults, sourceResults *results.SecurityCommandResults, allowPartialResults bool) error {
	if !allowPartialResults {
		return nil
	}
	if targetResults == nil {
		// If IncludeAllVulnerabilities is applied, only sourceResults exists and we don't need to filter anything - we present results we have
		return nil
	}

	// If both source & target results exists, we need to filter out results of scans that failed in either source or target results, to avoid presenting incorrect diff results
	if err := sortTargetsByPhysicalLocation(targetResults, sourceResults); err != nil {
		return err
	}
	// TODO: implement logic for filtering violations under ScanResults instead of under targetResults/SourceResults
	for idx := 0; idx < len(sourceResults.Targets); idx++ {
		targetResult := targetResults.Targets[idx]
		sourceResult := sourceResults.Targets[idx]

		filterOutScaResultsIfScanFailed(targetResult, sourceResult)
		filterJasResultsIfScanFailed(targetResult, sourceResult, jasutils.Applicability)
		filterJasResultsIfScanFailed(targetResult, sourceResult, jasutils.Secrets)
		filterJasResultsIfScanFailed(targetResult, sourceResult, jasutils.IaC)
		filterJasResultsIfScanFailed(targetResult, sourceResult, jasutils.Sast)
	}
	return nil
}

func filterJasResultsIfScanFailed(targetResult, sourceResult *results.TargetResults, scanType jasutils.JasScanType) {
	switch scanType {
	case jasutils.Applicability:
		if isJasScanFailedInSourceOrTarget(sourceResult.JasResults.ApplicabilityScanResults, targetResult.JasResults.ApplicabilityScanResults) {
			log.Debug(fmt.Sprintf(vulnerabilitiesFilteringErrorMessage, scanType.String()))
			sourceResult.JasResults.ApplicabilityScanResults = nil
		}
	case jasutils.Secrets:
		if isJasScanFailedInSourceOrTarget(sourceResult.JasResults.JasVulnerabilities.SecretsScanResults, targetResult.JasResults.JasVulnerabilities.SecretsScanResults) {
			log.Debug(fmt.Sprintf(vulnerabilitiesFilteringErrorMessage, scanType.String()))
			sourceResult.JasResults.JasVulnerabilities.SecretsScanResults = nil
		}

		if (sourceResult.JasResults.JasViolations.SecretsScanResults != nil || targetResult.JasResults.JasViolations.SecretsScanResults != nil) && isJasScanFailedInSourceOrTarget(sourceResult.JasResults.JasViolations.SecretsScanResults, targetResult.JasResults.JasViolations.SecretsScanResults) {
			log.Debug(fmt.Sprintf(violationsFilteringErrorMessage, scanType.String()))
			sourceResult.JasResults.JasViolations.SecretsScanResults = nil
		}
	case jasutils.IaC:
		if isJasScanFailedInSourceOrTarget(sourceResult.JasResults.JasVulnerabilities.IacScanResults, targetResult.JasResults.JasVulnerabilities.IacScanResults) {
			log.Debug(fmt.Sprintf(vulnerabilitiesFilteringErrorMessage, scanType.String()))
			sourceResult.JasResults.JasVulnerabilities.IacScanResults = nil
		}

		if (sourceResult.JasResults.JasViolations.IacScanResults != nil || targetResult.JasResults.JasViolations.IacScanResults != nil) && isJasScanFailedInSourceOrTarget(sourceResult.JasResults.JasViolations.IacScanResults, targetResult.JasResults.JasViolations.IacScanResults) {
			log.Debug(fmt.Sprintf(violationsFilteringErrorMessage, scanType.String()))
			sourceResult.JasResults.JasViolations.IacScanResults = nil
		}
	case jasutils.Sast:
		if isJasScanFailedInSourceOrTarget(sourceResult.JasResults.JasVulnerabilities.SastScanResults, targetResult.JasResults.JasVulnerabilities.SastScanResults) {
			log.Debug(fmt.Sprintf(vulnerabilitiesFilteringErrorMessage, scanType.String()))
			sourceResult.JasResults.JasVulnerabilities.SastScanResults = nil
		}

		if (sourceResult.JasResults.JasViolations.SastScanResults != nil || targetResult.JasResults.JasViolations.SastScanResults != nil) && isJasScanFailedInSourceOrTarget(sourceResult.JasResults.JasViolations.SastScanResults, targetResult.JasResults.JasViolations.SastScanResults) {
			log.Debug(fmt.Sprintf(violationsFilteringErrorMessage, scanType.String()))
			sourceResult.JasResults.JasViolations.SastScanResults = nil
		}
	}
}

func isJasScanFailedInSourceOrTarget(sourceResults, targetResults []results.ScanResult[[]*sarif.Run]) bool {
	for _, scanResult := range sourceResults {
		if scanResult.StatusCode != 0 {
			return true
		}
	}

	for _, scanResult := range targetResults {
		if scanResult.StatusCode != 0 {
			return true
		}
	}
	return false
}

func filterOutScaResultsIfScanFailed(targetResult, sourceResult *results.TargetResults) {
	// Filter out new Sca results
	if sourceResult.ScaResults.ScanStatusCode != 0 || targetResult.ScaResults.ScanStatusCode != 0 {
		var statusCode int
		var errorSource string
		if sourceResult.ScaResults.ScanStatusCode != 0 {
			statusCode = sourceResult.ScaResults.ScanStatusCode
			errorSource = "source"
		} else {
			statusCode = targetResult.ScaResults.ScanStatusCode
			errorSource = "target"
		}
		log.Debug(fmt.Sprintf("Sca scan on %s code has completed with errors (status %d). Sca vulnerability results will be removed from final report", errorSource, statusCode))
		sourceResult.ScaResults.Sbom = nil
		if sourceResult.Violations != nil {
			log.Debug(fmt.Sprintf("Sca scan on %s has completed with errors (status %d). Sca violations results will be removed from final report", errorSource, statusCode))
			sourceResult.ScaResults.Violations = nil
		}
	}

	// Note: Although we have a slice on ScanResults in DeprecatedXrayResults, in fact there is only a single entry
	hasScaFailure := false
	for _, deprecatedScaResult := range targetResult.ScaResults.DeprecatedXrayResults {
		if deprecatedScaResult.StatusCode != 0 {
			hasScaFailure = true
			break
		}
	}
	for _, deprecatedScaResult := range sourceResult.ScaResults.DeprecatedXrayResults {
		if deprecatedScaResult.StatusCode != 0 {
			hasScaFailure = true
			break
		}
	}
	if hasScaFailure {
		log.Debug("Sca scan has completed with errors. Sca vulnerabilities and violations results will be removed from final report")
		// Violations are being filtered as well as they are included in the DeprecatedXrayResults
		sourceResult.ScaResults.DeprecatedXrayResults = nil
	}
}

// Sorts the Targets slice in both targetResults and sourceResults
// by the physical location (Target field) of each scan target in ascending order.
func sortTargetsByPhysicalLocation(targetResults, sourceResults *results.SecurityCommandResults) error {
	// If !IncludeAllVulnerabilities we expect targetResults and sourceResults to be non-empty and to have the same amount of targets.
	if len(targetResults.Targets) != len(sourceResults.Targets) {
		return fmt.Errorf("amount of targets in target results is different than source results: %d vs %d", len(targetResults.Targets), len(sourceResults.Targets))
	}
	if len(targetResults.Targets) > 0 {
		sort.Slice(targetResults.Targets, func(i, j int) bool {
			return targetResults.Targets[i].Target < targetResults.Targets[j].Target
		})
	}

	if len(sourceResults.Targets) > 0 {
		sort.Slice(sourceResults.Targets, func(i, j int) bool {
			return sourceResults.Targets[i].Target < sourceResults.Targets[j].Target
		})
	}
	return nil
}

func scanResultsToIssuesCollection(scanResults *results.SecurityCommandResults, allowedLicenses []string, workingDirs ...string) (issuesCollection *issues.ScansIssuesCollection, err error) {
	simpleJsonResults, err := conversion.NewCommandResultsConvertor(conversion.ResultConvertParams{
		IncludeVulnerabilities: scanResults.IncludesVulnerabilities(),
		HasViolationContext:    scanResults.HasViolationContext(),
		IncludeLicenses:        true,
		SimplifiedOutput:       true,
	}).ConvertToSimpleJson(scanResults)
	if err != nil {
		return nil, err
	}
	issuesCollection = &issues.ScansIssuesCollection{
		ScanStatus:         simpleJsonResults.Statuses,
		ScaVulnerabilities: simpleJsonResults.Vulnerabilities,
		ScaViolations:      simpleJsonResults.SecurityViolations,
		LicensesViolations: simpleJsonResults.LicensesViolations,

		IacVulnerabilities: simpleJsonResults.IacsVulnerabilities,
		IacViolations:      simpleJsonResults.IacsViolations,

		SecretsVulnerabilities: simpleJsonResults.SecretsVulnerabilities,
		SecretsViolations:      simpleJsonResults.SecretsViolations,

		SastVulnerabilities: simpleJsonResults.SastVulnerabilities,
		SastViolations:      simpleJsonResults.SastViolations,
	}
	if len(workingDirs) == 0 {
		workingDirs = scanResults.GetTargetsPaths()
	}
	utils.ConvertSarifPathsToRelative(issuesCollection, workingDirs...)
	return
}

func getResultScanStatues(cmdResults ...*results.SecurityCommandResults) formats.ScanStatus {
	converted := make([]formats.SimpleJsonResults, len(cmdResults))
	for i, cmdResult := range cmdResults {
		convertor := conversion.NewCommandResultsConvertor(conversion.ResultConvertParams{IncludeVulnerabilities: cmdResult.IncludesVulnerabilities(), HasViolationContext: cmdResult.HasViolationContext(), SimplifiedOutput: true})
		var err error
		if converted[i], err = convertor.ConvertToSimpleJson(cmdResult); err != nil {
			log.Debug(fmt.Sprintf("Failed to get scan status for failed scan #%d. Error: %s", i, err.Error()))
			continue
		}
	}
	return getScanStatus(converted...)
}

func prepareTargetForScan(gitDetails utils.Git, scanDetails *utils.ScanDetails) (targetBranchWd string, cleanupTarget func() error, err error) {
	target := gitDetails.PullRequestDetails.Target
	// Download target branch
	if targetBranchWd, cleanupTarget, err = utils.DownloadRepoToTempDir(scanDetails.Client(), target.Owner, target.Repository, target.Name); err != nil {
		return
	}
	if scanDetails.Git.UseMostCommonAncestorAsTarget == nil || !*scanDetails.Git.UseMostCommonAncestorAsTarget {
		return
	}
	log.Debug("Using most common ancestor commit as target branch commit")

	// Get common parent commit between source and target and use it (checkout) to the target branch commit
	repoCloneUrl, err := scanDetails.GetRepositoryHttpsCloneUrl(scanDetails.Client())
	if err != nil {
		return
	}
	if e := tryCheckoutToMostCommonAncestor(scanDetails, gitDetails.PullRequestDetails.Source.Name, target.Name, targetBranchWd, repoCloneUrl); e != nil {
		log.Warn(fmt.Sprintf("Failed to get best common ancestor commit between source branch: %s and target branch: %s, defaulting to target branch commit. Error: %s", gitDetails.PullRequestDetails.Source.Name, target.Name, e.Error()))
	}
	return
}

func tryCheckoutToMostCommonAncestor(scanDetails *utils.ScanDetails, baseBranch, headBranch, targetBranchWd, cloneRepoUrl string) (err error) {
	// Change working directory to the temp target branch directory
	cwd, err := os.Getwd()
	if err != nil {
		return
	}
	if err = os.Chdir(targetBranchWd); err != nil {
		return
	}
	defer func() {
		err = errors.Join(err, os.Chdir(cwd))
	}()
	// Create a new git manager and fetch
	gitManager, err := utils.NewGitManager().SetAuth(scanDetails.Username, scanDetails.Token).SetRemoteGitUrl(cloneRepoUrl)
	if err != nil {
		return
	}
	if err = gitManager.Fetch(); err != nil {
		return
	}
	// Get the most common ancestor commit hash
	bestAncestorHash, err := gitManager.GetMostCommonAncestorHash(baseBranch, headBranch)
	if err != nil {
		return
	}
	return gitManager.CheckoutToHash(bestAncestorHash)
}

func getScanStatus(cmdResults ...formats.SimpleJsonResults) formats.ScanStatus {
	if len(cmdResults) == 0 {
		return formats.ScanStatus{}
	}
	if len(cmdResults) == 1 {
		return cmdResults[0].Statuses
	}
	statuses := cmdResults[0].Statuses
	for _, sourceResults := range cmdResults[1:] {
		statuses.ScaStatusCode = getWorstScanStatus(statuses.ScaStatusCode, sourceResults.Statuses.ScaStatusCode)
		statuses.IacStatusCode = getWorstScanStatus(statuses.IacStatusCode, sourceResults.Statuses.IacStatusCode)
		statuses.SecretsStatusCode = getWorstScanStatus(statuses.SecretsStatusCode, sourceResults.Statuses.SecretsStatusCode)
		statuses.SastStatusCode = getWorstScanStatus(statuses.SastStatusCode, sourceResults.Statuses.SastStatusCode)
		statuses.ApplicabilityStatusCode = getWorstScanStatus(statuses.ApplicabilityStatusCode, sourceResults.Statuses.ApplicabilityStatusCode)
	}
	return statuses
}

func getWorstScanStatus(targetStatus, sourceStatus *int) *int {
	if sourceStatus == nil && targetStatus == nil {
		// Scan not performed.
		return nil
	}
	if targetStatus == nil {
		return sourceStatus
	}
	if sourceStatus == nil {
		return targetStatus
	}
	if *sourceStatus == 0 {
		return targetStatus
	}
	return sourceStatus
}
