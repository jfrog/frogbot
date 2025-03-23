package scanpullrequest

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/jfrog/frogbot/v2/utils"
	"github.com/jfrog/frogbot/v2/utils/issues"
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/froggit-go/vcsutils"
	"github.com/jfrog/gofrog/datastructures"
	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/results/conversion"
	"github.com/jfrog/jfrog-cli-security/utils/xsc"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray/services"
)

const (
	SecurityIssueFoundErr   = "issues were detected by Frogbot\n You can avoid marking the Frogbot scan as failed by setting failOnSecurityIssues to false in the " + utils.FrogbotConfigFile + " file"
	noGitHubEnvErr          = "frogbot did not scan this PR, because a GitHub Environment named 'frogbot' does not exist. Please refer to the Frogbot documentation for instructions on how to create the Environment"
	noGitHubEnvReviewersErr = "frogbot did not scan this PR, because the existing GitHub Environment named 'frogbot' doesn't have reviewers selected. Please refer to the Frogbot documentation for instructions on how to create the Environment"
	analyticsScanPrScanType = "PR"
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
	return failFlagSet && issues.IssuesExists(repo.PullRequestSecretComments)
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
		SetFailOnInstallationErrors(*repoConfig.FailOnSecurityIssues).
		SetConfigProfile(repoConfig.ConfigProfile).
		SetSkipAutoInstall(repoConfig.SkipAutoInstall).
		SetDisableJas(repoConfig.DisableJas).
		SetXscPRGitInfoContext(repoConfig.Project, client, repoConfig.PullRequestDetails).
		SetDiffScan(true)
	return scanDetails.SetMinSeverity(repoConfig.MinSeverity)
}

func prepareSourceCodeForScan(repoConfig *utils.Repository, scanDetails *utils.ScanDetails) (sourceBranchWd, targetBranchWd string, cleanup func() error, err error) {
	var cleanupSource func() error
	cleanupTarget := func() error { return nil }

	log.Info("Downloading source branch code...")
	if sourceBranchWd, cleanupSource, err = utils.DownloadRepoToTempDir(scanDetails.Client(),
		scanDetails.PullRequestDetails.Source.Owner,
		scanDetails.PullRequestDetails.Source.Repository,
		scanDetails.PullRequestDetails.Source.Name,
	); err != nil {
		err = fmt.Errorf("failed to download source branch code. Error: %s", err.Error())
		return
	}
	cleanup = cleanupSource
	if repoConfig.IncludeAllVulnerabilities {
		// No need to download target branch
		log.Info("Frogbot is configured to show all issues at source branch")
		return
	}
	if targetBranchWd, cleanupTarget, err = prepareTargetForScan(repoConfig.Git, scanDetails); err != nil {
		err = fmt.Errorf("failed to download target branch code. Error: %s", err.Error())
		return
	}
	cleanup = func() error { return errors.Join(cleanupSource(), cleanupTarget()) }
	// // Create a new git manager and fetch
	// gitManager, err := utils.NewGitManager().SetAuth(scanDetails.Username, scanDetails.Token).SetRemoteGitUrl(scanDetails.GitRepoHttpsCloneUrl)
	// if err != nil {
	// 	return
	// }
	// gitManager.Diff()
	return
}

func auditPullRequestCode(repoConfig *utils.Repository, scanDetails *utils.ScanDetails, sourceBranchWd, targetBranchWd string) (issuesCollection *issues.ScansIssuesCollection, err error) {
	issuesCollection = &issues.ScansIssuesCollection{}

	for i := range repoConfig.Projects {
		// Reset scan details for each project
		scanDetails.SetProject(&repoConfig.Projects[i]).SetSourceScanResults(nil)
		// Scan source branch of the project
		log.Debug("Scanning source branch code...")
		sourceScanResults, e := auditPullRequestSourceCode(repoConfig, scanDetails, sourceBranchWd)
		if e != nil {
			issuesCollection.AppendStatus(getResultScanStatues(sourceScanResults))
			err = errors.Join(err, fmt.Errorf("failed to audit source branch code for %v project. Error: %s", repoConfig.Projects[i].WorkingDirs, e.Error()))
			continue
		}
		if repoConfig.IncludeAllVulnerabilities {
			// Get all issues that exist in the source branch
			if issues, e := scanResultsToIssuesCollection(sourceScanResults, repoConfig.AllowedLicenses, strings.TrimPrefix(sourceBranchWd, string(filepath.Separator))); e == nil {
				issuesCollection.Append(issues)
			} else {
				issuesCollection.AppendStatus(getResultScanStatues(sourceScanResults))
				err = errors.Join(err, fmt.Errorf("failed to get all issues for %v project. Error: %s", repoConfig.Projects[i].WorkingDirs, e.Error()))
			}
			continue
		}
		log.Debug("Scanning target branch code...")
		// Diff scan, scan target branch and get new issues
		if newIssues, e := auditTargetCodeAndGetDiffIssues(repoConfig, scanDetails.SetSourceScanResults(sourceScanResults), sourceBranchWd, targetBranchWd); e == nil {
			issuesCollection.Append(newIssues)
			continue
		} else if newIssues != nil {
			issuesCollection.AppendStatus(newIssues.ScanStatus)
			err = errors.Join(err, fmt.Errorf("failed to audit target branch code for %v project. Error: %s", repoConfig.Projects[i].WorkingDirs, e.Error()))
		}
	}

	return
}

func auditPullRequestSourceCode(repoConfig *utils.Repository, scanDetails *utils.ScanDetails, sourceBranchWd string) (scanResults *results.SecurityCommandResults, err error) {
	scanResults = scanDetails.RunInstallAndAudit(utils.GetFullPathWorkingDirs(scanDetails.Project.WorkingDirs, sourceBranchWd)...)
	if err = scanResults.GetErrors(); err == nil {
		// Set JAS output flags based on the scan results
		repoConfig.OutputWriter.SetJasOutputFlags(scanResults.EntitledForJas, scanResults.HasJasScansResults(jasutils.Applicability))
	}
	return
}

func auditTargetCodeAndGetDiffIssues(repoConfig *utils.Repository, scanDetails *utils.ScanDetails, sourceBranchWd, targetBranchWd string) (newIssues *issues.ScansIssuesCollection, err error) {
	targetScanResults := scanDetails.RunInstallAndAudit(utils.GetFullPathWorkingDirs(scanDetails.Project.WorkingDirs, targetBranchWd)...)
	if err = targetScanResults.GetErrors(); err != nil {
		return
	}
	return scanResultsToIssuesCollection(targetScanResults, repoConfig.AllowedLicenses, strings.TrimPrefix(sourceBranchWd, string(filepath.Separator)), strings.TrimPrefix(targetBranchWd, string(filepath.Separator)))
}

func scanResultsToIssuesCollection(scanResults *results.SecurityCommandResults, allowedLicenses []string, workingDirs ...string) (issuesCollection *issues.ScansIssuesCollection, err error) {
	simpleJsonResults, err := conversion.NewCommandResultsConvertor(conversion.ResultConvertParams{
		IncludeVulnerabilities: scanResults.IncludesVulnerabilities(),
		HasViolationContext:    scanResults.HasViolationContext(),
		AllowedLicenses:        allowedLicenses,
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
	if !scanDetails.Git.UseMostCommonAncestorAsTarget {
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

func createNewSourceCodeRows(targetResults, sourceResults []formats.SourceCodeRow) []formats.SourceCodeRow {
	targetSourceCodeVulnerabilitiesKeys := datastructures.MakeSet[string]()
	for _, row := range targetResults {
		if row.Fingerprint != "" {
			targetSourceCodeVulnerabilitiesKeys.Add(row.Fingerprint)
		} else {
			targetSourceCodeVulnerabilitiesKeys.Add(row.File + row.Snippet)
		}
	}
	var addedSourceCodeVulnerabilities []formats.SourceCodeRow
	for _, row := range sourceResults {
		if !targetSourceCodeVulnerabilitiesKeys.Exists(row.File+row.Snippet) && !targetSourceCodeVulnerabilitiesKeys.Exists(row.Fingerprint) {
			addedSourceCodeVulnerabilities = append(addedSourceCodeVulnerabilities, row)
		}
	}
	return addedSourceCodeVulnerabilities
}

func getUniqueVulnerabilityOrViolationRows(targetRows, sourceRows []formats.VulnerabilityOrViolationRow) []formats.VulnerabilityOrViolationRow {
	existingRows := make(map[string]formats.VulnerabilityOrViolationRow)
	var newRows []formats.VulnerabilityOrViolationRow
	for _, row := range targetRows {
		existingRows[utils.GetVulnerabiltiesUniqueID(row)] = row
	}
	for _, row := range sourceRows {
		if _, exists := existingRows[utils.GetVulnerabiltiesUniqueID(row)]; !exists {
			newRows = append(newRows, row)
		}
	}
	return newRows
}

func getUniqueLicenseRows(targetRows, sourceRows []formats.LicenseViolationRow) []formats.LicenseViolationRow {
	existingLicenses := make(map[string]formats.LicenseViolationRow)
	var newLicenses []formats.LicenseViolationRow
	for _, row := range targetRows {
		existingLicenses[getUniqueLicenseKey(row.LicenseRow)] = row
	}
	for _, row := range sourceRows {
		if _, exists := existingLicenses[getUniqueLicenseKey(row.LicenseRow)]; !exists {
			newLicenses = append(newLicenses, row)
		}
	}
	return newLicenses
}

func getUniqueLicenseKey(license formats.LicenseRow) string {
	return license.LicenseKey + license.ImpactedDependencyName + license.ImpactedDependencyType
}

func aggregateScanResults(scanResults []services.ScanResponse) services.ScanResponse {
	aggregateResults := services.ScanResponse{
		Violations:      []services.Violation{},
		Vulnerabilities: []services.Vulnerability{},
		Licenses:        []services.License{},
	}
	for _, scanResult := range scanResults {
		aggregateResults.Violations = append(aggregateResults.Violations, scanResult.Violations...)
		aggregateResults.Vulnerabilities = append(aggregateResults.Vulnerabilities, scanResult.Vulnerabilities...)
		aggregateResults.Licenses = append(aggregateResults.Licenses, scanResult.Licenses...)
	}
	return aggregateResults
}
