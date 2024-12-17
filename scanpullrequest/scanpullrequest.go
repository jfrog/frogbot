package scanpullrequest

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/jfrog/frogbot/v2/utils"
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

type ScanPullRequestCmd struct {
	XrayVersion string
}

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
	issues, err := auditPullRequest(repo, client)
	if err != nil {
		return
	}

	// Output results
	shouldSendExposedSecretsEmail := issues.SecretsExists() && repo.SmtpServer != ""
	if shouldSendExposedSecretsEmail {
		secretsEmailDetails := utils.NewSecretsEmailDetails(client, repo, issues.Secrets)
		if err = utils.AlertSecretsExposed(secretsEmailDetails); err != nil {
			return
		}
	}

	// Handle PR comments for scan output
	if err = utils.HandlePullRequestCommentsAfterScan(issues, repo, client, int(pullRequestDetails.ID)); err != nil {
		return
	}

	// Fail the Frogbot task if a security issue is found and Frogbot isn't configured to avoid the failure.
	if toFailTaskStatus(repo, issues) {
		err = errors.New(SecurityIssueFoundErr)
		return
	}
	return
}

func toFailTaskStatus(repo *utils.Repository, issues *utils.IssuesCollection) bool {
	failFlagSet := repo.FailOnSecurityIssues != nil && *repo.FailOnSecurityIssues
	return failFlagSet && issues.IssuesExists()
}

// Downloads Pull Requests branches code and audits them
func auditPullRequest(repoConfig *utils.Repository, client vcsclient.VcsClient) (issuesCollection *utils.IssuesCollection, err error) {
	scanDetails := utils.NewScanDetails(client, &repoConfig.Server, &repoConfig.Git).
		SetXrayGraphScanParams(repoConfig.Watches, repoConfig.JFrogProjectKey, len(repoConfig.AllowedLicenses) > 0).
		SetFixableOnly(repoConfig.FixableOnly).
		SetFailOnInstallationErrors(*repoConfig.FailOnSecurityIssues).
		SetConfigProfile(repoConfig.ConfigProfile).
		SetSkipAutoInstall(repoConfig.SkipAutoInstall).
		SetDisableJas(repoConfig.DisableJas)
	if scanDetails, err = scanDetails.SetMinSeverity(repoConfig.MinSeverity); err != nil {
		return
	}
	scanDetails.XrayVersion = repoConfig.XrayVersion
	scanDetails.XscVersion = repoConfig.XscVersion

	scanDetails.MultiScanId, scanDetails.StartTime = xsc.SendNewScanEvent(
		scanDetails.XrayVersion,
		scanDetails.XscVersion,
		scanDetails.ServerDetails,
		utils.CreateScanEvent(scanDetails.ServerDetails, nil, analyticsScanPrScanType),
	)

	defer func() {
		if issuesCollection != nil {
			xsc.SendScanEndedEvent(scanDetails.XrayVersion, scanDetails.XscVersion, scanDetails.ServerDetails, scanDetails.MultiScanId, scanDetails.StartTime, issuesCollection.CountIssuesCollectionFindings(), err)
		}
	}()

	issuesCollection = &utils.IssuesCollection{}
	for i := range repoConfig.Projects {
		scanDetails.SetProject(&repoConfig.Projects[i])
		var projectIssues *utils.IssuesCollection
		if projectIssues, err = auditPullRequestInProject(repoConfig, scanDetails); err != nil {
			return
		}
		issuesCollection.Append(projectIssues)
	}
	return
}

func auditPullRequestInProject(repoConfig *utils.Repository, scanDetails *utils.ScanDetails) (auditIssues *utils.IssuesCollection, err error) {
	// Download source branch
	sourcePullRequestInfo := scanDetails.PullRequestDetails.Source
	sourceBranchWd, cleanupSource, err := utils.DownloadRepoToTempDir(scanDetails.Client(), sourcePullRequestInfo.Owner, sourcePullRequestInfo.Repository, sourcePullRequestInfo.Name)
	if err != nil {
		return
	}
	defer func() {
		err = errors.Join(err, cleanupSource())
	}()

	// Audit source branch
	var sourceResults *results.SecurityCommandResults
	workingDirs := utils.GetFullPathWorkingDirs(scanDetails.Project.WorkingDirs, sourceBranchWd)
	log.Info("Scanning source branch...")
	sourceResults = scanDetails.RunInstallAndAudit(workingDirs...)
	if err = sourceResults.GetErrors(); err != nil {
		return
	}

	// Set JAS output flags
	repoConfig.OutputWriter.SetJasOutputFlags(sourceResults.EntitledForJas, len(sourceResults.GetJasScansResults(jasutils.Applicability)) > 0)

	// Get all issues that exist in the source branch
	if repoConfig.IncludeAllVulnerabilities {
		if auditIssues, err = getAllIssues(sourceResults, repoConfig.AllowedLicenses, scanDetails.HasViolationContext()); err != nil {
			return
		}
		utils.ConvertSarifPathsToRelative(auditIssues, sourceBranchWd)
		return
	}

	var targetBranchWd string
	if auditIssues, targetBranchWd, err = auditTargetBranch(repoConfig, scanDetails, sourceResults); err != nil {
		return
	}
	utils.ConvertSarifPathsToRelative(auditIssues, sourceBranchWd, targetBranchWd)
	return
}

func auditTargetBranch(repoConfig *utils.Repository, scanDetails *utils.ScanDetails, sourceScanResults *results.SecurityCommandResults) (newIssues *utils.IssuesCollection, targetBranchWd string, err error) {
	// Download target branch (if needed)
	cleanupTarget := func() error { return nil }
	if !repoConfig.IncludeAllVulnerabilities {
		if targetBranchWd, cleanupTarget, err = prepareTargetForScan(repoConfig.PullRequestDetails, scanDetails); err != nil {
			return
		}
	}
	defer func() {
		err = errors.Join(err, cleanupTarget())
	}()

	// Set target branch scan details
	var targetResults *results.SecurityCommandResults
	workingDirs := utils.GetFullPathWorkingDirs(scanDetails.Project.WorkingDirs, targetBranchWd)
	log.Info("Scanning target branch...")
	targetResults = scanDetails.RunInstallAndAudit(workingDirs...)
	if err = targetResults.GetErrors(); err != nil {
		return
	}

	// Get newly added issues
	newIssues, err = getNewlyAddedIssues(targetResults, sourceScanResults, repoConfig.AllowedLicenses, scanDetails.HasViolationContext())
	return
}

func prepareTargetForScan(pullRequestDetails vcsclient.PullRequestInfo, scanDetails *utils.ScanDetails) (targetBranchWd string, cleanupTarget func() error, err error) {
	target := pullRequestDetails.Target
	// Download target branch
	if targetBranchWd, cleanupTarget, err = utils.DownloadRepoToTempDir(scanDetails.Client(), target.Owner, target.Repository, target.Name); err != nil {
		return
	}
	if !scanDetails.Git.UseMostCommonAncestorAsTarget {
		return
	}
	log.Debug("Using most common ancestor commit as target branch commit")
	// Get common parent commit between source and target and use it (checkout) to the target branch commit
	if e := tryCheckoutToMostCommonAncestor(scanDetails, pullRequestDetails.Source.Name, target.Name, targetBranchWd); e != nil {
		log.Warn(fmt.Sprintf("Failed to get best common ancestor commit between source branch: %s and target branch: %s, defaulting to target branch commit. Error: %s", pullRequestDetails.Source.Name, target.Name, e.Error()))
	}
	return
}

func tryCheckoutToMostCommonAncestor(scanDetails *utils.ScanDetails, baseBranch, headBranch, targetBranchWd string) (err error) {
	repositoryInfo, err := scanDetails.Client().GetRepositoryInfo(context.Background(), scanDetails.RepoOwner, scanDetails.RepoName)
	if err != nil {
		return
	}
	scanDetails.Git.RepositoryCloneUrl = repositoryInfo.CloneInfo.HTTP
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
	gitManager, err := utils.NewGitManager().SetAuth(scanDetails.Username, scanDetails.Token).SetRemoteGitUrl(scanDetails.Git.RepositoryCloneUrl)
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

func getAllIssues(cmdResults *results.SecurityCommandResults, allowedLicenses []string, hasViolationContext bool) (*utils.IssuesCollection, error) {
	log.Info("Frogbot is configured to show all vulnerabilities")
	simpleJsonResults, err := conversion.NewCommandResultsConvertor(conversion.ResultConvertParams{
		IncludeVulnerabilities: true,
		HasViolationContext:    hasViolationContext,
		AllowedLicenses:        allowedLicenses,
		IncludeLicenses:        true,
		SimplifiedOutput:       true,
	}).ConvertToSimpleJson(cmdResults)
	if err != nil {
		return nil, err
	}
	return &utils.IssuesCollection{
		Vulnerabilities: append(simpleJsonResults.Vulnerabilities, simpleJsonResults.SecurityViolations...),
		Iacs:            simpleJsonResults.Iacs,
		Secrets:         simpleJsonResults.Secrets,
		Sast:            simpleJsonResults.Sast,
		Licenses:        simpleJsonResults.LicensesViolations,
	}, nil
}

// Returns all the issues found in the source branch that didn't exist in the target branch.
func getNewlyAddedIssues(targetResults, sourceResults *results.SecurityCommandResults, allowedLicenses []string, hasViolationContext bool) (*utils.IssuesCollection, error) {
	var err error
	convertor := conversion.NewCommandResultsConvertor(conversion.ResultConvertParams{IncludeVulnerabilities: true, HasViolationContext: hasViolationContext, IncludeLicenses: len(allowedLicenses) > 0, AllowedLicenses: allowedLicenses, SimplifiedOutput: true})
	simpleJsonSource, err := convertor.ConvertToSimpleJson(sourceResults)
	if err != nil {
		return nil, err
	}
	simpleJsonTarget, err := convertor.ConvertToSimpleJson(targetResults)
	if err != nil {
		return nil, err
	}

	var newVulnerabilitiesOrViolations []formats.VulnerabilityOrViolationRow
	if len(simpleJsonSource.Vulnerabilities) > 0 || len(simpleJsonSource.SecurityViolations) > 0 {
		newVulnerabilitiesOrViolations = append(
			getUniqueVulnerabilityOrViolationRows(simpleJsonTarget.Vulnerabilities, simpleJsonSource.Vulnerabilities),
			getUniqueVulnerabilityOrViolationRows(simpleJsonTarget.SecurityViolations, simpleJsonSource.SecurityViolations)...,
		)
	}

	var newLicenses []formats.LicenseRow
	if len(simpleJsonSource.LicensesViolations) > 0 {
		newLicenses = getUniqueLicenseRows(simpleJsonTarget.LicensesViolations, simpleJsonSource.LicensesViolations)
	}

	var newIacs []formats.SourceCodeRow
	if len(simpleJsonSource.Iacs) > 0 {
		newIacs = createNewSourceCodeRows(simpleJsonTarget.Iacs, simpleJsonSource.Iacs)
	}
	var newSecrets []formats.SourceCodeRow
	if len(simpleJsonSource.Secrets) > 0 {
		newSecrets = createNewSourceCodeRows(simpleJsonTarget.Secrets, simpleJsonSource.Secrets)
	}
	var newSast []formats.SourceCodeRow
	if len(simpleJsonSource.Sast) > 0 {
		newSast = createNewSourceCodeRows(simpleJsonTarget.Sast, simpleJsonSource.Sast)
	}

	return &utils.IssuesCollection{
		Vulnerabilities: newVulnerabilitiesOrViolations,
		Iacs:            newIacs,
		Secrets:         newSecrets,
		Sast:            newSast,
		Licenses:        newLicenses,
	}, nil
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

func getUniqueLicenseRows(targetRows, sourceRows []formats.LicenseRow) []formats.LicenseRow {
	existingLicenses := make(map[string]formats.LicenseRow)
	var newLicenses []formats.LicenseRow
	for _, row := range targetRows {
		existingLicenses[getUniqueLicenseKey(row)] = row
	}
	for _, row := range sourceRows {
		if _, exists := existingLicenses[getUniqueLicenseKey(row)]; !exists {
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
