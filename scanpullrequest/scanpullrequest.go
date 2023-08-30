package scanpullrequest

import (
	"context"
	"errors"
	"fmt"
	"github.com/jfrog/frogbot/utils"
	"github.com/jfrog/frogbot/utils/outputwriter"
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/froggit-go/vcsutils"
	"github.com/jfrog/gofrog/datastructures"
	audit "github.com/jfrog/jfrog-cli-core/v2/xray/commands/audit/generic"
	"github.com/jfrog/jfrog-cli-core/v2/xray/formats"
	xrayutils "github.com/jfrog/jfrog-cli-core/v2/xray/utils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray/services"
	"golang.org/x/exp/slices"
	"os"
	"strings"
)

const (
	securityIssueFoundErr   = "issues were detected by Frogbot\n You can avoid marking the Frogbot scan as failed by setting failOnSecurityIssues to false in the " + utils.FrogbotConfigFile + " file"
	noGitHubEnvErr          = "frogbot did not scan this PR, because a GitHub Environment named 'frogbot' does not exist. Please refer to the Frogbot documentation for instructions on how to create the Environment"
	noGitHubEnvReviewersErr = "frogbot did not scan this PR, because the existing GitHub Environment named 'frogbot' doesn't have reviewers selected. Please refer to the Frogbot documentation for instructions on how to create the Environment"
	frogbotCommentNotFound  = -1
)

type ScanPullRequestCmd struct{}

type issuesRows struct {
	Vulnerabilities []formats.VulnerabilityOrViolationRow
	Iacs            []formats.IacSecretsRow
	Secrets         []formats.IacSecretsRow
	Licenses        []formats.LicenseBaseWithKey
}

func (ir *issuesRows) VulnerabilitiesExists() bool {
	return len(ir.Vulnerabilities) > 0
}

func (ir *issuesRows) IacExists() bool {
	return len(ir.Iacs) > 0
}

func (ir *issuesRows) LicensesExists() bool {
	return len(ir.Licenses) > 0
}

func (ir *issuesRows) SecretsExists() bool {
	return len(ir.Secrets) > 0
}

func (ir *issuesRows) Append(issues *issuesRows) {
	if len(issues.Vulnerabilities) > 0 {
		ir.Vulnerabilities = append(ir.Vulnerabilities, issues.Vulnerabilities...)
	}
	if len(issues.Secrets) > 0 {
		ir.Secrets = append(ir.Secrets, issues.Secrets...)
	}
	if len(issues.Iacs) > 0 {
		ir.Iacs = append(ir.Iacs, issues.Iacs...)
	}
	if len(issues.Licenses) > 0 {
		ir.Licenses = append(ir.Licenses, issues.Licenses...)
	}
}

// Run ScanPullRequest method only works for a single repository scan.
// Therefore, the first repository config represents the repository on which Frogbot runs, and it is the only one that matters.
func (cmd *ScanPullRequestCmd) Run(configAggregator utils.RepoAggregator, client vcsclient.VcsClient) (err error) {
	if err = utils.ValidateSingleRepoConfiguration(&configAggregator); err != nil {
		return
	}
	repoConfig := &(configAggregator)[0]
	if repoConfig.GitProvider == vcsutils.GitHub {
		if err = verifyGitHubFrogbotEnvironment(client, repoConfig); err != nil {
			return
		}
	}

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
	issues, err := auditPullRequest(repo, client, pullRequestDetails)
	if err != nil {
		return
	}

	shouldSendExposedSecretsEmail := issues.SecretsExists() && repo.SmtpServer != ""
	if shouldSendExposedSecretsEmail {
		secretsEmailDetails := utils.NewSecretsEmailDetails(client, repo, &pullRequestDetails, issues.Secrets)
		if err = utils.AlertSecretsExposed(secretsEmailDetails); err != nil {
			return
		}
	}

	// Delete previous Frogbot pull request message if exists
	if err = deleteExistingPullRequestComment(repo, client); err != nil {
		return
	}

	// Create a pull request message
	message := createPullRequestComment(issues, repo.OutputWriter)

	// Add comment to the pull request
	if err = client.AddPullRequestComment(context.Background(), repo.RepoOwner, repo.RepoName, message, int(pullRequestDetails.ID)); err != nil {
		err = errors.New("couldn't add pull request comment: " + err.Error())
		return
	}

	// Fail the Frogbot task if a security issue is found and Frogbot isn't configured to avoid the failure.
	if toFailTaskStatus(repo, issues) {
		err = errors.New(securityIssueFoundErr)
	}
	return
}

func toFailTaskStatus(repo *utils.Repository, issues *issuesRows) bool {
	failFlagSet := repo.FailOnSecurityIssues != nil && *repo.FailOnSecurityIssues
	issuesExists := issues.VulnerabilitiesExists() || issues.IacExists() || issues.LicensesExists()
	return failFlagSet && issuesExists
}

// Downloads Pull Requests branches code and audits them
func auditPullRequest(repoConfig *utils.Repository, client vcsclient.VcsClient, pullRequestDetails vcsclient.PullRequestInfo) (issues *issuesRows, err error) {
	// Download source branch
	sourceBranchInfo := pullRequestDetails.Source
	sourceBranchWd, cleanupSource, err := utils.DownloadRepoToTempDir(client, sourceBranchInfo.Owner, sourceBranchInfo.Repository, sourceBranchInfo.Name)
	if err != nil {
		return
	}

	// Download target branch (if needed)
	targetBranchWd := ""
	cleanupTarget := func() error { return nil }
	if !repoConfig.IncludeAllVulnerabilities {
		targetBranchInfo := pullRequestDetails.Target
		if targetBranchWd, cleanupTarget, err = utils.DownloadRepoToTempDir(client, targetBranchInfo.Owner, targetBranchInfo.Repository, targetBranchInfo.Name); err != nil {
			return
		}

	}
	defer func() {
		err = errors.Join(err, cleanupSource(), cleanupTarget())
	}()

	scanDetails := utils.NewScanDetails(client, &repoConfig.Server, &repoConfig.Git).
		SetXrayGraphScanParams(repoConfig.Watches, repoConfig.JFrogProjectKey, true).
		SetMinSeverity(repoConfig.MinSeverity).
		SetFixableOnly(repoConfig.FixableOnly).
		SetFailOnInstallationErrors(*repoConfig.FailOnSecurityIssues)

	for i := range repoConfig.Projects {
		scanDetails.SetProject(&repoConfig.Projects[i])
		var projectIssues *issuesRows
		projectIssues, err = auditPullRequestInProject(repoConfig, scanDetails, sourceBranchWd, targetBranchWd)
		issues.Append(projectIssues)
	}
	return
}

func auditPullRequestInProject(repoConfig *utils.Repository, scanDetails *utils.ScanDetails, sourceBranchWd, targetBranchWd string) (newIssues *issuesRows, err error) {
	// Audit source branch
	var sourceResults *audit.Results
	workingDirs := utils.GetFullPathWorkingDirs(scanDetails.Project.WorkingDirs, sourceBranchWd)
	sourceResults, err = scanDetails.RunInstallAndAudit(workingDirs...)
	if err != nil {
		return
	}

	// Set JAS output flags
	sourceScanResults := sourceResults.ExtendedScanResults
	repoConfig.OutputWriter.SetJasOutputFlags(sourceScanResults.EntitledForJas, len(sourceScanResults.ApplicabilityScanResults) > 0)

	// Get all issues that were found in the source branch
	if repoConfig.IncludeAllVulnerabilities {
		return getAllIssues(sourceResults, repoConfig.AllowedLicenses)
	}

	// Set target branch scan details
	var targetResults *audit.Results
	workingDirs = utils.GetFullPathWorkingDirs(scanDetails.Project.WorkingDirs, targetBranchWd)
	targetResults, err = scanDetails.RunInstallAndAudit(workingDirs...)
	if err != nil {
		return
	}

	// Get new issues
	return getNewIssues(targetResults, sourceResults, repoConfig.AllowedLicenses)
}

func getAllIssues(results *audit.Results, allowedLicenses []string) (*issuesRows, error) {
	log.Info("Frogbot is configured to show all vulnerabilities")
	scanResults := results.ExtendedScanResults
	allVulnerabilitiesRows, forbiddenLicenses, err := getScanVulnerabilitiesRows(results, allowedLicenses)
	if err != nil {
		return nil, err
	}
	return &issuesRows{
		Vulnerabilities: allVulnerabilitiesRows,
		Iacs:            xrayutils.PrepareIacs(scanResults.IacScanResults),
		Secrets:         xrayutils.PrepareSecrets(scanResults.SecretsScanResults),
		Licenses:        forbiddenLicenses,
	}, nil
}

func getNewIssues(targetResults, sourceResults *audit.Results, allowedLicenses []string) (*issuesRows, error) {
	var newVulnerabilitiesOrViolations []formats.VulnerabilityOrViolationRow
	var newLicenses []formats.LicenseBaseWithKey
	var err error
	if len(sourceResults.ExtendedScanResults.XrayResults) > 0 {
		if newVulnerabilitiesOrViolations, newLicenses, err = createNewVulnerabilitiesRows(targetResults, sourceResults, allowedLicenses); err != nil {
			return nil, err
		}
	}

	var newIacs []formats.IacSecretsRow
	if len(sourceResults.ExtendedScanResults.IacScanResults) > 0 {
		targetIacRows := xrayutils.PrepareIacs(targetResults.ExtendedScanResults.IacScanResults)
		sourceIacRows := xrayutils.PrepareIacs(sourceResults.ExtendedScanResults.IacScanResults)
		newIacs = createNewIacOrSecretsRows(targetIacRows, sourceIacRows)
	}

	var newSecrets []formats.IacSecretsRow
	if len(sourceResults.ExtendedScanResults.SecretsScanResults) > 0 {
		targetSecretsRows := xrayutils.PrepareSecrets(targetResults.ExtendedScanResults.SecretsScanResults)
		sourceSecretsRows := xrayutils.PrepareSecrets(sourceResults.ExtendedScanResults.SecretsScanResults)
		newSecrets = createNewIacOrSecretsRows(targetSecretsRows, sourceSecretsRows)
	}

	return &issuesRows{
		Vulnerabilities: newVulnerabilitiesOrViolations,
		Iacs:            newIacs,
		Secrets:         newSecrets,
		Licenses:        newLicenses,
	}, nil
}

func createNewIacOrSecretsRows(targetResults, sourceResults []formats.IacSecretsRow) []formats.IacSecretsRow {
	targetIacOrSecretsVulnerabilitiesKeys := datastructures.MakeSet[string]()
	for _, row := range targetResults {
		targetIacOrSecretsVulnerabilitiesKeys.Add(row.File + row.Text)
	}
	var addedIacOrSecretsVulnerabilities []formats.IacSecretsRow
	for _, row := range sourceResults {
		if !targetIacOrSecretsVulnerabilitiesKeys.Exists(row.File + row.Text) {
			addedIacOrSecretsVulnerabilities = append(addedIacOrSecretsVulnerabilities, row)
		}
	}
	return addedIacOrSecretsVulnerabilities
}

// The rows should contain only the new issues added by this PR
func createNewVulnerabilitiesRows(targetResults, sourceResults *audit.Results, allowedLicenses []string) (vulnerabilityOrViolationRows []formats.VulnerabilityOrViolationRow, licenseRows []formats.LicenseBaseWithKey, err error) {
	targetScanAggregatedResults := aggregateScanResults(targetResults.ExtendedScanResults.XrayResults)
	sourceScanAggregatedResults := aggregateScanResults(sourceResults.ExtendedScanResults.XrayResults)

	if len(sourceScanAggregatedResults.Violations) > 0 {
		return getNewViolations(&targetScanAggregatedResults, &sourceScanAggregatedResults, sourceResults)
	}
	if len(sourceScanAggregatedResults.Vulnerabilities) > 0 {
		if vulnerabilityOrViolationRows, err = getNewSecurityVulnerabilities(&targetScanAggregatedResults, &sourceScanAggregatedResults, sourceResults); err != nil {
			return
		}
	}
	var newLicenses []formats.LicenseBaseWithKey
	if newLicenses, err = getNewLicenseRows(&targetScanAggregatedResults, &sourceScanAggregatedResults); err != nil {
		return
	}
	licenseRows = getForbiddenLicenses(allowedLicenses, newLicenses)
	return
}

func getNewLicenseRows(targetScan, sourceScan *services.ScanResponse) (newLicenses []formats.LicenseBaseWithKey, err error) {
	targetLicenses, err := xrayutils.PrepareLicenses(targetScan.Licenses)
	if err != nil {
		return
	}
	sourceLicenses, err := xrayutils.PrepareLicenses(sourceScan.Licenses)
	if err != nil {
		return
	}
	var sourceLicensesWithKeys, targetLicensesWithKeys []formats.LicenseBaseWithKey
	if sourceLicensesWithKeys, err = getBaseLicensesWithKeys(sourceLicenses); err != nil {
		return
	}
	if targetLicensesWithKeys, err = getBaseLicensesWithKeys(targetLicenses); err != nil {
		return
	}
	newLicenses = getUniqueLicenseRows(targetLicensesWithKeys, sourceLicensesWithKeys)
	return
}

func aggregateScanResults(scanResults []services.ScanResponse) services.ScanResponse {
	aggregateResults := services.ScanResponse{
		Violations:      []services.Violation{},
		Vulnerabilities: []services.Vulnerability{},
		Licenses:        []services.License{},
	}
	for _, scanResult := range scanResults {
		aggregateResults.Licenses = append(aggregateResults.Licenses, scanResult.Licenses...)
		aggregateResults.Violations = append(aggregateResults.Violations, scanResult.Violations...)
		aggregateResults.Vulnerabilities = append(aggregateResults.Vulnerabilities, scanResult.Vulnerabilities...)
	}
	return aggregateResults
}

// Create vulnerability rows. The rows should contain all the issues that were found in this module scan.
func getScanVulnerabilitiesRows(auditResults *audit.Results, allowedLicenses []string) (vulnerabilitiesRows []formats.VulnerabilityOrViolationRow, forbiddenLicenses []formats.LicenseBaseWithKey, err error) {
	violations, vulnerabilities, licenses := xrayutils.SplitScanResults(auditResults.ExtendedScanResults.XrayResults)
	var baseLicensesWithKey []formats.LicenseBaseWithKey
	if len(violations) > 0 {
		var licenseViolationsRows []formats.LicenseViolationRow
		if vulnerabilitiesRows, licenseViolationsRows, _, err = xrayutils.PrepareViolations(violations, auditResults.ExtendedScanResults, auditResults.IsMultipleRootProject, true); err != nil {
			return nil, nil, err
		}
		baseLicensesWithKey, err = getBaseLicensesWithKeys(licenseViolationsRows)
		return vulnerabilitiesRows, baseLicensesWithKey, err
	}
	if len(vulnerabilities) > 0 {
		if vulnerabilitiesRows, err = xrayutils.PrepareVulnerabilities(vulnerabilities, auditResults.ExtendedScanResults, auditResults.IsMultipleRootProject, true); err != nil {
			return
		}
	}
	var licensesRows []formats.LicenseRow
	if licensesRows, err = xrayutils.PrepareLicenses(licenses); err != nil {
		return
	}
	if baseLicensesWithKey, err = getBaseLicensesWithKeys(licensesRows); err != nil {
		return
	}
	forbiddenLicenses = getForbiddenLicenses(allowedLicenses, baseLicensesWithKey)
	return
}

func getForbiddenLicenses(allowedLicenses []string, licenses []formats.LicenseBaseWithKey) []formats.LicenseBaseWithKey {
	var forbiddenLicenses []formats.LicenseBaseWithKey
	for _, license := range licenses {
		if !slices.Contains(allowedLicenses, license.LicenseKey) {
			forbiddenLicenses = append(forbiddenLicenses, license)
		}
	}
	return forbiddenLicenses
}

func getNewViolations(targetScan, sourceScan *services.ScanResponse, auditResults *audit.Results) (newSecurityViolationsRows []formats.VulnerabilityOrViolationRow, newLicenseViolationsRows []formats.LicenseBaseWithKey, err error) {
	targetSecurityViolationsRows, targetLicenseViolationsRows, _, err := xrayutils.PrepareViolations(targetScan.Violations, auditResults.ExtendedScanResults, auditResults.IsMultipleRootProject, true)
	if err != nil {
		return
	}
	sourceSecurityViolationsRows, sourceLicenseViolationsRows, _, err := xrayutils.PrepareViolations(sourceScan.Violations, auditResults.ExtendedScanResults, auditResults.IsMultipleRootProject, true)
	if err != nil {
		return
	}
	newSecurityViolationsRows = getUniqueVulnerabilityOrViolationRows(targetSecurityViolationsRows, sourceSecurityViolationsRows)
	if len(sourceLicenseViolationsRows) > 0 {
		var sourceLicensesWithKeys, targetLicensesWithKeys []formats.LicenseBaseWithKey
		if sourceLicensesWithKeys, err = getBaseLicensesWithKeys(sourceLicenseViolationsRows); err != nil {
			return
		}
		if targetLicensesWithKeys, err = getBaseLicensesWithKeys(targetLicenseViolationsRows); err != nil {
			return
		}
		newLicenseViolationsRows = getUniqueLicenseRows(targetLicensesWithKeys, sourceLicensesWithKeys)
	}
	return
}

func getBaseLicensesWithKeys(licenses interface{}) (results []formats.LicenseBaseWithKey, err error) {
	switch rows := licenses.(type) {
	case []formats.LicenseViolationRow:
		for _, row := range rows {
			results = append(results, row.LicenseBaseWithKey)
		}
	case []formats.LicenseRow:
		for _, row := range rows {
			results = append(results, row.LicenseBaseWithKey)
		}
	default:
		err = fmt.Errorf("unexpected license type received: %T", rows)
	}
	return
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

func getUniqueLicenseRows(targetRows, sourceRows []formats.LicenseBaseWithKey) []formats.LicenseBaseWithKey {
	existingLicenses := make(map[string]formats.LicenseBaseWithKey)
	var newLicenses []formats.LicenseBaseWithKey
	for _, row := range targetRows {
		existingLicenses[row.LicenseKey] = row
	}
	for _, row := range sourceRows {
		if _, exists := existingLicenses[row.LicenseKey]; !exists {
			newLicenses = append(newLicenses, row)
		}
	}
	return newLicenses
}

func getNewSecurityVulnerabilities(targetScan, sourceScan *services.ScanResponse, auditResults *audit.Results) (newVulnerabilitiesRows []formats.VulnerabilityOrViolationRow, err error) {
	targetVulnerabilitiesRows, err := xrayutils.PrepareVulnerabilities(targetScan.Vulnerabilities, auditResults.ExtendedScanResults, auditResults.IsMultipleRootProject, true)
	if err != nil {
		return newVulnerabilitiesRows, err
	}
	sourceVulnerabilitiesRows, err := xrayutils.PrepareVulnerabilities(sourceScan.Vulnerabilities, auditResults.ExtendedScanResults, auditResults.IsMultipleRootProject, true)
	if err != nil {
		return newVulnerabilitiesRows, err
	}
	newVulnerabilitiesRows = getUniqueVulnerabilityOrViolationRows(targetVulnerabilitiesRows, sourceVulnerabilitiesRows)
	return
}

func createPullRequestComment(issues *issuesRows, writer outputwriter.OutputWriter) string {
	if !issues.VulnerabilitiesExists() && !issues.LicensesExists() && !issues.IacExists() {
		return writer.NoVulnerabilitiesTitle() + writer.UntitledForJasMsg() + writer.Footer()
	}
	comment := strings.Builder{}
	comment.WriteString(writer.VulnerabilitiesTitle(true))
	comment.WriteString(writer.VulnerabilitiesContent(issues.Vulnerabilities))
	comment.WriteString(writer.IacContent(issues.Iacs))
	comment.WriteString(writer.LicensesContent(issues.Licenses))
	comment.WriteString(writer.UntitledForJasMsg())
	comment.WriteString(writer.Footer())

	return comment.String()
}

func deleteExistingPullRequestComment(repository *utils.Repository, client vcsclient.VcsClient) error {
	log.Debug("Looking for an existing Frogbot pull request comment. Deleting it if it exists...")
	prDetails := repository.PullRequestDetails
	comments, err := utils.GetSortedPullRequestComments(client, prDetails.Target.Owner, prDetails.Target.Repository, int(prDetails.ID))
	if err != nil {
		return fmt.Errorf(
			"failed to get comments. the following details were used in order to fetch the comments: <%s/%s> pull request #%d. the error received: %s",
			repository.RepoOwner, repository.RepoName, int(repository.PullRequestDetails.ID), err.Error())
	}

	commentID := frogbotCommentNotFound
	for _, comment := range comments {
		if repository.OutputWriter.IsFrogbotResultComment(comment.Content) {
			log.Debug("Found previous Frogbot comment with the id:", comment.ID)
			commentID = int(comment.ID)
			break
		}
	}

	if commentID != frogbotCommentNotFound {
		err = client.DeletePullRequestComment(context.Background(), prDetails.Target.Owner, prDetails.Target.Repository, int(prDetails.ID), commentID)
	}

	return err
}
