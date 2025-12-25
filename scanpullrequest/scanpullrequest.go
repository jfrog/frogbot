package scanpullrequest

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/formats/violationutils"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/results/conversion"
	"github.com/jfrog/jfrog-cli-security/utils/xsc"
	"github.com/jfrog/jfrog-client-go/utils/log"

	"github.com/jfrog/frogbot/v2/utils"
	"github.com/jfrog/frogbot/v2/utils/issues"
)

const (
	SecurityIssueFoundErr = "issues were detected by Frogbot\n" +
		"Security violation with 'fail-pull-request' rule is found"
	analyticsScanPrScanType              = "PR"
	vulnerabilitiesFilteringErrorMessage = "%s scan has completed with errors. Vulnerabilities results will be removed from final report"
	violationsFilteringErrorMessage      = "%s scan has completed with errors. Violations results will be removed from final report"
)

type ScanPullRequestCmd struct{}

func (pr *ScanPullRequestCmd) Run(repository utils.Repository, client vcsclient.VcsClient, frogbotRepoConnection *utils.UrlAccessChecker) (err error) {
	repoConfig := &repository
	repoConfig.OutputWriter.SetHasInternetConnection(frogbotRepoConnection.IsConnected())
	if repoConfig.Params.Git.PullRequestDetails, err = client.GetPullRequestByID(context.Background(),
		repoConfig.Params.Git.RepoOwner, repoConfig.Params.Git.RepoName, int(repoConfig.Params.Git.PullRequestDetails.ID)); err != nil {
		return
	}
	pullRequestDetails := &repository.Params.Git.PullRequestDetails
	log.Info(fmt.Sprintf("Scanning Pull Request #%d (from source branch: <%s/%s/%s> to target branch: <%s/%s/%s>)",
		pullRequestDetails.ID,
		pullRequestDetails.Source.Owner, pullRequestDetails.Source.Repository, pullRequestDetails.Source.Name,
		pullRequestDetails.Target.Owner, pullRequestDetails.Target.Repository, pullRequestDetails.Target.Name))
	log.Info("-----------------------------------------------------------")

	pullRequestIssues, resultContext, err := auditPullRequestAndReport(&repository, client)
	if err != nil {
		return
	}
	if err = utils.HandlePullRequestCommentsAfterScan(pullRequestIssues, resultContext, &repository, client, int(pullRequestDetails.ID)); err != nil {
		return
	}
	if pullRequestIssues.IsFailPrRuleApplied() {
		err = errors.New(SecurityIssueFoundErr)
		return
	}
	return
}

func auditPullRequestAndReport(repoConfig *utils.Repository, client vcsclient.VcsClient) (issuesCollection *issues.ScansIssuesCollection, resultContext results.ResultContext, err error) {
	scanDetails, err := createBaseScanDetails(repoConfig, client)
	if err != nil {
		return
	}
	resultContext = scanDetails.ResultContext
	sourceBranchWd, targetBranchWd, cleanup, err := downloadSourceAndTarget(repoConfig, scanDetails)
	if err != nil {
		return
	}
	defer func() {
		err = errors.Join(err, cleanup())
	}()
	scanDetails.MultiScanId, scanDetails.StartTime = xsc.SendNewScanEvent(
		scanDetails.XrayVersion,
		scanDetails.XscVersion,
		scanDetails.ServerDetails,
		utils.CreateScanEvent(scanDetails.ServerDetails, scanDetails.XscGitInfoContext, analyticsScanPrScanType),
		repoConfig.Params.JFrogPlatform.JFrogProjectKey,
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
	issuesCollection, err = auditPullRequestCode(repoConfig, scanDetails, sourceBranchWd, targetBranchWd)
	return
}

func createBaseScanDetails(repoConfig *utils.Repository, client vcsclient.VcsClient) (scanDetails *utils.ScanDetails, err error) {
	repositoryCloneUrl, err := repoConfig.Params.Git.GetRepositoryHttpsCloneUrl(client)
	if err != nil {
		return
	}
	return utils.NewScanDetails(client, &repoConfig.Server, &repoConfig.Params.Git).
		SetJfrogVersions(repoConfig.Params.XrayVersion, repoConfig.Params.XscVersion).
		SetResultsContext(repositoryCloneUrl, repoConfig.Params.JFrogPlatform.JFrogProjectKey, false).
		SetConfigProfile(repoConfig.Params.ConfigProfile).
		SetDiffScan(true).
		SetXscPRGitInfoContext(repoConfig.Params.Git.Project, client, repoConfig.Params.Git.PullRequestDetails), nil
}

func downloadSourceAndTarget(repoConfig *utils.Repository, scanDetails *utils.ScanDetails) (sourceBranchWd, targetBranchWd string, cleanup func() error, err error) {
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
	target := repoConfig.Params.Git.PullRequestDetails.Target
	if targetBranchWd, cleanupTarget, err = utils.DownloadRepoToTempDir(scanDetails.Client(), target.Owner, target.Repository, target.Name); err != nil {
		err = fmt.Errorf("failed to download target branch code. Error: %s", err.Error())
		return
	}
	return
}

func auditPullRequestCode(repoConfig *utils.Repository, scanDetails *utils.ScanDetails, sourceBranchWd, targetBranchWd string) (issuesCollection *issues.ScansIssuesCollection, err error) {
	issuesCollection = &issues.ScansIssuesCollection{}
	log.Debug("Scanning target branch code...")
	if targetScanResults, e := auditPullRequestTargetCode(scanDetails, targetBranchWd); e != nil {
		issuesCollection.AppendStatus(getResultScanStatues(targetScanResults))
		return issuesCollection, fmt.Errorf("failed to audit target branch. Error: %s", e.Error())
	} else {
		scanDetails.SetResultsToCompare(targetScanResults)
	}
	log.Debug("Scanning source branch code...")
	pullRequestIssues, e := auditPullRequestSourceCode(repoConfig, scanDetails, sourceBranchWd, targetBranchWd)
	if e != nil {
		if pullRequestIssues != nil {
			// Scan error, report the scan status
			issuesCollection.AppendStatus(pullRequestIssues.ScanStatus)
		}
		return issuesCollection, fmt.Errorf("failed to audit source branch code. Error: %s", e.Error())
	}
	issuesCollection.Append(pullRequestIssues)
	return
}

func auditPullRequestTargetCode(scanDetails *utils.ScanDetails, targetBranchWd string) (scanResults *results.SecurityCommandResults, err error) {
	scanResults = scanDetails.Audit(targetBranchWd)
	err = scanResults.GetErrors()
	return
}

func auditPullRequestSourceCode(repoConfig *utils.Repository, scanDetails *utils.ScanDetails, sourceBranchWd, targetBranchWd string) (issuesCollection *issues.ScansIssuesCollection, err error) {
	scanResults := scanDetails.Audit(sourceBranchWd)
	if err = scanResults.GetErrors(); err != nil {
		issuesCollection = &issues.ScansIssuesCollection{ScanStatus: getResultScanStatues(scanResults)}
		return
	}
	// Set JAS output flags based on the scan results
	repoConfig.OutputWriter.SetJasOutputFlags(scanResults.EntitledForJas, scanResults.HasJasScansResults(jasutils.Applicability))
	workingDirs := []string{strings.TrimPrefix(sourceBranchWd, string(filepath.Separator))}
	if targetBranchWd != "" && scanDetails.ResultsToCompare != nil {
		log.Debug("Diff scan - converting to new issues...")
		workingDirs = append(workingDirs, strings.TrimPrefix(targetBranchWd, string(filepath.Separator)))
	}

	/*
		if !repoConfig.Params.ConfigProfile.GeneralConfig.FailUponAnyScannerError {
			if err = filterOutFailedScans(scanDetails.ResultsToCompare, scanResults); err != nil {
				return
			}
		}
	*/

	issuesCollection, e := scanResultsToIssuesCollection(scanResults, workingDirs...)
	if e != nil {
		err = errors.Join(err, fmt.Errorf("failed to get issues for pull request. Error: %s", e.Error()))
	}
	return
}

// if we found any error in any of its results (non-zero status code) in either source or target results.
// This logic prevents us from presenting incorrect results due to an incomplete scan that produced incomplete results that might affect the diff process.
func filterOutFailedScans(targetResults, sourceResults *results.SecurityCommandResults) error {
	if targetResults == nil {
		return nil
	}

	// If both source & target results exists, we need to filter out results of scans that failed in either source or target results, to avoid presenting incorrect diff results
	if err := sortTargetsByPhysicalLocation(targetResults, sourceResults); err != nil {
		return err
	}

	for idx := 0; idx < len(sourceResults.Targets); idx++ {
		targetResult := targetResults.Targets[idx]
		sourceResult := sourceResults.Targets[idx]

		filterOutScaResultsIfScanFailed(targetResult, sourceResult, sourceResults.Violations)
		filterJasResultsIfScanFailed(targetResult, sourceResult, results.CmdStepContextualAnalysis)
		filterJasResultsIfScanFailed(targetResult, sourceResult, results.CmdStepSecrets)
		filterJasResultsIfScanFailed(targetResult, sourceResult, results.CmdStepIaC)
		filterJasResultsIfScanFailed(targetResult, sourceResult, results.CmdStepSast)
	}
	return nil
}

func filterJasResultsIfScanFailed(targetResult, sourceResult *results.TargetResults, cmdStep results.SecurityCommandStep) {
	sourceResults := []*results.TargetResults{sourceResult}
	targetResults := []*results.TargetResults{targetResult}
	switch cmdStep {
	case results.CmdStepContextualAnalysis:
		if isScanFailedInSourceOrTarget(sourceResults, targetResults, cmdStep) {
			log.Debug(fmt.Sprintf(vulnerabilitiesFilteringErrorMessage, cmdStep))
			sourceResult.JasResults.ApplicabilityScanResults = nil
		}
	case results.CmdStepSecrets:
		if isScanFailedInSourceOrTarget(sourceResults, targetResults, cmdStep) {
			log.Debug(fmt.Sprintf(vulnerabilitiesFilteringErrorMessage, cmdStep))
			sourceResult.JasResults.JasVulnerabilities.SecretsScanResults = nil
		}
		if (sourceResult.JasResults.JasViolations.SecretsScanResults != nil || targetResult.JasResults.JasViolations.SecretsScanResults != nil) &&
			isScanFailedInSourceOrTarget(sourceResults, targetResults, cmdStep) {
			log.Debug(fmt.Sprintf(violationsFilteringErrorMessage, cmdStep))
			sourceResult.JasResults.JasViolations.SecretsScanResults = nil
		}
	case results.CmdStepIaC:
		if isScanFailedInSourceOrTarget(sourceResults, targetResults, cmdStep) {
			log.Debug(fmt.Sprintf(vulnerabilitiesFilteringErrorMessage, cmdStep))
			sourceResult.JasResults.JasVulnerabilities.IacScanResults = nil
		}

		if (sourceResult.JasResults.JasViolations.IacScanResults != nil || targetResult.JasResults.JasViolations.IacScanResults != nil) && isScanFailedInSourceOrTarget(sourceResults, targetResults, cmdStep) {
			log.Debug(fmt.Sprintf(violationsFilteringErrorMessage, cmdStep))
			sourceResult.JasResults.JasViolations.IacScanResults = nil
		}
	case results.CmdStepSast:
		if isScanFailedInSourceOrTarget(sourceResults, targetResults, cmdStep) {
			log.Debug(fmt.Sprintf(vulnerabilitiesFilteringErrorMessage, cmdStep))
			sourceResult.JasResults.JasVulnerabilities.SastScanResults = nil
		}

		if (sourceResult.JasResults.JasViolations.SastScanResults != nil || targetResult.JasResults.JasViolations.SastScanResults != nil) && isScanFailedInSourceOrTarget(sourceResults, targetResults, cmdStep) {
			log.Debug(fmt.Sprintf(violationsFilteringErrorMessage, cmdStep))
			sourceResult.JasResults.JasViolations.SastScanResults = nil
		}
	}
}

func isScanFailedInSourceOrTarget(sourceResults, targetResults []*results.TargetResults, step results.SecurityCommandStep) bool {
	for _, scanResult := range sourceResults {
		if scanResult.ResultsStatus.IsScanFailed(step) {
			return true
		}
	}

	for _, scanResult := range targetResults {
		if scanResult.ResultsStatus.IsScanFailed(step) {
			return true
		}
	}
	return false
}

func filterOutScaResultsIfScanFailed(targetResult, sourceResult *results.TargetResults, sourceViolations *violationutils.Violations) {
	// Filter out new Sca results
	if sourceResult.ResultsStatus.IsScanFailed(results.CmdStepSca) || targetResult.ResultsStatus.IsScanFailed(results.CmdStepSca) {
		var statusCode *int
		var errorSource string
		if sourceResult.ResultsStatus.IsScanFailed(results.CmdStepSca) {
			statusCode = sourceResult.ResultsStatus.ScaScanStatusCode
			errorSource = "source"
		} else {
			statusCode = targetResult.ResultsStatus.ScaScanStatusCode
			errorSource = "target"
		}
		log.Debug(fmt.Sprintf("Sca scan on %s code has completed with errors (status %d). Sca vulnerability results will be removed from final report", errorSource, statusCode))
		sourceResult.ScaResults.Sbom = nil
		if sourceViolations != nil && sourceViolations.Sca != nil {
			log.Debug(fmt.Sprintf("Sca scan on %s has completed with errors (status %d). Sca violations results will be removed from final report", errorSource, statusCode))
			sourceViolations.Sca = nil
		}
	}

}

// Sorts the Targets slice in both targetResults and sourceResults
// by the physical location (Target field) of each scan target in ascending order.
func sortTargetsByPhysicalLocation(targetResults, sourceResults *results.SecurityCommandResults) error {
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

func scanResultsToIssuesCollection(scanResults *results.SecurityCommandResults, workingDirs ...string) (issuesCollection *issues.ScansIssuesCollection, err error) {
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
