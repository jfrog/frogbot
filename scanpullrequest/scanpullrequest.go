package scanpullrequest

import (
	"context"
	"errors"
	"fmt"
	"github.com/jfrog/gofrog/datastructures"
	"os"
	"path/filepath"
	"strings"

	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/jfrog-cli-security/utils/formats"
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

// targetPair represents a matched pair of source and target scan results
type targetPair struct {
	source *results.TargetResults
	target *results.TargetResults
}

type ScanPullRequestCmd struct{}

func (pr *ScanPullRequestCmd) Run(repository utils.Repository, client vcsclient.VcsClient) (err error) {
	if repository.Params.Git.PullRequestDetails, err = client.GetPullRequestByID(context.Background(),
		repository.Params.Git.RepoOwner, repository.Params.Git.RepoName, int(repository.Params.Git.PullRequestDetails.ID)); err != nil {
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
	filterFailedResultsIfScannersFailuresAreAllowed(scanDetails.ResultsToCompare, scanResults, repoConfig.Params.ConfigProfile.GeneralConfig.FailUponAnyScannerError, sourceBranchWd, targetBranchWd)

	log.Debug("Diff scan - converting to new issues...")
	issuesCollection, e := scanResultsToIssuesCollection(scanResults, strings.TrimPrefix(sourceBranchWd, string(filepath.Separator)), strings.TrimPrefix(targetBranchWd, string(filepath.Separator)))
	if e != nil {
		err = errors.Join(err, fmt.Errorf("failed to get issues for pull request. Error: %s", e.Error()))
	}
	return
}

// When failUponAnyScannerError is false, and we are performing a diff scan (both source & target results exist),
// we filter out a scanner results if we found any error in any of its results (non-zero status code) in either source or target results.
// This logic prevents us from presenting incorrect results due to an incomplete scan that produced incomplete results that might affect the diff process.
func filterFailedResultsIfScannersFailuresAreAllowed(targetResults, sourceResults *results.SecurityCommandResults, failUponAnyScannerError bool, sourceWdPrefix, targetWdPrefix string) {
	if failUponAnyScannerError || targetResults == nil {
		return
	}

	matchedByLocation, matchedByName, unmatchedSource := buildTargetMappings(targetResults, sourceResults, sourceWdPrefix, targetWdPrefix)

	for _, targetSourceResultsPair := range matchedByLocation {
		log.Debug(fmt.Sprintf("removing failing scans results out of source result located in '%s' if exists", targetSourceResultsPair.source.Target))
		filterScaResultsIfScanFailed(targetSourceResultsPair.target, targetSourceResultsPair.source)
		filterJasResultsIfScanFailed(targetSourceResultsPair.target, targetSourceResultsPair.source, results.CmdStepContextualAnalysis)
		filterJasResultsIfScanFailed(targetSourceResultsPair.target, targetSourceResultsPair.source, results.CmdStepSecrets)
		filterJasResultsIfScanFailed(targetSourceResultsPair.target, targetSourceResultsPair.source, results.CmdStepIaC)
		filterJasResultsIfScanFailed(targetSourceResultsPair.target, targetSourceResultsPair.source, results.CmdStepSast)
	}

	for _, targetSourceResultsPair := range matchedByName {
		log.Debug(fmt.Sprintf("removing failing scans results out of source result named '%s', if exists", targetSourceResultsPair.source.Name))
		filterScaResultsIfScanFailed(targetSourceResultsPair.target, targetSourceResultsPair.source)
		filterJasResultsIfScanFailed(targetSourceResultsPair.target, targetSourceResultsPair.source, results.CmdStepContextualAnalysis)
		filterJasResultsIfScanFailed(targetSourceResultsPair.target, targetSourceResultsPair.source, results.CmdStepSecrets)
		filterJasResultsIfScanFailed(targetSourceResultsPair.target, targetSourceResultsPair.source, results.CmdStepIaC)
		filterJasResultsIfScanFailed(targetSourceResultsPair.target, targetSourceResultsPair.source, results.CmdStepSast)
	}

	for _, sourceResult := range unmatchedSource {
		log.Debug(fmt.Sprintf("removing failing scans results out of newly detected/ moved source result located in'%s', if exists", sourceResult.Target))
		filterScaResultsIfScanFailed(nil, sourceResult)
		filterJasResultsIfScanFailed(nil, sourceResult, results.CmdStepContextualAnalysis)
		filterJasResultsIfScanFailed(nil, sourceResult, results.CmdStepSecrets)
		filterJasResultsIfScanFailed(nil, sourceResult, results.CmdStepIaC)
		filterJasResultsIfScanFailed(nil, sourceResult, results.CmdStepSast)
	}
	// Note: Unmatched target results (removed targets) are ignored as they don't affect PR diff, as they are targets that were removed in the PR and don't exist in source results.

	if sourceResults.ViolationsStatusCode == nil || targetResults.ViolationsStatusCode == nil {
		// If ViolationsStatusCode is nil it means we didn't perform violation check. We ensure the violation results are zeroed and return
		sourceResults.Violations = nil
		return
	}

	filterViolationsResults(sourceResults, targetResults)
}

func filterViolationsResults(sourceResults, targetResults *results.SecurityCommandResults) {
	if sourceResults.Violations == nil {
		return
	}

	// Violation's scan status relates to all violation scans from all targets, therefore if violation status != 0 we filter out all violations results for all scanners from all targets
	if *sourceResults.ViolationsStatusCode != 0 || *targetResults.ViolationsStatusCode != 0 {
		log.Debug("violation scan has failed. Removing all violations results out of source results")
		sourceResults.Violations = nil
		return
	}

	// If we have a failure in a specific scanner, we filter out this scanner's violation to avoid incorrect results
	filterSpecificScannersViolationsIfScanFailed(sourceResults, sourceResults.GetStatusCodes(), targetResults.GetStatusCodes())
}

func filterSpecificScannersViolationsIfScanFailed(sourceResults *results.SecurityCommandResults, sourceStatusCodes, targetStatusCodes results.ResultsStatus) {
	if (sourceStatusCodes.ScaScanStatusCode != nil && *sourceStatusCodes.ScaScanStatusCode != 0) ||
		(targetStatusCodes.ScaScanStatusCode != nil && *targetStatusCodes.ScaScanStatusCode != 0) {
		log.Debug(fmt.Sprintf(violationsFilteringErrorMessage, results.CmdStepSca))
		sourceResults.Violations.Sca = nil
	}

	if (sourceStatusCodes.SecretsScanStatusCode != nil && *sourceStatusCodes.SecretsScanStatusCode != 0) ||
		(targetStatusCodes.SecretsScanStatusCode != nil && *targetStatusCodes.SecretsScanStatusCode != 0) {
		log.Debug(fmt.Sprintf(violationsFilteringErrorMessage, results.CmdStepSecrets))
		sourceResults.Violations.Secrets = nil
	}

	if (sourceStatusCodes.IacScanStatusCode != nil && *sourceStatusCodes.IacScanStatusCode != 0) ||
		(targetStatusCodes.IacScanStatusCode != nil && *targetStatusCodes.IacScanStatusCode != 0) {
		log.Debug(fmt.Sprintf(violationsFilteringErrorMessage, results.CmdStepIaC))
		sourceResults.Violations.Iac = nil
	}

	if (sourceStatusCodes.SastScanStatusCode != nil && *sourceStatusCodes.SastScanStatusCode != 0) ||
		(targetStatusCodes.SastScanStatusCode != nil && *targetStatusCodes.SastScanStatusCode != 0) {
		log.Debug(fmt.Sprintf(violationsFilteringErrorMessage, results.CmdStepSast))
		sourceResults.Violations.Sast = nil
	}
}

// Creates maps and slices of matched/unmatched targets using pointers to original objects.
// Optimized version using lookup maps for O(n+m) complexity instead of O(n*m).
// Returns:
//   - matchedByLocation: map of pairs matched by physical location (Target field)
//   - matchedByName: map of pairs matched by logical name (Name field) - fallback for location changes
//   - unmatchedSource: slice of source-only targets (newly added targets)
func buildTargetMappings(targetResults, sourceResults *results.SecurityCommandResults, sourceWdPrefix, targetWdPrefix string) (matchedByLocation map[string]*targetPair, matchedByName map[string]*targetPair, unmatchedSource []*results.TargetResults) {
	matchedByLocation = make(map[string]*targetPair)
	matchedByName = make(map[string]*targetPair)
	unmatchedSource = []*results.TargetResults{}
	matchedSourceTargets := datastructures.MakeSet[*results.TargetResults]()
	matchedTargetTargets := datastructures.MakeSet[*results.TargetResults]()

	targetsByLocation := make(map[string]*results.TargetResults)
	targetsByName := make(map[string]*results.TargetResults)
	// In new SCA scan all results are in a single target, but since the targets array is not yet deprecated from the struct we iterate all targets
	for _, targetResult := range targetResults.Targets {
		if targetResult.Target != "" {
			targetsByLocation[trimTargetPrefix(targetResult.Target, targetWdPrefix)] = targetResult
		}
		if targetResult.Name != "" {
			targetsByName[targetResult.Name] = targetResult
		}
	}

	for _, sourceResult := range sourceResults.Targets {
		if sourceResult.Target == "" {
			continue
		}
		targetResult := targetsByLocation[trimTargetPrefix(sourceResult.Target, sourceWdPrefix)]
		if targetResult == nil || matchedTargetTargets.Exists(targetResult) {
			continue
		}

		matchedByLocation[sourceResult.Target] = &targetPair{
			source: sourceResult,
			target: targetResult,
		}
		matchedSourceTargets.Add(sourceResult)
		matchedTargetTargets.Add(targetResult)
	}

	for _, sourceResult := range sourceResults.Targets {
		if sourceResult.Name == "" || matchedSourceTargets.Exists(sourceResult) {
			continue
		}

		targetResult := targetsByName[sourceResult.Name]
		if targetResult == nil || matchedTargetTargets.Exists(targetResult) {
			continue
		}

		matchedByName[sourceResult.Name] = &targetPair{
			source: sourceResult,
			target: targetResult,
		}
		matchedSourceTargets.Add(sourceResult)
		matchedTargetTargets.Add(targetResult)
	}

	// The unmatched source targets are newly added targets
	for _, sourceResult := range sourceResults.Targets {
		if !matchedSourceTargets.Exists(sourceResult) {
			unmatchedSource = append(unmatchedSource, sourceResult)
		}
	}

	return matchedByLocation, matchedByName, unmatchedSource
}

func filterJasResultsIfScanFailed(targetResult, sourceResult *results.TargetResults, cmdStep results.SecurityCommandStep) {
	if !isScanFailedInSourceOrTarget(sourceResult, targetResult, cmdStep) {
		return
	}
	log.Debug(fmt.Sprintf(vulnerabilitiesFilteringErrorMessage, cmdStep))

	switch cmdStep {
	case results.CmdStepContextualAnalysis:
		if sourceResult.JasResults != nil {
			sourceResult.JasResults.ApplicabilityScanResults = nil
		}
	case results.CmdStepSecrets:
		if sourceResult.JasResults != nil {
			sourceResult.JasResults.JasVulnerabilities.SecretsScanResults = nil
		}
	case results.CmdStepIaC:
		if sourceResult.JasResults != nil {
			sourceResult.JasResults.JasVulnerabilities.IacScanResults = nil
		}
	case results.CmdStepSast:
		if sourceResult.JasResults != nil {
			sourceResult.JasResults.JasVulnerabilities.SastScanResults = nil
		}
	}
}

func isScanFailedInSourceOrTarget(sourceResult, targetResult *results.TargetResults, step results.SecurityCommandStep) bool {
	if sourceResult != nil && sourceResult.ResultsStatus.IsScanFailed(step) {
		return true
	}

	if targetResult != nil && targetResult.ResultsStatus.IsScanFailed(step) {
		return true
	}
	return false
}

func filterScaResultsIfScanFailed(targetResult, sourceResult *results.TargetResults) {
	// Filter out new Sca results
	sourceFailed := sourceResult.ResultsStatus.IsScanFailed(results.CmdStepSca)
	targetFailed := targetResult != nil && targetResult.ResultsStatus.IsScanFailed(results.CmdStepSca)

	if sourceFailed || targetFailed {
		var statusCode *int
		var errorSource string
		if sourceFailed {
			statusCode = sourceResult.ResultsStatus.ScaScanStatusCode
			errorSource = "source"
		} else {
			statusCode = targetResult.ResultsStatus.ScaScanStatusCode
			errorSource = "target"
		}
		log.Debug(fmt.Sprintf("Sca scan on %s code has completed with errors (status %d). Sca vulnerability results will be removed from final report", errorSource, statusCode))
		if sourceResult.ScaResults != nil {
			sourceResult.ScaResults.Sbom = nil
		}
	}
}

func trimTargetPrefix(fullPath, prefix string) string {
	if prefix == "" {
		return fullPath
	}
	// Normalize prefix to end with path separator
	normalizedPrefix := strings.TrimSuffix(prefix, string(os.PathSeparator)) + string(os.PathSeparator)

	// Check if fullPath actually starts with normalizedPrefix
	if !strings.HasPrefix(fullPath, normalizedPrefix) {
		// If fullPath doesn't start with normalizedPrefix, check if it equals the prefix (without trailing /)
		if fullPath == prefix || fullPath == strings.TrimSuffix(prefix, string(os.PathSeparator)) {
			return "."
		}
		// Otherwise, return fullPath unchanged (not under this prefix)
		return fullPath
	}

	trimmed := strings.TrimPrefix(fullPath, normalizedPrefix)
	if trimmed == "" {
		// Everything was trimmed, meaning fullPath == normalizedPrefix
		return "."
	}
	return trimmed
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

func getResultScanStatues(cmdResult *results.SecurityCommandResults) formats.ScanStatus {
	if cmdResult == nil {
		return formats.ScanStatus{}
	}
	converted, err := conversion.NewCommandResultsConvertor(conversion.ResultConvertParams{IncludeVulnerabilities: cmdResult.IncludesVulnerabilities(), HasViolationContext: cmdResult.HasViolationContext(), SimplifiedOutput: true}).ConvertToSimpleJson(cmdResult)
	if err != nil {
		log.Debug(fmt.Sprintf("Failed to get scan status for failed scan. Error: %v", err))
		return formats.ScanStatus{}
	}
	return converted.Statuses
}
