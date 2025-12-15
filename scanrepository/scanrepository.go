package scanrepository

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/go-git/go-git/v5"
	biutils "github.com/jfrog/build-info-go/utils"

	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/froggit-go/vcsutils"
	"github.com/jfrog/gofrog/version"
	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/results/conversion"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-cli-security/utils/xsc"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"

	"github.com/jfrog/frogbot/v2/packagehandlers"
	"github.com/jfrog/frogbot/v2/utils"
	"github.com/jfrog/frogbot/v2/utils/outputwriter"
)

const analyticsScanRepositoryScanType = "monitor"

type ScanRepositoryCmd struct {
	// The interface that Frogbot utilizes to format and style the displayed messages on the Git providers
	outputwriter.OutputWriter
	// dryRun is used for testing purposes, mocking part of the git commands that requires networking
	dryRun bool
	// When dryRun is enabled, dryRunRepoPath specifies the repository local path to clone
	dryRunRepoPath string
	// The scanDetails of the current scan
	scanDetails *utils.ScanDetails
	// The base working directory
	baseWd string
	// The git client the command performs git operations with
	gitManager *utils.GitManager
	// The current project technology
	projectTech []techutils.Technology
	// Stores all package manager handlers for detected issues
	handlers map[techutils.Technology]packagehandlers.PackageHandler

	customTemplates utils.CustomTemplates

	XrayVersion string
	XscVersion  string
}

func (sr *ScanRepositoryCmd) Run(repository utils.Repository, client vcsclient.VcsClient, frogbotRepoConnection *utils.UrlAccessChecker) (err error) {
	repository.OutputWriter.SetHasInternetConnection(frogbotRepoConnection.IsConnected())
	sr.XrayVersion = repository.Params.XrayVersion
	sr.XscVersion = repository.Params.XscVersion
	if err = sr.setCommandPrerequisites(&repository, client); err != nil {
		return
	}
	log.Debug(fmt.Sprintf("Detected branches for scan: %s", strings.Join(repository.Params.Git.Branches, ", ")))
	for _, branch := range repository.Params.Git.Branches {
		log.Debug(fmt.Sprintf("Scanning '%s' branch...", branch))
		sr.scanDetails.SetBaseBranch(branch)
		sr.scanDetails.SetXscGitInfoContext(branch, repository.Params.Git.Project, client)
		if err = sr.prepareEnvAndScanBranch(&repository); err != nil {
			return
		}
	}
	return
}

func (sr *ScanRepositoryCmd) scanAndFixRepository(repository *utils.Repository, client vcsclient.VcsClient) (err error) {
	if err = sr.setCommandPrerequisites(repository, client); err != nil {
		return
	}
	log.Debug(fmt.Sprintf("Detected branches for scan: %s", strings.Join(repository.Params.Git.Branches, ", ")))
	for _, branch := range repository.Params.Git.Branches {
		log.Debug(fmt.Sprintf("Scanning '%s' branch...", branch))
		sr.scanDetails.SetBaseBranch(branch)
		sr.scanDetails.SetXscGitInfoContext(branch, repository.Params.Git.Project, client)
		if err = sr.prepareEnvAndScanBranch(repository); err != nil {
			return
		}
	}
	return
}

func (sr *ScanRepositoryCmd) prepareEnvAndScanBranch(repository *utils.Repository) (err error) {
	repoDir, restoreBaseDir, err := sr.checkoutToBranch()
	if err != nil {
		return
	}
	sr.baseWd = repoDir
	defer func() {
		// On dry run don't delete the folder as we want to validate results
		if sr.dryRun {
			return
		}
		err = errors.Join(err, restoreBaseDir(), fileutils.RemoveTempDir(repoDir))
	}()

	sr.scanDetails.MultiScanId, sr.scanDetails.StartTime = xsc.SendNewScanEvent(sr.scanDetails.XrayVersion, sr.scanDetails.XscVersion,
		sr.scanDetails.ServerDetails, utils.CreateScanEvent(sr.scanDetails.ServerDetails, sr.scanDetails.XscGitInfoContext, analyticsScanRepositoryScanType),
		repository.Params.JFrogPlatform.JFrogProjectKey,
	)

	findings := 0
	defer func() {
		xsc.SendScanEndedEvent(sr.scanDetails.XrayVersion, sr.scanDetails.XscVersion, sr.scanDetails.ServerDetails, sr.scanDetails.MultiScanId, sr.scanDetails.StartTime, findings, &sr.scanDetails.ResultContext, err)
	}()
	findings, err = sr.scanAndFixBranch(repository)
	return
}

func (sr *ScanRepositoryCmd) setCommandPrerequisites(repository *utils.Repository, client vcsclient.VcsClient) (err error) {
	repositoryCloneUrl, err := repository.Params.Git.GetRepositoryHttpsCloneUrl(client)
	if err != nil {
		return
	}
	sr.scanDetails = utils.NewScanDetails(client, &repository.Server, &repository.Params.Git).
		SetJfrogVersions(sr.XrayVersion, sr.XscVersion).
		SetResultsContext(repositoryCloneUrl, repository.Params.JFrogPlatform.JFrogProjectKey, false).
		SetConfigProfile(repository.Params.ConfigProfile)

	// Set the outputwriter interface for the relevant vcs git provider
	sr.OutputWriter = outputwriter.GetCompatibleOutputWriter(repository.Params.Git.GitProvider)
	sr.OutputWriter.SetSizeLimit(client)
	// Set the git client to perform git operations
	sr.gitManager, err = utils.NewGitManager().
		SetAuth(sr.scanDetails.Username, sr.scanDetails.Token).
		SetDryRun(sr.dryRun, sr.dryRunRepoPath).
		SetRemoteGitUrl(repositoryCloneUrl)
	if err != nil {
		return
	}
	if sr.customTemplates, err = utils.LoadCustomTemplates(repository.ConfigProfile.FrogbotConfig.CommitMessageTemplate,
		repository.ConfigProfile.FrogbotConfig.BranchNameTemplate, repository.ConfigProfile.FrogbotConfig.PrTitleTemplate); err != nil {
		return
	}
	sr.gitManager.SetGitParams(sr.scanDetails.Git)
	return
}

func (sr *ScanRepositoryCmd) scanAndFixBranch(repository *utils.Repository) (int, error) {
	totalFindings := 0
	scanResults, err := sr.scan()
	if err != nil {
		if err = utils.CreateErrorIfFailUponScannerErrorEnabled(repository.GeneralConfig.FailUponAnyScannerError, fmt.Sprintf("An error occurred during Audit execution for '%s' branch. Fixes will be skipped for this branch", sr.scanDetails.BaseBranch()), err); err != nil {
			return 0, err
		}
	}
	if summary, err := conversion.NewCommandResultsConvertor(conversion.ResultConvertParams{IncludeVulnerabilities: scanResults.IncludesVulnerabilities(), HasViolationContext: scanResults.HasViolationContext()}).ConvertToSummary(scanResults); err != nil {
		return 0, err
	} else {
		findingCount := summary.GetTotalViolations()
		if findingCount == 0 {
			findingCount = summary.GetTotalVulnerabilities()
		}
		totalFindings = findingCount
	}
	sr.uploadResultsToGithubDashboardsIfNeeded(repository, err, scanResults)

	if !repository.Params.FrogbotConfig.CreateAutoFixPr {
		log.Info(fmt.Sprintf("This command is running in detection mode only. To enable automatic fixing of issues, set the '%s' flag under the repository's coniguration settings in Jfrog platform")) // todo add configuration name
		return totalFindings, nil
	}
	vulnerabilitiesByPathMap, err := sr.createVulnerabilitiesMap(repository.GeneralConfig.FailUponAnyScannerError, scanResults)
	if err != nil {
		if err = utils.CreateErrorIfFailUponScannerErrorEnabled(repository.GeneralConfig.FailUponAnyScannerError, fmt.Sprintf("An error occurred while preparing the vulnerabilities map for branch '%s'.", sr.scanDetails.BaseBranch()), err); err != nil {
			return 0, err
		}
	}
	if len(vulnerabilitiesByPathMap) == 0 {
		log.Info("Didn't find vulnerable dependencies with existing fix versions for", sr.scanDetails.RepoName)
		return totalFindings, nil
	}
	return totalFindings, sr.fixVulnerablePackages(repository, vulnerabilitiesByPathMap)
}

func (sr *ScanRepositoryCmd) uploadResultsToGithubDashboardsIfNeeded(repository *utils.Repository, err error, scanResults *results.SecurityCommandResults) {
	if repository.Params.Git.GitProvider.String() == vcsutils.GitHub.String() {
		// Uploads Sarif results to GitHub in order to view the scan in the code scanning UI
		// Currently available on GitHub only
		if err = utils.UploadSarifResultsToGithubSecurityTab(scanResults, repository, sr.scanDetails.BaseBranch(), sr.scanDetails.Client()); err != nil {
			log.Warn(err)
		}

		if *repository.Params.Git.UploadSbomToVcs && scanResults.EntitledForJas {
			if err = utils.UploadSbomSnapshotToGithubDependencyGraph(repository.Params.Git.RepoOwner, repository.Params.Git.RepoName, scanResults, sr.scanDetails.Client(), sr.scanDetails.BaseBranch()); err != nil {
				log.Warn(err)
			}
		}
	}
}

// Audit the dependencies of the current commit.
func (sr *ScanRepositoryCmd) scan() (*results.SecurityCommandResults, error) {
	auditResults := sr.scanDetails.Audit(sr.baseWd)
	if err := auditResults.GetErrors(); err != nil {
		return nil, err
	}
	log.Info("Xray scan completed")
	sr.OutputWriter.SetJasOutputFlags(auditResults.EntitledForJas, auditResults.HasJasScansResults(jasutils.Applicability))
	sr.projectTech = auditResults.GetTechnologies(sr.projectTech...)
	return auditResults, nil
}

func (sr *ScanRepositoryCmd) fixVulnerablePackages(repository *utils.Repository, vulnerabilitiesMap map[string]*utils.VulnerabilityDetails) (err error) {
	if repository.FrogbotConfig.AggregateFixes {
		aggregatedFixBranchName, e := sr.gitManager.GenerateAggregatedFixBranchName(sr.scanDetails.BaseBranch(), sr.projectTech)
		if e != nil {
			return
		}
		existingPullRequestDetails, e := sr.getOpenPullRequestBySourceBranch(aggregatedFixBranchName)
		if e != nil {
			return
		}
		e = sr.aggregateFixAndOpenPullRequest(repository, vulnerabilitiesMap, aggregatedFixBranchName, existingPullRequestDetails)
	} else {
		if e := sr.fixProjectVulnerabilities(repository, vulnerabilitiesMap); e != nil {
			err = errors.Join(err, fmt.Errorf("the following errors occured while fixing vulnerabilities in '%s':\n%s", sr.scanDetails.BaseBranch(), e))
		}
	}
	if err != nil {
		return utils.CreateErrorIfFailUponScannerErrorEnabled(repository.GeneralConfig.FailUponAnyScannerError, fmt.Sprintf("failed to fix vulnerable dependencies: %s", err.Error()), err)
	}
	return
}

func (sr *ScanRepositoryCmd) fixProjectVulnerabilities(repository *utils.Repository, vulnerabilities map[string]*utils.VulnerabilityDetails) (err error) {
	// Fix every vulnerability in a separate pull request and branch
	for _, vulnerability := range vulnerabilities {
		if e := sr.fixSinglePackageAndCreatePR(repository, vulnerability); e != nil {
			err = errors.Join(err, sr.handleUpdatePackageErrors(e))
		}
	}
	return
}

func (sr *ScanRepositoryCmd) fixMultiplePackages(vulnerabilities map[string]*utils.VulnerabilityDetails) (fixedVulnerabilities []*utils.VulnerabilityDetails, err error) {
	for _, vulnDetails := range vulnerabilities {
		if e := sr.updatePackageToFixedVersion(vulnDetails); e != nil {
			err = errors.Join(err, sr.handleUpdatePackageErrors(e))
			continue
		}
		fixedVulnerabilities = append(fixedVulnerabilities, vulnDetails)
		log.Info(fmt.Sprintf("Updated dependency '%s' to version '%s'", vulnDetails.ImpactedDependencyName, vulnDetails.SuggestedFixedVersion))
	}
	return
}

// Handles possible error of update package operation
// When the expected custom error occurs, log to debug.
// else, return the error
func (sr *ScanRepositoryCmd) handleUpdatePackageErrors(err error) error {
	var errUnsupportedFix *utils.ErrUnsupportedFix
	var errNoChangesToCommit *utils.ErrNothingToCommit

	switch {
	case errors.As(err, &errUnsupportedFix):
		log.Debug(strings.TrimSpace(err.Error()))
	case errors.As(err, &errNoChangesToCommit):
		log.Info(err.Error())
	default:
		return err
	}
	return nil
}

// Creates a branch for the fixed package and open pull request against the target branch.
// In case a branch already exists on remote, we skip it.
func (sr *ScanRepositoryCmd) fixSinglePackageAndCreatePR(repository *utils.Repository, vulnDetails *utils.VulnerabilityDetails) (err error) {
	fixVersion := vulnDetails.SuggestedFixedVersion
	log.Debug("Attempting to fix", fmt.Sprintf("%s:%s", vulnDetails.ImpactedDependencyName, vulnDetails.ImpactedDependencyVersion), "with", fixVersion)
	fixBranchName, err := sr.gitManager.GenerateFixBranchName(sr.scanDetails.BaseBranch(), vulnDetails.ImpactedDependencyName, fixVersion)
	if err != nil {
		return
	}
	existsInRemote, err := sr.gitManager.BranchExistsInRemote(fixBranchName)
	if err != nil {
		return
	}
	if existsInRemote {
		log.Info(fmt.Sprintf("A pull request updating the dependency '%s' to version '%s' already exists. Skipping...", vulnDetails.ImpactedDependencyName, vulnDetails.SuggestedFixedVersion))
		return
	}

	workTreeIsClean, err := sr.gitManager.IsClean()
	if err != nil {
		return
	}
	if !workTreeIsClean {
		// If there are local changes, such as files generated after running an 'install' command, we aim to preserve them in the new branch
		err = sr.gitManager.CreateBranchAndCheckout(fixBranchName, true)
	} else {
		err = sr.gitManager.CreateBranchAndCheckout(fixBranchName, false)
	}
	if err != nil {
		return
	}

	if err = sr.updatePackageToFixedVersion(vulnDetails); err != nil {
		return
	}
	if err = sr.openFixingPullRequest(repository, fixBranchName, vulnDetails); err != nil {
		return errors.Join(fmt.Errorf("failed while creating a fixing pull request for: %s with version: %s with error: ", vulnDetails.ImpactedDependencyName, fixVersion), err)
	}
	log.Info(fmt.Sprintf("Created Pull Request updating dependency '%s' to version '%s'", vulnDetails.ImpactedDependencyName, vulnDetails.SuggestedFixedVersion))
	return
}

func (sr *ScanRepositoryCmd) openFixingPullRequest(repository *utils.Repository, fixBranchName string, vulnDetails *utils.VulnerabilityDetails) (err error) {
	log.Debug("Checking if there are changes to commit")
	isClean, err := sr.gitManager.IsClean()
	if err != nil {
		return
	}
	if isClean {
		// In instances where a fix is required that Frogbot does not support, the worktree will remain clean, and there will be nothing to push
		return &utils.ErrNothingToCommit{PackageName: vulnDetails.ImpactedDependencyName}
	}
	commitMessage := sr.gitManager.GenerateCommitMessage(vulnDetails.ImpactedDependencyName, vulnDetails.SuggestedFixedVersion)
	if err = sr.cleanNewFilesMissingInRemote(); err != nil {
		log.Warn(fmt.Sprintf("failed fo clean untracked files from '%s' due to the following errors: %s", sr.baseWd, err.Error()))
	}
	if err = sr.gitManager.AddAllAndCommit(commitMessage, vulnDetails.ImpactedDependencyName); err != nil {
		return
	}
	if err = sr.gitManager.Push(false, fixBranchName); err != nil {
		return
	}
	return sr.handleFixPullRequestContent(repository, fixBranchName, nil, vulnDetails)
}

func (sr *ScanRepositoryCmd) handleFixPullRequestContent(repository *utils.Repository, fixBranchName string, pullRequestInfo *vcsclient.PullRequestInfo, vulnerabilities ...*utils.VulnerabilityDetails) (err error) {
	pullRequestTitle, prBody, extraComments, err := sr.preparePullRequestDetails(repository.FrogbotConfig.AggregateFixes, vulnerabilities...)
	if err != nil {
		return
	}
	// Update PR description
	if pullRequestInfo, err = sr.createOrUpdatePullRequest(repository, pullRequestInfo, fixBranchName, pullRequestTitle, prBody); err != nil {
		return
	}
	// Update PR extra comments
	client := sr.scanDetails.Client()
	for _, comment := range extraComments {
		if err = client.AddPullRequestComment(context.Background(), sr.scanDetails.RepoOwner, sr.scanDetails.RepoName, comment, int(pullRequestInfo.ID)); err != nil {
			err = errors.New("couldn't add pull request comment: " + err.Error())
			return
		}
	}
	return
}

func (sr *ScanRepositoryCmd) createOrUpdatePullRequest(repository *utils.Repository, pullRequestInfo *vcsclient.PullRequestInfo, fixBranchName, pullRequestTitle, prBody string) (prInfo *vcsclient.PullRequestInfo, err error) {
	if pullRequestInfo == nil {
		log.Info("Creating Pull Request from:", fixBranchName, "to:", sr.scanDetails.BaseBranch())
		if err = sr.scanDetails.Client().CreatePullRequest(context.Background(), sr.scanDetails.RepoOwner, sr.scanDetails.RepoName, fixBranchName, sr.scanDetails.BaseBranch(), pullRequestTitle, prBody); err != nil {
			return
		}
		return sr.getOpenPullRequestBySourceBranch(fixBranchName)
	}
	log.Info("Updating Pull Request from:", fixBranchName, "to:", sr.scanDetails.BaseBranch())
	if err = sr.scanDetails.Client().UpdatePullRequest(context.Background(), sr.scanDetails.RepoOwner, sr.scanDetails.RepoName, pullRequestTitle, prBody, pullRequestInfo.Target.Name, int(pullRequestInfo.ID), vcsutils.Open); err != nil {
		return
	}
	// Delete old extra comments
	return pullRequestInfo, utils.DeletePullRequestComments(repository, sr.scanDetails.Client(), int(pullRequestInfo.ID))
}

// Handles the opening or updating of a pull request when the aggregate mode is active.
// If a pull request is already open, Frogbot will update the branch and the pull request body.
func (sr *ScanRepositoryCmd) openAggregatedPullRequest(repository *utils.Repository, fixBranchName string, pullRequestInfo *vcsclient.PullRequestInfo, vulnerabilities []*utils.VulnerabilityDetails) (err error) {
	commitMessage := sr.gitManager.GenerateAggregatedCommitMessage(sr.projectTech)
	if err = sr.cleanNewFilesMissingInRemote(); err != nil {
		return
	}
	if err = sr.gitManager.AddAllAndCommit(commitMessage, ""); err != nil {
		return
	}
	if err = sr.gitManager.Push(true, fixBranchName); err != nil {
		return
	}
	return sr.handleFixPullRequestContent(repository, fixBranchName, pullRequestInfo, vulnerabilities...)
}

func (sr *ScanRepositoryCmd) cleanNewFilesMissingInRemote() error {
	// Open the local repository
	localRepo, err := git.PlainOpen(sr.baseWd)
	if err != nil {
		return err
	}

	// Getting the repository working tree
	worktree, err := localRepo.Worktree()
	if err != nil {
		return err
	}

	// Getting the working tree status
	gitStatus, err := worktree.Status()
	if err != nil {
		return err
	}

	for relativeFilePath, status := range gitStatus {
		if status.Worktree == git.Untracked {
			log.Debug(fmt.Sprintf("Untracking file '%s' that was created locally during the scan/fix process", relativeFilePath))
			fileDeletionErr := os.Remove(filepath.Join(sr.baseWd, relativeFilePath))
			if fileDeletionErr != nil {
				err = errors.Join(err, fmt.Errorf("file '%s': %s", relativeFilePath, fileDeletionErr.Error()))
				continue
			}
		}
	}
	return err
}

func (sr *ScanRepositoryCmd) preparePullRequestDetails(aggregateFixes bool, vulnerabilitiesDetails ...*utils.VulnerabilityDetails) (prTitle, prBody string, otherComments []string, err error) {
	if sr.dryRun && aggregateFixes {
		// For testings, don't compare pull request body as scan results order may change.
		return sr.gitManager.GenerateAggregatedPullRequestTitle(sr.projectTech), "", []string{}, nil
	}
	vulnerabilitiesRows := utils.ExtractVulnerabilitiesDetailsToRows(vulnerabilitiesDetails)

	prBody, extraComments := utils.GenerateFixPullRequestDetails(vulnerabilitiesRows, sr.OutputWriter)

	if aggregateFixes {
		var scanHash string
		if scanHash, err = utils.VulnerabilityDetailsToMD5Hash(vulnerabilitiesRows...); err != nil {
			return
		}
		return sr.gitManager.GenerateAggregatedPullRequestTitle(sr.projectTech), prBody + outputwriter.MarkdownComment(fmt.Sprintf("Checksum: %s", scanHash)), extraComments, nil
	}
	// In separate pull requests there is only one vulnerability
	vulnDetails := vulnerabilitiesDetails[0]
	pullRequestTitle := sr.gitManager.GeneratePullRequestTitle(vulnDetails.ImpactedDependencyName, vulnDetails.SuggestedFixedVersion)
	return pullRequestTitle, prBody, extraComments, nil
}

func (sr *ScanRepositoryCmd) checkoutToBranch() (tempWd string, restoreDir func() error, err error) {
	if sr.dryRun {
		tempWd = filepath.Join(sr.dryRunRepoPath, sr.scanDetails.RepoName)
	} else {
		if tempWd, err = fileutils.CreateTempDir(); err != nil {
			return
		}
	}
	log.Debug("Created temp working directory:", tempWd)

	var curDir string
	if curDir, err = os.Getwd(); err != nil {
		return
	}
	if err = biutils.CopyDir(curDir, tempWd, true, nil); err != nil {
		return
	}
	// 'CD' into the temp working directory
	restoreDir, err = utils.Chdir(tempWd)
	if err != nil {
		return
	}
	// Set the current copied local dir as the local git repository we are working with
	err = sr.gitManager.SetLocalRepository()
	return
}

// Create a vulnerabilities map - a map with 'impacted package' as a key and all the necessary information of this vulnerability as value.
func (sr *ScanRepositoryCmd) createVulnerabilitiesMap(failUponError bool, scanResults *results.SecurityCommandResults) (map[string]*utils.VulnerabilityDetails, error) {
	vulnerabilitiesMap := map[string]*utils.VulnerabilityDetails{}
	simpleJsonResult, err := conversion.NewCommandResultsConvertor(conversion.ResultConvertParams{IncludeVulnerabilities: scanResults.IncludesVulnerabilities(), HasViolationContext: scanResults.HasViolationContext()}).ConvertToSimpleJson(scanResults)
	if err != nil {
		return nil, err
	}
	if len(simpleJsonResult.Vulnerabilities) > 0 {
		for i := range simpleJsonResult.Vulnerabilities {
			if err = sr.addVulnerabilityToFixVersionsMap(failUponError, &simpleJsonResult.Vulnerabilities[i], vulnerabilitiesMap); err != nil {
				return nil, err
			}
		}
	} else if len(simpleJsonResult.SecurityViolations) > 0 {
		for i := range simpleJsonResult.SecurityViolations {
			if err = sr.addVulnerabilityToFixVersionsMap(failUponError, &simpleJsonResult.SecurityViolations[i], vulnerabilitiesMap); err != nil {
				return nil, err
			}
		}
	}
	if len(vulnerabilitiesMap) > 0 {
		log.Debug("Frogbot will attempt to resolve the following vulnerable dependencies:\n", strings.Join(maps.Keys(vulnerabilitiesMap), ",\n"))
	}
	return vulnerabilitiesMap, nil
}

func (sr *ScanRepositoryCmd) addVulnerabilityToFixVersionsMap(failUponError bool, vulnerability *formats.VulnerabilityOrViolationRow, vulnerabilitiesMap map[string]*utils.VulnerabilityDetails) error {
	if len(vulnerability.FixedVersions) == 0 {
		return nil
	}
	if len(sr.projectTech) == 0 {
		sr.projectTech = []techutils.Technology{vulnerability.Technology}
	}
	vulnFixVersion := getMinimalFixVersion(vulnerability.ImpactedDependencyVersion, vulnerability.FixedVersions)
	if vulnFixVersion == "" {
		return nil
	}
	if vulnDetails, exists := vulnerabilitiesMap[vulnerability.ImpactedDependencyName]; exists {
		// More than one vulnerability can exist on the same impacted package.
		// Among all possible fix versions that fix the above-impacted package, we select the maximum fix version.
		vulnDetails.UpdateFixVersionIfMax(vulnFixVersion)
	} else {
		isDirectDependency, err := utils.IsDirectDependency(vulnerability.ImpactPaths)
		if err != nil {
			if failUponError {
				return err
			}
			log.Warn(fmt.Sprintf("An error occurred while determining if the dependency '%s' is direct: %s.\nAs fail upon scan configuration is permitted, the vulnerability will not be fixed", vulnerability.ImpactedDependencyName, err.Error()))
		}
		// First appearance of a version that fixes the current impacted package
		newVulnDetails := utils.NewVulnerabilityDetails(*vulnerability, vulnFixVersion)
		newVulnDetails.SetIsDirectDependency(isDirectDependency)
		vulnerabilitiesMap[vulnerability.ImpactedDependencyName] = newVulnDetails
	}
	// Set the fixed version array to the relevant fixed version so that only that specific fixed version will be displayed
	vulnerability.FixedVersions = []string{vulnerabilitiesMap[vulnerability.ImpactedDependencyName].SuggestedFixedVersion}
	return nil
}

// Updates impacted package, can return ErrUnsupportedFix.
func (sr *ScanRepositoryCmd) updatePackageToFixedVersion(vulnDetails *utils.VulnerabilityDetails) (err error) {
	if err = isBuildToolsDependency(vulnDetails); err != nil {
		return
	}

	if sr.handlers == nil {
		sr.handlers = make(map[techutils.Technology]packagehandlers.PackageHandler)
	}

	handler := sr.handlers[vulnDetails.Technology]
	if handler == nil {
		handler = packagehandlers.GetCompatiblePackageHandler(vulnDetails, sr.scanDetails)
		sr.handlers[vulnDetails.Technology] = handler
	} else if _, unsupported := handler.(*packagehandlers.UnsupportedPackageHandler); unsupported {
		return
	}

	return sr.handlers[vulnDetails.Technology].UpdateDependency(vulnDetails)
}

// The getRemoteBranchScanHash function extracts the checksum written inside the pull request body and returns it.
func (sr *ScanRepositoryCmd) getRemoteBranchScanHash(prBody string) string {
	// The pattern matches the string "Checksum: <checksum>", followed by one or more word characters (letters, digits, or underscores).
	re := regexp.MustCompile(`Checksum: (\w+)`)
	match := re.FindStringSubmatch(prBody)

	// The first element is the entire matched string, and the second element is the checksum value.
	// If the length of match is not equal to 2, it means that the pattern was not found or the captured group is missing.
	if len(match) != 2 {
		log.Debug("Checksum not found in the aggregated pull request. Frogbot will proceed to update the existing pull request.")
		return ""
	}

	return match[1]
}

func (sr *ScanRepositoryCmd) getOpenPullRequestBySourceBranch(branchName string) (prInfo *vcsclient.PullRequestInfo, err error) {
	list, err := sr.scanDetails.Client().ListOpenPullRequestsWithBody(context.Background(), sr.scanDetails.RepoOwner, sr.scanDetails.RepoName)
	if err != nil {
		return
	}
	for _, pr := range list {
		if pr.Source.Name == branchName {
			log.Debug("Found pull request from source branch ", branchName)
			return &pr, nil
		}
	}
	log.Debug("No pull request found from source branch ", branchName)
	return
}

func (sr *ScanRepositoryCmd) aggregateFixAndOpenPullRequest(repository *utils.Repository, vulnerabilitiesMap map[string]*utils.VulnerabilityDetails, aggregatedFixBranchName string, existingPullRequestInfo *vcsclient.PullRequestInfo) (err error) {
	log.Info("-----------------------------------------------------------------")
	log.Info("Starting aggregated dependencies fix")

	workTreeIsClean, err := sr.gitManager.IsClean()
	if err != nil {
		return
	}
	if !workTreeIsClean {
		// If there are local changes, such as files generated after running an 'install' command, we aim to preserve them in the new branch
		err = sr.gitManager.CreateBranchAndCheckout(aggregatedFixBranchName, true)
	} else {
		err = sr.gitManager.CreateBranchAndCheckout(aggregatedFixBranchName, false)
	}
	if err != nil {
		return
	}

	fixedVulnerabilities, err := sr.fixMultiplePackages(vulnerabilitiesMap)
	if err != nil {
		return err
	}
	updateRequired, e := sr.isUpdateRequired(fixedVulnerabilities, existingPullRequestInfo)
	if e != nil {
		err = errors.Join(err, e)
		return
	}
	if !updateRequired {
		err = errors.Join(err, sr.gitManager.Checkout(sr.scanDetails.BaseBranch()))
		log.Info("The existing pull request is in sync with the latest scan, and no further updates are required.")
		return
	}
	if len(fixedVulnerabilities) > 0 {
		if e = sr.openAggregatedPullRequest(repository, aggregatedFixBranchName, existingPullRequestInfo, fixedVulnerabilities); e != nil {
			err = errors.Join(err, fmt.Errorf("failed while creating aggregated pull request. Error: \n%s", e.Error()))
		}
	}
	log.Info("-----------------------------------------------------------------")
	err = errors.Join(err, sr.gitManager.Checkout(sr.scanDetails.BaseBranch()))
	return
}

// Determines whether an update is necessary:
// First, checks if the working tree is clean. If so, no update is required.
// Second, checks if there is an already open pull request for the fix. If so, no update is needed.
// Lastly, performs a comparison of Xray scan result hashes between an existing pull request's remote source branch and the current source branch to identify any differences.
func (sr *ScanRepositoryCmd) isUpdateRequired(fixedVulnerabilities []*utils.VulnerabilityDetails, prInfo *vcsclient.PullRequestInfo) (updateRequired bool, err error) {
	isClean, err := sr.gitManager.IsClean()
	if err != nil {
		return
	}
	if isClean {
		log.Info("There were no changes to commit after fixing vulnerabilities.\nNote: Frogbot currently cannot address certain vulnerabilities in some package managers, which may result in the absence of changes")
		updateRequired = false
		return
	}

	if prInfo == nil {
		updateRequired = true
		return
	}
	log.Info("Aggregated pull request already exists, verifying if update is needed...")
	log.Debug("Comparing current scan results to existing", prInfo.Target.Name, "scan results")
	fixedVulnerabilitiesRows := utils.ExtractVulnerabilitiesDetailsToRows(fixedVulnerabilities)
	currentScanHash, err := utils.VulnerabilityDetailsToMD5Hash(fixedVulnerabilitiesRows...)
	if err != nil {
		return
	}
	remoteBranchScanHash := sr.getRemoteBranchScanHash(prInfo.Body)
	updateRequired = currentScanHash != remoteBranchScanHash
	if updateRequired {
		log.Info("The existing pull request is not in sync with the latest scan, updating pull request...")
	}
	return
}

// getMinimalFixVersion find the minimal version that fixes the current impactedPackage;
// fixVersions is a sorted array. The function returns the first version in the array, that is larger than impactedPackageVersion.
func getMinimalFixVersion(impactedPackageVersion string, fixVersions []string) string {
	// Trim 'v' prefix in case of Go package
	currVersionStr := strings.TrimPrefix(impactedPackageVersion, "v")
	currVersion := version.NewVersion(currVersionStr)
	for _, fixVersion := range fixVersions {
		fixVersionCandidate := parseVersionChangeString(fixVersion)
		if currVersion.Compare(fixVersionCandidate) > 0 {
			return fixVersionCandidate
		}
	}
	return ""
}

// 1.0         --> 1.0 ≤ x
// (,1.0]      --> x ≤ 1.0
// (,1.0)      --> x < 1.0
// [1.0]       --> x == 1.0
// (1.0,)      --> 1.0 >= x
// (1.0, 2.0)  --> 1.0 < x < 2.0
// [1.0, 2.0]  --> 1.0 ≤ x ≤ 2.0
func parseVersionChangeString(fixVersion string) string {
	latestVersion := strings.Split(fixVersion, ",")[0]
	if latestVersion[0] == '(' {
		return ""
	}
	latestVersion = strings.Trim(latestVersion, "[")
	latestVersion = strings.Trim(latestVersion, "]")
	return latestVersion
}

// Skip build tools dependencies (for example, pip)
// that are not defined in the descriptor file and cannot be fixed by a PR.
func isBuildToolsDependency(vulnDetails *utils.VulnerabilityDetails) error {
	//nolint:typecheck // Ignoring typecheck error: The linter fails to deduce the returned type as []string from utils.BuildToolsDependenciesMap, despite its declaration in utils/utils.go as map[coreutils.Technology][]string.
	if slices.Contains(utils.BuildToolsDependenciesMap[vulnDetails.Technology], vulnDetails.ImpactedDependencyName) {
		return &utils.ErrUnsupportedFix{
			PackageName:  vulnDetails.ImpactedDependencyName,
			FixedVersion: vulnDetails.SuggestedFixedVersion,
			ErrorType:    utils.BuildToolsDependencyFixNotSupported,
		}
	}
	return nil
}
