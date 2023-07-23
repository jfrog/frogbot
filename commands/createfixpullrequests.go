package commands

import (
	"context"
	"errors"
	"fmt"
	"github.com/jfrog/frogbot/commands/utils"
	"github.com/jfrog/frogbot/commands/utils/packagehandlers"
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/froggit-go/vcsutils"
	"github.com/jfrog/gofrog/version"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	audit "github.com/jfrog/jfrog-cli-core/v2/xray/commands/audit/generic"
	"github.com/jfrog/jfrog-cli-core/v2/xray/formats"
	xrayutils "github.com/jfrog/jfrog-cli-core/v2/xray/utils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
	"os"
	"regexp"
	"strings"
)

type CreateFixPullRequestsCmd struct {
	// The interface that Frogbot utilizes to format and style the displayed messages on the Git providers
	utils.OutputWriter
	// dryRun is used for testing purposes, mocking part of the git commands that requires networking
	dryRun bool
	// When dryRun is enabled, dryRunRepoPath specifies the repository local path to clone
	dryRunRepoPath string
	// The details of the current scan
	details *utils.ScanDetails
	// The base working directory
	baseWd string
	// The git client the command performs git operations with
	gitManager *utils.GitManager
	// Determines whether to open a pull request for each vulnerability fix or to aggregate all fixes into one pull request
	aggregateFixes bool
	// The current project technology
	projectTech coreutils.Technology
	// Stores all package manager handlers for detected issues
	handlers map[coreutils.Technology]packagehandlers.PackageHandler
}

func (cfp *CreateFixPullRequestsCmd) Run(repoAggregator utils.RepoAggregator, client vcsclient.VcsClient) error {
	if err := utils.ValidateSingleRepoConfiguration(&repoAggregator); err != nil {
		return err
	}
	repository := repoAggregator[0]
	for _, branch := range repository.Branches {
		err := cfp.scanAndFixRepository(&repository, branch, client)
		if err != nil {
			return err
		}
	}
	return nil
}

func (cfp *CreateFixPullRequestsCmd) scanAndFixRepository(repository *utils.Repository, branch string, client vcsclient.VcsClient) (err error) {
	cfp.baseWd, err = os.Getwd()
	if err != nil {
		return
	}
	cfp.setCommandPrerequisites(repository, branch, client)
	for i := range repository.Projects {
		cfp.details.Project = &repository.Projects[i]
		cfp.projectTech = ""
		if err = cfp.scanAndFixProject(repository); err != nil {
			return
		}
	}
	return
}

func (cfp *CreateFixPullRequestsCmd) setCommandPrerequisites(repository *utils.Repository, branch string, client vcsclient.VcsClient) {
	cfp.details = utils.NewScanDetails(client, &repository.Server, &repository.Git).
		SetXrayGraphScanParams(repository.Watches, repository.JFrogProjectKey).
		SetFailOnInstallationErrors(*repository.FailOnSecurityIssues).
		SetBranch(branch).
		SetFixableOnly(repository.FixableOnly).
		SetMinSeverity(repository.MinSeverity)
	cfp.aggregateFixes = repository.Git.AggregateFixes
	cfp.OutputWriter = utils.GetCompatibleOutputWriter(repository.GitProvider)
}

func (cfp *CreateFixPullRequestsCmd) scanAndFixProject(repository *utils.Repository) error {
	var fixNeeded bool
	// A map that contains the full project paths as a keys
	// The value is a map of vulnerable package names -> the details of the vulnerable packages.x
	// That means we have a map of all the vulnerabilities that were found in a specific folder, along with their full details.
	vulnerabilitiesByPathMap := make(map[string]map[string]*utils.VulnerabilityDetails)
	projectFullPathWorkingDirs := getFullPathWorkingDirs(cfp.details.Project.WorkingDirs, cfp.baseWd)
	for _, fullPathWd := range projectFullPathWorkingDirs {
		scanResults, err := cfp.scan(fullPathWd)
		if err != nil {
			return err
		}

		if !cfp.dryRun {
			if err = utils.UploadScanToGitProvider(scanResults, repository, cfp.details.Branch(), cfp.details.Client()); err != nil {
				log.Warn(err)
			}
		}

		// Prepare the vulnerabilities map for each working dir path
		currPathVulnerabilities, err := cfp.getVulnerabilitiesMap(scanResults.ExtendedScanResults, scanResults.IsMultipleRootProject)
		if err != nil {
			return err
		}
		if len(currPathVulnerabilities) > 0 {
			fixNeeded = true
		}
		vulnerabilitiesByPathMap[fullPathWd] = currPathVulnerabilities
	}
	if fixNeeded {
		return cfp.fixVulnerablePackages(vulnerabilitiesByPathMap)
	}
	return nil
}

// Audit the dependencies of the current commit.
func (cfp *CreateFixPullRequestsCmd) scan(currentWorkingDir string) (*audit.Results, error) {
	// Audit commit code
	auditResults, err := runInstallAndAudit(cfp.details, currentWorkingDir)
	if err != nil {
		return nil, err
	}
	log.Info("Xray scan completed")
	cfp.OutputWriter.SetEntitledForJas(auditResults.ExtendedScanResults.EntitledForJas)
	return auditResults, nil
}

func (cfp *CreateFixPullRequestsCmd) getVulnerabilitiesMap(scanResults *xrayutils.ExtendedScanResults, isMultipleRoots bool) (map[string]*utils.VulnerabilityDetails, error) {
	vulnerabilitiesMap, err := cfp.createVulnerabilitiesMap(scanResults, isMultipleRoots)
	if err != nil {
		return nil, err
	}

	// Nothing to fix, return
	if len(vulnerabilitiesMap) == 0 {
		log.Info("Didn't find vulnerable dependencies with existing fix versions for", cfp.details.RepoName)
	}
	return vulnerabilitiesMap, nil
}

func (cfp *CreateFixPullRequestsCmd) fixVulnerablePackages(vulnerabilitiesByWdMap map[string]map[string]*utils.VulnerabilityDetails) (err error) {
	if cfp.gitManager == nil {
		cfp.gitManager, err = utils.NewGitManager(cfp.dryRun, cfp.dryRunRepoPath, ".", "origin", cfp.details.Token, cfp.details.Username, cfp.details.Git)
		if err != nil {
			return
		}
	}
	clonedRepoDir, restoreBaseDir, err := cfp.cloneRepository()
	if err != nil {
		return
	}
	defer func() {
		// On dry run don't delete the folder as we want to validate results.
		if !cfp.dryRun {
			err = errors.Join(err, restoreBaseDir(), fileutils.RemoveTempDir(clonedRepoDir))
		}
	}()

	if cfp.aggregateFixes {
		return cfp.fixIssuesSinglePR(vulnerabilitiesByWdMap)
	}
	return cfp.fixIssuesSeparatePRs(vulnerabilitiesByWdMap)
}

func (cfp *CreateFixPullRequestsCmd) fixIssuesSeparatePRs(vulnerabilitiesMap map[string]map[string]*utils.VulnerabilityDetails) error {
	var err error
	for fullPath, vulnerabilities := range vulnerabilitiesMap {
		if e := cfp.fixProjectVulnerabilities(fullPath, vulnerabilities); e != nil {
			err = errors.Join(err, fmt.Errorf("the following errors occured while fixing vulnerabilities in %s:\n%s", fullPath, e))
		}
	}
	return err
}

func (cfp *CreateFixPullRequestsCmd) fixProjectVulnerabilities(fullProjectPath string, vulnerabilities map[string]*utils.VulnerabilityDetails) (err error) {
	// Update the working directory to the project's current working directory
	projectWorkingDir := utils.GetRelativeWd(fullProjectPath, cfp.baseWd)

	// 'CD' into the relevant working directory
	if projectWorkingDir != "" {
		restoreDir, err := utils.Chdir(projectWorkingDir)
		if err != nil {
			return err
		}
		defer func() {
			err = errors.Join(err, restoreDir())
		}()
	}

	// Fix every vulnerability in a separate pull request and branch
	for _, vulnerability := range vulnerabilities {
		if e := cfp.fixSinglePackageAndCreatePR(vulnerability); e != nil {
			err = errors.Join(err, cfp.handleUpdatePackageErrors(e))
		}

		// After fixing the current vulnerability, checkout to the base branch to start fixing the next vulnerability
		log.Debug("Running git checkout to base branch:", cfp.details.Branch())
		if e := cfp.gitManager.CheckoutLocalBranch(cfp.details.Branch()); e != nil {
			err = errors.Join(err, cfp.handleUpdatePackageErrors(e))
			return
		}
	}

	return
}

func (cfp *CreateFixPullRequestsCmd) fixMultiplePackages(fullProjectPath string, vulnerabilities map[string]*utils.VulnerabilityDetails) (fixedVulnerabilities []*utils.VulnerabilityDetails, err error) {
	// Update the working directory to the project's current working directory
	projectWorkingDir := utils.GetRelativeWd(fullProjectPath, cfp.baseWd)

	// 'CD' into the relevant working directory
	if projectWorkingDir != "" {
		restoreDir, err := utils.Chdir(projectWorkingDir)
		if err != nil {
			return nil, err
		}
		defer func() {
			err = errors.Join(err, restoreDir())
		}()
	}
	for _, vulnDetails := range vulnerabilities {
		if e := cfp.updatePackageToFixedVersion(vulnDetails); e != nil {
			err = errors.Join(err, cfp.handleUpdatePackageErrors(e))
			continue
		}
		fixedVulnerabilities = append(fixedVulnerabilities, vulnDetails)
		log.Info(fmt.Sprintf("Updated dependency '%s' to version '%s'", vulnDetails.ImpactedDependencyName, vulnDetails.SuggestedFixedVersion))
	}
	return
}

// fixIssuesSinglePR fixes all the vulnerabilities in a single aggregated pull request.
// If an existing aggregated fix is present, it checks for different scan results.
// If the scan results are the same, no action is taken.
// Otherwise, it performs a force push to the same branch and reopens the pull request if it was closed.
// Only one aggregated pull request should remain open at all times.
func (cfp *CreateFixPullRequestsCmd) fixIssuesSinglePR(vulnerabilitiesMap map[string]map[string]*utils.VulnerabilityDetails) (err error) {
	aggregatedFixBranchName, err := cfp.gitManager.GenerateAggregatedFixBranchName(cfp.projectTech)
	if err != nil {
		return
	}
	existingPullRequestDetails, err := cfp.getOpenPullRequestBySourceBranch(aggregatedFixBranchName)
	if err != nil {
		return
	}
	return cfp.aggregateFixAndOpenPullRequest(vulnerabilitiesMap, aggregatedFixBranchName, existingPullRequestDetails)
}

// Handles possible error of update package operation
// When the expected custom error occurs, log to debug.
// else, return the error
func (cfp *CreateFixPullRequestsCmd) handleUpdatePackageErrors(err error) error {
	if _, isCustomError := err.(*utils.ErrUnsupportedFix); isCustomError {
		log.Debug(err.Error())
		return nil
	}
	return err
}

// Creates a branch for the fixed package and open pull request against the target branch.
// In case a branch already exists on remote, we skip it.
func (cfp *CreateFixPullRequestsCmd) fixSinglePackageAndCreatePR(vulnDetails *utils.VulnerabilityDetails) (err error) {
	fixVersion := vulnDetails.SuggestedFixedVersion
	log.Debug("Attempting to fix", vulnDetails.ImpactedDependencyName, "with", fixVersion)
	fixBranchName, err := cfp.gitManager.GenerateFixBranchName(cfp.details.Branch(), vulnDetails.ImpactedDependencyName, fixVersion)
	if err != nil {
		return
	}
	existsInRemote, err := cfp.gitManager.BranchExistsInRemote(fixBranchName)
	if err != nil {
		return
	}
	if existsInRemote {
		log.Info(fmt.Sprintf("A pull request updating the dependency '%s' to version '%s' already exists. Skipping...", vulnDetails.ImpactedDependencyName, vulnDetails.SuggestedFixedVersion))
		return
	}
	if err = cfp.gitManager.CreateBranchAndCheckout(fixBranchName); err != nil {
		return fmt.Errorf("failed while creating new branch: \n%s", err.Error())
	}
	if err = cfp.updatePackageToFixedVersion(vulnDetails); err != nil {
		return
	}
	if err = cfp.openFixingPullRequest(fixBranchName, vulnDetails); err != nil {
		return fmt.Errorf("failed while creating a fixing pull request for: %s with version: %s with error: \n%s",
			vulnDetails.ImpactedDependencyName, fixVersion, err.Error())
	}
	log.Info(fmt.Sprintf("Created Pull Request updating dependency '%s' to version '%s'", vulnDetails.ImpactedDependencyName, vulnDetails.SuggestedFixedVersion))
	return
}

func (cfp *CreateFixPullRequestsCmd) openFixingPullRequest(fixBranchName string, vulnDetails *utils.VulnerabilityDetails) (err error) {
	log.Debug("Checking if there are changes to commit")
	isClean, err := cfp.gitManager.IsClean()
	if err != nil {
		return
	}
	if isClean {
		return fmt.Errorf("there were no changes to commit after fixing the package '%s'", vulnDetails.ImpactedDependencyName)
	}
	commitMessage := cfp.gitManager.GenerateCommitMessage(vulnDetails.ImpactedDependencyName, vulnDetails.SuggestedFixedVersion)
	if err = cfp.gitManager.AddAllAndCommit(commitMessage); err != nil {
		return
	}
	if err = cfp.gitManager.Push(false, fixBranchName); err != nil {
		return
	}
	scanHash, err := utils.VulnerabilityDetailsToMD5Hash(vulnDetails)
	if err != nil {
		return err
	}
	pullRequestTitle, prBody := cfp.preparePullRequestDetails(scanHash, []formats.VulnerabilityOrViolationRow{*vulnDetails.VulnerabilityOrViolationRow})
	log.Debug("Creating Pull Request form:", fixBranchName, " to:", cfp.details.Branch())
	return cfp.details.Client().CreatePullRequest(context.Background(), cfp.details.RepoOwner, cfp.details.RepoName, fixBranchName, cfp.details.Branch(), pullRequestTitle, prBody)
}

// openAggregatedPullRequest handles the opening or updating of a pull request when the aggregate mode is active.
// If a pull request is already open, Frogbot will update the branch and the pull request body.
func (cfp *CreateFixPullRequestsCmd) openAggregatedPullRequest(fixBranchName string, pullRequestInfo *vcsclient.PullRequestInfo, vulnerabilities []*utils.VulnerabilityDetails) (err error) {
	commitMessage := cfp.gitManager.GenerateAggregatedCommitMessage(cfp.projectTech)
	if err = cfp.gitManager.AddAllAndCommit(commitMessage); err != nil {
		return
	}
	if err = cfp.gitManager.Push(true, fixBranchName); err != nil {
		return
	}
	scanHash, err := utils.VulnerabilityDetailsToMD5Hash(vulnerabilities...)
	if err != nil {
		return
	}
	var vulnerabilityRows []formats.VulnerabilityOrViolationRow
	for _, vulnerability := range vulnerabilities {
		vulnerabilityRows = append(vulnerabilityRows, *vulnerability.VulnerabilityOrViolationRow)
	}
	pullRequestTitle, prBody := cfp.preparePullRequestDetails(scanHash, vulnerabilityRows)
	if pullRequestInfo == nil {
		log.Info("Creating Pull Request from:", fixBranchName, "to:", cfp.details.Branch())
		return cfp.details.Client().CreatePullRequest(context.Background(), cfp.details.RepoOwner, cfp.details.RepoName, fixBranchName, cfp.details.Branch(), pullRequestTitle, prBody)
	}
	log.Info("Updating Pull Request from:", fixBranchName, "to:", cfp.details.Branch())
	return cfp.details.Client().UpdatePullRequest(context.Background(), cfp.details.RepoOwner, cfp.details.RepoName, pullRequestTitle, prBody, "", int(pullRequestInfo.ID), vcsutils.Open)
}

func (cfp *CreateFixPullRequestsCmd) preparePullRequestDetails(scanHash string, vulnerabilitiesRows []formats.VulnerabilityOrViolationRow) (string, string) {
	if cfp.dryRun && cfp.aggregateFixes {
		// For testings, don't compare pull request body as scan results order may change.
		return utils.GetAggregatedPullRequestTitle(cfp.projectTech), ""
	}

	prBody := cfp.OutputWriter.VulnerabiltiesTitle(false) + "\n" + cfp.OutputWriter.VulnerabilitiesContent(vulnerabilitiesRows) + "\n---\n" + cfp.OutputWriter.UntitledForJasMsg() + cfp.OutputWriter.Footer()
	if cfp.aggregateFixes {
		return utils.GetAggregatedPullRequestTitle(cfp.projectTech), prBody + utils.MarkdownComment(fmt.Sprintf("Checksum: %s", scanHash))
	}
	// In separate pull requests there is only one vulnerability
	vulnDetails := vulnerabilitiesRows[0]
	pullRequestTitle := cfp.gitManager.GeneratePullRequestTitle(vulnDetails.ImpactedDependencyName, vulnDetails.FixedVersions[0])
	return pullRequestTitle, prBody
}

func (cfp *CreateFixPullRequestsCmd) cloneRepository() (tempWd string, restoreDir func() error, err error) {
	if cfp.dryRunRepoPath != "" {
		tempWd, err = cfp.getDryRunClonedRepo()
	} else {
		// Create temp working directory
		tempWd, err = fileutils.CreateTempDir()
	}
	if err != nil {
		return
	}
	log.Debug("Created temp working directory:", tempWd)

	// Clone the content of the repo to the new working directory
	if err = cfp.gitManager.Clone(tempWd, cfp.details.Branch()); err != nil {
		return
	}

	// 'CD' into the temp working directory
	restoreDir, err = utils.Chdir(tempWd)
	return
}

func (cfp *CreateFixPullRequestsCmd) getDryRunClonedRepo() (tempWd string, err error) {
	// Check if we already cloned the repository before, for multi projects tests
	// Return the existing folder if exists
	var files []string
	files, err = fileutils.ListFiles(cfp.dryRunRepoPath, true)
	if err != nil {
		return
	}
	for _, file := range files {
		if strings.Contains(file, "nested-temp.") {
			cfp.gitManager.SkipClone = true
			tempWd = file
			return
		}
	}
	// Create the temp folder nested in the current folder
	return os.MkdirTemp(cfp.dryRunRepoPath, "nested-temp.")
}

// Create a vulnerabilities map - a map with 'impacted package' as a key and all the necessary information of this vulnerability as value.
func (cfp *CreateFixPullRequestsCmd) createVulnerabilitiesMap(scanResults *xrayutils.ExtendedScanResults, isMultipleRoots bool) (map[string]*utils.VulnerabilityDetails, error) {
	vulnerabilitiesMap := map[string]*utils.VulnerabilityDetails{}
	for _, scanResult := range scanResults.XrayResults {
		if len(scanResult.Vulnerabilities) > 0 {
			vulnerabilities, err := xrayutils.PrepareVulnerabilities(scanResult.Vulnerabilities, scanResults, isMultipleRoots, true)
			if err != nil {
				return nil, err
			}
			for i := range vulnerabilities {
				if err = cfp.addVulnerabilityToFixVersionsMap(&vulnerabilities[i], vulnerabilitiesMap); err != nil {
					return nil, err
				}
			}
		} else if len(scanResult.Violations) > 0 {
			violations, _, _, err := xrayutils.PrepareViolations(scanResult.Violations, scanResults, isMultipleRoots, true)
			if err != nil {
				return nil, err
			}
			for i := range violations {
				if err = cfp.addVulnerabilityToFixVersionsMap(&violations[i], vulnerabilitiesMap); err != nil {
					return nil, err
				}
			}
		}
	}
	log.Debug("Frogbot will attempt to resolve the following vulnerable dependencies:\n", strings.Join(maps.Keys(vulnerabilitiesMap), ",\n"))
	return vulnerabilitiesMap, nil
}

func (cfp *CreateFixPullRequestsCmd) addVulnerabilityToFixVersionsMap(vulnerability *formats.VulnerabilityOrViolationRow, vulnerabilitiesMap map[string]*utils.VulnerabilityDetails) error {
	if len(vulnerability.FixedVersions) == 0 {
		return nil
	}
	if cfp.projectTech == "" {
		cfp.projectTech = vulnerability.Technology
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
			return err
		}
		// First appearance of a version that fixes the current impacted package
		newVulnDetails := utils.NewVulnerabilityDetails(vulnerability, vulnFixVersion)
		newVulnDetails.SetIsDirectDependency(isDirectDependency)
		vulnerabilitiesMap[vulnerability.ImpactedDependencyName] = newVulnDetails
	}
	// Set the fixed version array to the relevant fixed version so that only that specific fixed version will be displayed
	vulnerability.FixedVersions = []string{vulnerabilitiesMap[vulnerability.ImpactedDependencyName].SuggestedFixedVersion}
	return nil
}

// Updates impacted package, can return ErrUnsupportedFix.
func (cfp *CreateFixPullRequestsCmd) updatePackageToFixedVersion(vulnDetails *utils.VulnerabilityDetails) (err error) {
	if err = isBuildToolsDependency(vulnDetails); err != nil {
		return
	}

	if cfp.handlers == nil {
		cfp.handlers = make(map[coreutils.Technology]packagehandlers.PackageHandler)
	}

	handler := cfp.handlers[vulnDetails.Technology]
	if handler == nil {
		handler = packagehandlers.GetCompatiblePackageHandler(vulnDetails, cfp.details)
		cfp.handlers[vulnDetails.Technology] = handler
	} else if _, unsupported := handler.(*packagehandlers.UnsupportedPackageHandler); unsupported {
		return
	}

	return cfp.handlers[vulnDetails.Technology].UpdateDependency(vulnDetails)
}

// The getRemoteBranchScanHash function extracts the checksum written inside the pull request body and returns it.
func (cfp *CreateFixPullRequestsCmd) getRemoteBranchScanHash(prBody string) string {
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

func (cfp *CreateFixPullRequestsCmd) getOpenPullRequestBySourceBranch(branchName string) (prInfo *vcsclient.PullRequestInfo, err error) {
	list, err := cfp.details.Client().ListOpenPullRequestsWithBody(context.Background(), cfp.details.RepoOwner, cfp.details.RepoName)
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

func (cfp *CreateFixPullRequestsCmd) aggregateFixAndOpenPullRequest(vulnerabilitiesMap map[string]map[string]*utils.VulnerabilityDetails, aggregatedFixBranchName string, existingPullRequestInfo *vcsclient.PullRequestInfo) (err error) {
	log.Info("-----------------------------------------------------------------")
	log.Info("Starting aggregated dependencies fix")
	if err = cfp.gitManager.CreateBranchAndCheckout(aggregatedFixBranchName); err != nil {
		return
	}
	// Fix all packages in the same branch if expected error accrued, log and continue.
	var fixedVulnerabilities []*utils.VulnerabilityDetails
	for fullPath, vulnerabilities := range vulnerabilitiesMap {
		currentFixes, e := cfp.fixMultiplePackages(fullPath, vulnerabilities)
		if e != nil {
			err = errors.Join(err, fmt.Errorf("the following errors occured while fixing vulnerabilities in %s:\n%s", fullPath, e))
			continue
		}
		fixedVulnerabilities = append(fixedVulnerabilities, currentFixes...)
	}
	updateRequired, e := cfp.isUpdateRequired(fixedVulnerabilities, existingPullRequestInfo)
	if err != nil {
		err = errors.Join(err, e)
		return
	}
	if !updateRequired {
		log.Info("The existing pull request is in sync with the latest scan, and no further updates are required.")
		return
	}
	if len(fixedVulnerabilities) > 0 {
		if e := cfp.openAggregatedPullRequest(aggregatedFixBranchName, existingPullRequestInfo, fixedVulnerabilities); e != nil {
			err = errors.Join(err, fmt.Errorf("failed while creating aggreagted pull request. Error: \n%s", err.Error()))
		}
	}
	log.Info("-----------------------------------------------------------------")
	if e := cfp.gitManager.CheckoutLocalBranch(cfp.details.Branch()); e != nil {
		err = errors.Join(err, e)
	}
	return
}

// Performs a comparison of the Xray scan results hashes between an existing pull request's remote source branch
// and the current source branch to identify any differences.
func (cfp *CreateFixPullRequestsCmd) isUpdateRequired(fixedVulnerabilities []*utils.VulnerabilityDetails, prInfo *vcsclient.PullRequestInfo) (updateRequired bool, err error) {
	if prInfo == nil {
		updateRequired = true
		return
	}
	log.Info("Aggregated pull request already exists, verifying if update is needed...")
	log.Debug("Comparing current scan results to existing", prInfo.Target.Name, "scan results")
	currentScanHash, err := utils.VulnerabilityDetailsToMD5Hash(fixedVulnerabilities...)
	if err != nil {
		return
	}
	remoteBranchScanHash := cfp.getRemoteBranchScanHash(prInfo.Body)
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
// (,1.0)      --> x &lt; 1.0
// [1.0]       --> x == 1.0
// (1.0,)      --> 1.0 &lt; x
// (1.0, 2.0)  --> 1.0 &lt; x &lt; 2.0
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
	if slices.Contains(utils.BuildToolsDependenciesMap[vulnDetails.Technology], vulnDetails.ImpactedDependencyName) {
		return &utils.ErrUnsupportedFix{
			PackageName:  vulnDetails.ImpactedDependencyName,
			FixedVersion: vulnDetails.SuggestedFixedVersion,
			ErrorType:    utils.BuildToolsDependencyFixNotSupported,
		}
	}
	return nil
}
