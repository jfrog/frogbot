package commands

import (
	"context"
	"errors"
	"fmt"
	"github.com/jfrog/frogbot/commands/utils"
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/gofrog/version"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-core/v2/xray/formats"
	xrayutils "github.com/jfrog/jfrog-cli-core/v2/xray/utils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray/services"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// Package names are case-insensitive with this prefix
var pythonPackageRegexPrefix = "(?i)"

// Match all possible operators and versions syntax
var pythonPackageRegexSuffix = "\\s*(([\\=\\<\\>\\~]=)|([\\>\\<]))\\s*(\\.|\\d)*(\\d|(\\.\\*))(\\,\\s*(([\\=\\<\\>\\~]=)|([\\>\\<])).*\\s*(\\.|\\d)*(\\d|(\\.\\*)))?"

type CreateFixPullRequestsCmd struct {
	// mavenDepToPropertyMap holds a map of direct dependencies found in pom.xml.
	// Keys values are only set if the key version is a property.
	mavenDepToPropertyMap map[string][]string
	// dryRun is used for testing purposes, mocking part of the git commands that requires networking
	dryRun bool
	// When dryRun is enabled, dryRunRepoPath specifies the repository local path to clone
	dryRunRepoPath string
	// The details of the current scan
	details *utils.ScanDetails
	// The current project working directory
	projectWorkingDir string
	// The git client the command performs git operations with
	gitManager *utils.GitManager
}

func (cfp *CreateFixPullRequestsCmd) Run(configAggregator utils.FrogbotConfigAggregator, client vcsclient.VcsClient) error {
	if err := utils.ValidateSingleRepoConfiguration(&configAggregator); err != nil {
		return err
	}
	repository := configAggregator[0]
	for _, branch := range repository.Branches {
		gitManager, err := utils.NewGitManager(cfp.dryRun, cfp.dryRunRepoPath, ".", "origin", cfp.details.Token, cfp.details.Username)
		if err != nil {
			return err
		}
		cfp.gitManager = gitManager
		err = cfp.scanAndFixRepository(&repository, branch, client)
		if err != nil {
			return err
		}
	}
	return nil
}

func (cfp *CreateFixPullRequestsCmd) scanAndFixRepository(repository *utils.FrogbotRepoConfig, branch string, client vcsclient.VcsClient) error {
	baseWd, err := os.Getwd()
	if err != nil {
		return err
	}
	cfp.details = &utils.ScanDetails{
		XrayGraphScanParams:      createXrayScanParams(repository.Watches, repository.JFrogProjectKey),
		ServerDetails:            &repository.Server,
		Git:                      &repository.Git,
		Client:                   client,
		FailOnInstallationErrors: *repository.FailOnSecurityIssues,
		Branch:                   branch,
		ReleasesRepo:             repository.JfrogReleasesRepo,
	}
	for _, project := range repository.Projects {
		cfp.details.Project = project
		projectFullPathWorkingDirs := getFullPathWorkingDirs(project.WorkingDirs, baseWd)
		for _, fullPathWd := range projectFullPathWorkingDirs {
			scanResults, isMultipleRoots, err := cfp.scan(cfp.details, fullPathWd)
			if err != nil {
				return err
			}

			err = utils.UploadScanToGitProvider(scanResults, repository, cfp.details.Branch, cfp.details.Client, isMultipleRoots)
			if err != nil {
				log.Warn(err)
			}

			// Update the working directory to the project current working directory
			cfp.projectWorkingDir = utils.GetRelativeWd(fullPathWd, baseWd)
			// Fix and create PRs
			if err = cfp.fixImpactedPackagesAndCreatePRs(scanResults, isMultipleRoots); err != nil {
				return err
			}
		}
	}
	return nil
}

// Audit the dependencies of the current commit.
func (cfp *CreateFixPullRequestsCmd) scan(scanSetup *utils.ScanDetails, currentWorkingDir string) ([]services.ScanResponse, bool, error) {
	// Audit commit code
	scanResults, isMultipleRoots, err := runInstallAndAudit(scanSetup, currentWorkingDir)
	if err != nil {
		return nil, false, err
	}
	log.Info("Xray scan completed")
	return scanResults, isMultipleRoots, nil
}

func (cfp *CreateFixPullRequestsCmd) fixImpactedPackagesAndCreatePRs(scanResults []services.ScanResponse, isMultipleRoots bool) (err error) {
	fixVersionsMap, err := cfp.createFixVersionsMap(scanResults, isMultipleRoots)
	if err != nil {
		return err
	}

	// Nothing to fix, return
	if len(fixVersionsMap) == 0 {
		log.Info("Didn't find vulnerable dependencies with existing fix versions for", cfp.details.RepoName)
		return nil
	}

	log.Info("Found", len(fixVersionsMap), "vulnerable dependencies with fix versions")
	return cfp.fixVulnerablePackages(fixVersionsMap)
}

func (cfp *CreateFixPullRequestsCmd) fixVulnerablePackages(fixVersionsMap map[string]*FixVersionInfo) (err error) {
	clonedRepoDir, restoreBaseDir, err := cfp.cloneRepository()
	if err != nil {
		return err
	}
	defer func() {
		e1 := restoreBaseDir()
		e2 := fileutils.RemoveTempDir(clonedRepoDir)
		if err == nil {
			err = e1
			if err == nil {
				err = e2
			}
		}
	}()

	// Fix all impacted packages
	for impactedPackage, fixVersionInfo := range fixVersionsMap {
		if err = cfp.fixSinglePackage(impactedPackage, fixVersionInfo); err != nil {
			log.Warn(err)
		}
		// After finishing to work on the current vulnerability, we go back to the base branch to start the next vulnerability fix
		log.Info("Running git checkout to base branch:", cfp.details.Branch)
		if err = cfp.gitManager.Checkout(cfp.details.Branch); err != nil {
			return err
		}
	}
	return nil
}

func (cfp *CreateFixPullRequestsCmd) fixSinglePackage(impactedPackage string, fixVersionInfo *FixVersionInfo) (err error) {
	log.Info("-----------------------------------------------------------------")
	log.Info("Start fixing", impactedPackage, "with", fixVersionInfo.fixVersion)
	fixBranchName, err := cfp.createFixingBranch(impactedPackage, fixVersionInfo)
	if err != nil {
		return fmt.Errorf("failed while creating new branch: \n%s", err.Error())
	}

	if err = cfp.updatePackageToFixedVersion(fixVersionInfo.packageType, impactedPackage, fixVersionInfo.fixVersion); err != nil {
		return fmt.Errorf("failed while fixing %s with version: %s with error: \n%s", impactedPackage, fixVersionInfo.fixVersion, err.Error())
	}

	if err = cfp.openFixingPullRequest(impactedPackage, fixBranchName, fixVersionInfo); err != nil {
		return fmt.Errorf("failed while creating a fixing pull request for: %s with version: %s with error: \n%s",
			impactedPackage, fixVersionInfo.fixVersion, err.Error())
	}
	return
}

func (cfp *CreateFixPullRequestsCmd) openFixingPullRequest(impactedPackage, fixBranchName string, fixVersionInfo *FixVersionInfo) (err error) {
	log.Info("Checking if there are changes to commit")
	isClean, err := cfp.gitManager.IsClean()
	if err != nil {
		return err
	}
	if isClean {
		return fmt.Errorf("there were no changes to commit after fixing the package '%s'", impactedPackage)
	}

	commitString := cfp.gitManager.GenerateCommitMessage(impactedPackage, fixVersionInfo)
	log.Info("Running git add all and commit...")
	err = cfp.gitManager.AddAllAndCommit(commitString)
	if err != nil {
		return err
	}

	log.Info("Pushing fix branch:", fixBranchName, "...")
	err = cfp.gitManager.Push()
	if err != nil {
		return err
	}

	pullRequestTitle := cfp.gitManager.GeneratePullRequestTitle(cfp.details.Branch, impactedPackage, fixVersionInfo.fixVersion)
	log.Info("Creating Pull Request form:", fixBranchName, " to:", cfp.details.Branch)
	prBody := commitString + "\n\n" + utils.WhatIsFrogbotMd
	return cfp.details.Client.CreatePullRequest(context.Background(), cfp.details.RepoOwner, cfp.details.RepoName, pullRequestTitle, cfp.details.Branch, commitString, prBody)
}

func (cfp *CreateFixPullRequestsCmd) createFixingBranch(impactedPackage string, fixVersionInfo *FixVersionInfo) (fixBranchName string, err error) {
	fixBranchName, err = generateFixBranchName(cfp.details.Branch, impactedPackage, fixVersionInfo.fixVersion)
	// TODO implement
	//fixBranchName, err = cfp.gitManager.GenerateFixBranchName(cfp.details.Branch, impactedPackage, fixVersionInfo.fixVersion)
	if err != nil {
		return
	}

	exists, err := cfp.gitManager.BranchExistsOnRemote(fixBranchName)
	if err != nil {
		return
	}
	log.Info("Creating branch:", fixBranchName)
	if exists {
		log.Info("Branch:", fixBranchName, "already exists on remote.")
		return
	}

	return fixBranchName, cfp.gitManager.CreateBranchAndCheckout(fixBranchName)
}

func (cfp *CreateFixPullRequestsCmd) cloneRepository() (tempWd string, restoreDir func() error, err error) {
	// Create temp working directory
	tempWd, err = fileutils.CreateTempDir()
	if err != nil {
		return
	}
	log.Debug("Created temp working directory:", tempWd)

	// Clone the content of the repo to the new working directory
	err = cfp.gitManager.Clone(tempWd, cfp.details.Branch)
	if err != nil {
		return
	}

	// 'CD' into the temp working directory
	restoreDir, err = utils.Chdir(tempWd)
	return
}

// Create fixVersionMap - a map with 'impacted package' as key and 'fix version' as value.
func (cfp *CreateFixPullRequestsCmd) createFixVersionsMap(scanResults []services.ScanResponse, isMultipleRoots bool) (map[string]*FixVersionInfo, error) {
	fixVersionsMap := map[string]*FixVersionInfo{}
	for _, scanResult := range scanResults {
		if len(scanResult.Vulnerabilities) > 0 {
			vulnerabilities, err := xrayutils.PrepareVulnerabilities(scanResult.Vulnerabilities, isMultipleRoots, true)
			if err != nil {
				return nil, err
			}
			for i := range vulnerabilities {
				if err = cfp.addVulnerabilityToFixVersionsMap(&vulnerabilities[i], fixVersionsMap); err != nil {
					return nil, err
				}
			}
		}
	}
	return fixVersionsMap, nil
}

func (cfp *CreateFixPullRequestsCmd) addVulnerabilityToFixVersionsMap(vulnerability *formats.VulnerabilityOrViolationRow, fixVersionsMap map[string]*FixVersionInfo) error {
	if len(vulnerability.FixedVersions) == 0 {
		return nil
	}

	fixVulnerability, err := cfp.shouldFixVulnerability(vulnerability)
	if err != nil {
		return err
	}
	if !fixVulnerability {
		return nil
	}
	vulnFixVersion := getMinimalFixVersion(vulnerability.ImpactedDependencyVersion, vulnerability.FixedVersions)
	if vulnFixVersion == "" {
		return nil
	}

	if fixVersionInfo, exists := fixVersionsMap[vulnerability.ImpactedDependencyName]; exists {
		// More than one vulnerability can exist on the same impacted package.
		// Among all possible fix versions that fix the above impacted package, we select the maximum fix version.
		fixVersionInfo.UpdateFixVersion(vulnFixVersion)
	} else {
		// First appearance of a version that fixes the current impacted package
		fixVersionsMap[vulnerability.ImpactedDependencyName] = NewFixVersionInfo(vulnFixVersion, vulnerability.Technology)
	}
	return nil
}

// getMinimalFixVersion that fixes the current impactedPackage
// fixVersions array is sorted, so we take the first index, unless it's version is older than what we have now.
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

func (cfp *CreateFixPullRequestsCmd) shouldFixVulnerability(vulnerability *formats.VulnerabilityOrViolationRow) (bool, error) {
	if vulnerability.Technology == coreutils.Maven {
		return cfp.shouldFixMavenVulnerability(vulnerability)
	}

	return true, nil
}

func (cfp *CreateFixPullRequestsCmd) shouldFixMavenVulnerability(vulnerability *formats.VulnerabilityOrViolationRow) (bool, error) {
	// In Maven, fix only direct dependencies
	if cfp.mavenDepToPropertyMap == nil {
		// Get all Maven dependencies and plugins from pom.xml
		cfp.mavenDepToPropertyMap = make(map[string][]string)
		for _, workingDir := range cfp.details.Project.WorkingDirs {
			if workingDir == utils.RootDir {
				workingDir = ""
			}
			if err := utils.GetVersionProperties(workingDir, cfp.mavenDepToPropertyMap); err != nil {
				return false, err
			}
		}
	}

	if _, exist := cfp.mavenDepToPropertyMap[vulnerability.ImpactedDependencyName]; !exist {
		return false, nil
	}

	return true, nil
}

func (cfp *CreateFixPullRequestsCmd) updatePackageToFixedVersion(packageType coreutils.Technology, impactedPackage, fixVersion string) (err error) {
	// 'CD' into the relevant working directory
	if cfp.projectWorkingDir != "" {
		restoreDir, err := utils.Chdir(cfp.projectWorkingDir)
		if err != nil {
			return err
		}
		defer func() {
			e := restoreDir()
			if err == nil {
				err = e
			} else if e != nil {
				err = fmt.Errorf("%s\n%s", err.Error(), e.Error())
			}
		}()
	}

	switch packageType {
	case coreutils.Go:
		commandArgs := []string{"get"}
		err = fixPackageVersionGeneric(packageType.GetExecCommandName(), commandArgs, impactedPackage, fixVersion, "@v")
	case coreutils.Npm:
		commandArgs := []string{"install"}
		err = fixPackageVersionGeneric(packageType.GetExecCommandName(), commandArgs, impactedPackage, fixVersion, "@")
	case coreutils.Maven:
		err = fixPackageVersionMaven(cfp, impactedPackage, fixVersion)
	case coreutils.Yarn:
		commandArgs := []string{"up"}
		err = fixPackageVersionGeneric(packageType.GetExecCommandName(), commandArgs, impactedPackage, fixVersion, "@")
	case coreutils.Pip:
		err = fixPackageVersionPip(impactedPackage, fixVersion, cfp.details.Project.PipRequirementsFile)
	case coreutils.Pipenv:
		commandArgs := []string{"install"}
		err = fixPackageVersionGeneric(packageType.GetExecCommandName(), commandArgs, impactedPackage, fixVersion, "==")
	case coreutils.Poetry:
		err = fixPackageVersionPoetry(impactedPackage, fixVersion)
	default:
		return fmt.Errorf("package type: %s is currently not supported", string(packageType))
	}

	return
}

// The majority of package managers already support upgrading specific package versions and update the dependency files automatically.
// In other cases, we had to handle the upgrade process
// commandName - Name of the package manager
// commandArgs - Package manager upgrade command
// impactedPackage - Vulnerable package to upgrade
// fixVersion - The version that fixes the vulnerable package
// operator - The operator between the impactedPackage to the fixVersion
func fixPackageVersionGeneric(commandName string, commandArgs []string, impactedPackage, fixVersion, operator string) error {
	fixedPackage := impactedPackage + operator + fixVersion
	commandArgs = append(commandArgs, fixedPackage)
	return runPackageMangerCommand(commandName, commandArgs)
}

func runPackageMangerCommand(commandName string, commandArgs []string) error {
	fullCommand := commandName + " " + strings.Join(commandArgs, " ")
	log.Debug(fmt.Sprintf("Running '%s'", fullCommand))
	output, err := exec.Command(commandName, commandArgs...).CombinedOutput() // #nosec G204
	if err != nil {
		return fmt.Errorf("%s command failed: %s\n%s", fullCommand, err.Error(), output)
	}
	return nil
}

func fixPackageVersionMaven(cfp *CreateFixPullRequestsCmd, impactedPackage, fixVersion string) error {
	properties := cfp.mavenDepToPropertyMap[impactedPackage]
	// Update the package version. This command updates it only if the version is not a reference to a property.
	updateVersionArgs := []string{"-B", "versions:use-dep-version", "-Dincludes=" + impactedPackage, "-DdepVersion=" + fixVersion, "-DgenerateBackupPoms=false"}
	updateVersionCmd := fmt.Sprintf("mvn %s", strings.Join(updateVersionArgs, " "))
	log.Debug(fmt.Sprintf("Running '%s'", updateVersionCmd))
	updateVersionOutput, err := exec.Command("mvn", updateVersionArgs...).CombinedOutput() // #nosec G204
	if err != nil {
		return fmt.Errorf("mvn command failed: %s\n%s", err.Error(), updateVersionOutput)
	}

	// Update properties that represent this package's version.
	for _, property := range properties {
		updatePropertyArgs := []string{"-B", "versions:set-property", "-Dproperty=" + property, "-DnewVersion=" + fixVersion, "-DgenerateBackupPoms=false"}
		updatePropertyCmd := fmt.Sprintf("mvn %s", strings.Join(updatePropertyArgs, " "))
		log.Debug(fmt.Sprintf("Running '%s'", updatePropertyCmd))
		updatePropertyOutput, err := exec.Command("mvn", updatePropertyArgs...).CombinedOutput() // #nosec G204
		if err != nil {
			return fmt.Errorf("mvn command failed: %s\n%s", err.Error(), updatePropertyOutput)
		}
	}

	return nil
}

func fixPackageVersionPip(impactedPackage, fixVersion, requirementsFile string) error {
	// This function assumes that the version of the dependencies is statically pinned in the requirements file or inside the 'install_requires' array in the setup.py file
	fixedPackage := impactedPackage + "==" + fixVersion
	if requirementsFile == "" {
		requirementsFile = "setup.py"
	}
	wd, err := os.Getwd()
	if err != nil {
		return err
	}
	fullPath := filepath.Join(wd, requirementsFile)
	if !strings.HasPrefix(filepath.Clean(fullPath), wd) {
		return errors.New("wrong requirements file input")
	}
	data, err := os.ReadFile(filepath.Clean(requirementsFile))
	if err != nil {
		return err
	}
	currentFile := string(data)
	// This regex will match the impactedPackage with it's pinned version e.g. PyJWT==1.7.1
	re := regexp.MustCompile(pythonPackageRegexPrefix + impactedPackage + pythonPackageRegexSuffix)
	packageToReplace := re.FindString(currentFile)
	if packageToReplace == "" {
		return fmt.Errorf("impacted package %s not found, fix failed", packageToReplace)
	}
	fixedFile := strings.Replace(currentFile, packageToReplace, fixedPackage, 1)
	err = os.WriteFile(requirementsFile, []byte(fixedFile), 0600)
	if err != nil {
		return err
	}

	return nil
}

func fixPackageVersionPoetry(impactedPackage, fixVersion string) error {
	// Install the desired fixed version
	err := fixPackageVersionGeneric(coreutils.Poetry.GetExecCommandName(), []string{"add"}, impactedPackage, fixVersion, "==")
	if err != nil {
		return err
	}
	// Update Poetry lock file as well
	return runPackageMangerCommand(coreutils.Poetry.GetExecCommandName(), []string{"update"})
}

func generateFixBranchName(baseBranch, impactedPackage, fixVersion string) (string, error) {
	uniqueString, err := utils.Md5Hash("frogbot", baseBranch, impactedPackage, fixVersion)
	if err != nil {
		return "", err
	}
	// Package names in Maven usually contain colons, which are not allowed in a branch name
	fixedPackageName := strings.ReplaceAll(impactedPackage, ":", "_")
	// fixBranchName example: 'frogbot-gopkg.in/yaml.v3-cedc1e5462e504fc992318d24e343e48'
	return fmt.Sprintf("%s-%s-%s", "frogbot", fixedPackageName, uniqueString), nil
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

type FixVersionInfo struct {
	fixVersion  string
	packageType coreutils.Technology
}

func NewFixVersionInfo(newFixVersion string, packageType coreutils.Technology) *FixVersionInfo {
	return &FixVersionInfo{newFixVersion, packageType}
}

func (fvi *FixVersionInfo) UpdateFixVersion(newFixVersion string) {
	// Update fvi.fixVersion as the maximum version if found a new version that is greater than the previous maximum version.
	if fvi.fixVersion == "" || version.NewVersion(fvi.fixVersion).Compare(newFixVersion) > 0 {
		fvi.fixVersion = newFixVersion
	}
}
