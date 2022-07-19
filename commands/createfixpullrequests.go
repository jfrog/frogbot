package commands

import (
	"context"
	"fmt"
	"github.com/jfrog/frogbot/commands/utils"
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/gofrog/version"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-core/v2/xray/formats"
	xrayutils "github.com/jfrog/jfrog-cli-core/v2/xray/utils"
	clientLog "github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray/services"
	"os/exec"
	"strings"
)

type CreateFixPullRequestsCmd struct {
	mavenDepToPropertyMap map[string][]string
}

func (cfp CreateFixPullRequestsCmd) Run(params *utils.FrogbotParams, client vcsclient.VcsClient) error {
	//Do scan current branch
	scanResults, err := cfp.scan(params)
	if err != nil {
		return err
	}

	//err = utils.UploadScanToGitProvider(scanResults, params, client)
	//if err != nil {
	//	clientLog.Debug("Unexpected error occurred while generating the sarif file from the scan result: " + err.Error())
	//}

	// Fix and create PRs
	return cfp.fixImpactedPackagesAndCreatePRs(params, client, scanResults)
}

// Audit the dependencies of the current commit.
func (cfp *CreateFixPullRequestsCmd) scan(params *utils.FrogbotParams) ([]services.ScanResponse, error) {
	// Audit commit code
	xrayScanParams := createXrayScanParams(params.Watches, params.Project)
	scanResults, err := auditSource(xrayScanParams, params)
	if err != nil {
		return nil, err
	}
	clientLog.Info("Xray scan completed")
	return scanResults, nil
}

func (cfp *CreateFixPullRequestsCmd) fixImpactedPackagesAndCreatePRs(params *utils.FrogbotParams, client vcsclient.VcsClient, scanResults []services.ScanResponse) error {
	fixVersionsMap, err := cfp.createFixVersionsMap(params, scanResults)
	if err != nil {
		return err
	}
	clientLog.Info("Found", len(fixVersionsMap), "vulnerable dependencies with fix versions")

	gitManager, err := utils.NewGitManager("/Users/omerz/Desktop/dev/frogbot", "test")
	if err != nil {
		return err
	}
	for impactedPackage, fixVersionInfo := range fixVersionsMap {
		clientLog.Info("Fixing", impactedPackage, "with", fixVersionInfo.fixVersion)
		err = cfp.fixSinglePackageAndCreatePR(impactedPackage, *fixVersionInfo, params, client, gitManager)
		if err != nil {
			clientLog.Error("failed while trying to fix and create PR for:", impactedPackage, "with version:", fixVersionInfo.fixVersion, "with error:", err.Error())
		}
		// After finishing to work on the current vulnerability we go back to the base branch to start the next vulnerability fix
		clientLog.Info("Running git checkout to base branch:", params.BaseBranch)
		err = gitManager.Checkout(params.BaseBranch)
		if err != nil {
			return err
		}

	}
	return nil
}

// Create fixVersionMap - a map between impacted packages and their fix version
func (cfp *CreateFixPullRequestsCmd) createFixVersionsMap(params *utils.FrogbotParams, scanResults []services.ScanResponse) (map[string]*FixVersionInfo, error) {
	fixVersionsMap := map[string]*FixVersionInfo{}
	for _, scanResult := range scanResults {
		if len(scanResult.Vulnerabilities) > 0 {
			vulnerabilities, err := xrayutils.PrepareVulnerabilities(scanResult.Vulnerabilities, false)
			if err != nil {
				return nil, err
			}
			for _, vulnerability := range vulnerabilities {
				if vulnerability.FixedVersions != nil && len(vulnerability.FixedVersions) > 0 {
					fixVulnerability, err := cfp.shouldFixVulnerability(params, vulnerability)
					if err != nil {
						return nil, err
					}
					if !fixVulnerability {
						continue
					}
					fixVersion := parseVersionChangeString(vulnerability.FixedVersions[0])
					fixVersionInfo, exists := fixVersionsMap[vulnerability.ImpactedPackageName]
					if exists {
						// Fix version for current impacted package already exists, so we need to select between the existing fix version and the current.
						fixVersionInfo.UpdateFixVersion(fixVersion)
					} else {
						// First appearance of a version that fixes the current impacted package
						fixVersionsMap[vulnerability.ImpactedPackageName] = NewFixVersionInfo(fixVersion, PackageType(vulnerability.Technology))
					}
				}
			}
		}
	}
	return fixVersionsMap, nil
}

func (cfp *CreateFixPullRequestsCmd) shouldFixVulnerability(params *utils.FrogbotParams, vulnerability formats.VulnerabilityOrViolationRow) (bool, error) {
	// In Maven, fix only direct dependencies
	if vulnerability.ImpactedPackageType == "Maven" {
		if cfp.mavenDepToPropertyMap == nil {
			cfp.mavenDepToPropertyMap = make(map[string][]string)
			err := utils.GetVersionProperties(params.WorkingDirectory, cfp.mavenDepToPropertyMap)
			if err != nil {
				return false, err
			}
		}
		if _, exist := cfp.mavenDepToPropertyMap[vulnerability.ImpactedPackageName]; !exist {
			return false, nil
		}
	}
	return true, nil
}

func (cfp *CreateFixPullRequestsCmd) fixSinglePackageAndCreatePR(impactedPackage string, fixVersionInfo FixVersionInfo, params *utils.FrogbotParams, client vcsclient.VcsClient, gitManager *utils.GitManager) (err error) {
	fixBranchName, err := generateFixBranchName(params.BaseBranch, impactedPackage, fixVersionInfo.fixVersion)
	if err != nil {
		return err
	}

	exists, err := gitManager.BranchExistsOnRemote(fixBranchName)
	if err != nil {
		return err
	}
	if exists {
		clientLog.Info("Branch:", fixBranchName, "already exists on remote.")
		return
	}
	clientLog.Info("Creating branch:", fixBranchName)
	err = gitManager.CreateBranchAndCheckout(fixBranchName)
	if err != nil {
		return err
	}

	err = cfp.updatePackageToFixedVersion(fixVersionInfo.packageType, impactedPackage, fixVersionInfo.fixVersion)
	if err != nil {
		return err
	}

	clientLog.Info("Checking if there are changes to commit")
	isClean, err := gitManager.IsClean()
	if err != nil {
		return err
	}
	if isClean {
		return fmt.Errorf("there were no changes to commit after fixing the package '%s'", impactedPackage)
	}

	clientLog.Info("Running git add all and commit")
	commitString := fmt.Sprintf("[🐸 Frogbot] Upgrade %s to %s", impactedPackage, fixVersionInfo.fixVersion)
	err = gitManager.AddAllAndCommit(commitString)
	if err != nil {
		return err
	}
	clientLog.Info("Pushing fix branch:", fixBranchName)
	err = gitManager.Push(params.Token)
	if err != nil {
		return err
	}
	clientLog.Info("Creating Pull Request for:", fixBranchName)
	prBody := commitString + "\n\n" + utils.WhatIsFrogbotMd
	err = client.CreatePullRequest(context.Background(), params.RepoOwner, params.Repo, fixBranchName, params.BaseBranch, commitString, prBody)
	return
}

func (cfp *CreateFixPullRequestsCmd) updatePackageToFixedVersion(packageType PackageType, impactedPackage, fixVersion string) error {
	switch packageType {
	case coreutils.Go:
		fixedImpactPackage := impactedPackage + "@v" + fixVersion
		clientLog.Info(fmt.Sprintf("Running 'go get %s'", fixedImpactPackage))
		var output []byte
		output, err := exec.Command("go", "get", fixedImpactPackage).CombinedOutput() // #nosec G204
		if err != nil {
			return fmt.Errorf("go get command failed: %s - %s", err.Error(), output)
		}
	case coreutils.Npm:
		packageFullName := impactedPackage + "@" + fixVersion
		clientLog.Debug(fmt.Sprintf("Running 'npm install %s'", packageFullName))
		output, err := exec.Command("npm", "install", packageFullName).CombinedOutput() // #nosec G204
		if err != nil {
			return fmt.Errorf("npm install command failed: %s\n%s", err.Error(), output)
		}
	case coreutils.Maven:
		properties := cfp.mavenDepToPropertyMap[impactedPackage]

		// Update the package version. This command updates it only if the version is not a reference to a property.
		updateVersionArgs := []string{"versions:use-dep-version", "-Dincludes=" + impactedPackage, "-DdepVersion=" + fixVersion, "-DgenerateBackupPoms=false"}
		updateVersionCmd := fmt.Sprintf("mvn %s", strings.Join(updateVersionArgs, " "))
		clientLog.Debug(fmt.Sprintf("Running '%s'", updateVersionCmd))
		updateVersionOutput, err := exec.Command("mvn", updateVersionArgs...).CombinedOutput() // #nosec G204
		if err != nil {
			return fmt.Errorf("mvn command failed: %s\n%s", err.Error(), updateVersionOutput)
		}

		// Update properties that represent this package's version.
		for _, property := range properties {
			updatePropertyArgs := []string{"versions:set-property", "-Dproperty=" + property, "-DnewVersion=" + fixVersion, "-DgenerateBackupPoms=false"}
			updatePropertyCmd := fmt.Sprintf("mvn %s", strings.Join(updatePropertyArgs, " "))
			clientLog.Debug(fmt.Sprintf("Running '%s'", updatePropertyCmd))
			updatePropertyOutput, err := exec.Command("mvn", updatePropertyArgs...).CombinedOutput() // #nosec G204
			if err != nil {
				return fmt.Errorf("mvn command failed: %s\n%s", err.Error(), updatePropertyOutput)
			}
		}
	case coreutils.Yarn:
		packageFullName := impactedPackage + "@" + fixVersion
		clientLog.Info(fmt.Sprintf("Running 'yarn up %s'", packageFullName))
		output, err := exec.Command("yarn", "up", packageFullName).CombinedOutput() // #nosec G204
		if err != nil {
			return fmt.Errorf("yarn up command failed: %s\n%s", err.Error(), output)
		}
	case coreutils.Pip:
		packageFullName := impactedPackage + "==" + fixVersion
		clientLog.Info(fmt.Sprintf("Running 'pip3 install %s'", packageFullName))
		output, err := exec.Command("pip3", "install", packageFullName).CombinedOutput() // #nosec G204
		if err != nil {
			return fmt.Errorf("pip3 install command failed: %s\n%s", err.Error(), output)
		}
	default:
		return fmt.Errorf("package type: %s is currently not supported", string(packageType))
	}
	return nil
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

///      1.0         --> 1.0 ≤ x
///      (,1.0]      --> x ≤ 1.0
///      (,1.0)      --> x &lt; 1.0
///      [1.0]       --> x == 1.0
///      (1.0,)      --> 1.0 &lt; x
///      (1.0, 2.0)   --> 1.0 &lt; x &lt; 2.0
///      [1.0, 2.0]   --> 1.0 ≤ x ≤ 2.0
func parseVersionChangeString(fixVersion string) string {
	latestVersion := strings.Split(fixVersion, ",")[0]
	if latestVersion[0] == '(' {
		return ""
	}
	latestVersion = strings.Trim(latestVersion, "[")
	latestVersion = strings.Trim(latestVersion, "]")
	return latestVersion
}

type PackageType string

type FixVersionInfo struct {
	fixVersion  string
	packageType PackageType
}

func NewFixVersionInfo(newFixVersion string, packageType PackageType) *FixVersionInfo {
	return &FixVersionInfo{newFixVersion, packageType}
}

func (fvi *FixVersionInfo) UpdateFixVersion(newFixVersion string) {
	if fvi.fixVersion == "" || version.NewVersion(fvi.fixVersion).AtLeast(newFixVersion) {
		fvi.fixVersion = newFixVersion
	}
}
