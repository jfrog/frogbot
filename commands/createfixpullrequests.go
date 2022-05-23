package commands

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/coreos/go-semver/semver"
	"github.com/jfrog/frogbot/commands/utils"
	"github.com/jfrog/froggit-go/vcsclient"
	xrayutils "github.com/jfrog/jfrog-cli-core/v2/xray/utils"
	clientLog "github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray/services"
)

type CreatePullRequestCmd struct {
}

func (cmd CreatePullRequestCmd) Run(params *utils.FrogbotParams, client vcsclient.VcsClient) error {
	// Do scan current branch
	scanResults, err := scan(params)
	if err != nil {
		return err
	}
	// Fix and create PRs
	return fixImpactedPackagesAndCreatePRs(params, client, scanResults)
}

// Audit the dependencies of the current commit.
func scan(params *utils.FrogbotParams) ([]services.ScanResponse, error) {
	// Audit commit code
	xrayScanParams := createXrayScanParams(params.Watches, params.Project)
	scanResults, err := auditSource(xrayScanParams, params)
	if err != nil {
		return nil, err
	}
	clientLog.Info("Xray scan completed")
	return scanResults, nil
}

func fixImpactedPackagesAndCreatePRs(params *utils.FrogbotParams, client vcsclient.VcsClient, scanResults []services.ScanResponse) error {
	fixVersionsMap, err := createFixVersionsMap(scanResults)
	if err != nil {
		return err
	}
	clientLog.Info("Found", len(fixVersionsMap), "vulnerable dependencies with fix versions")

	gitManager, err := utils.NewGitManager(".", "origin")
	if err != nil {
		return err
	}
	for impactedPackage, fixVersionInfo := range fixVersionsMap {
		clientLog.Info("Fixing", impactedPackage, "with", fixVersionInfo.fixVersion)
		err = fixSinglePackageAndCreatePR(impactedPackage, *fixVersionInfo, params, client, gitManager)
		if err != nil {
			clientLog.Error("failed while trying to fix and create PR for:", impactedPackage, "with version:", fixVersionInfo.fixVersion, "with error:", err.Error())
		}
	}
	return nil
}

// Create fixVersionMap - a map between impacted packages and their fix version
func createFixVersionsMap(scanResults []services.ScanResponse) (map[string]*FixVersionInfo, error) {
	fixVersionsMap := map[string]*FixVersionInfo{}
	for _, scanResult := range scanResults {
		if len(scanResult.Vulnerabilities) > 0 {
			vulnerabilities, err := xrayutils.PrepareVulnerabilities(scanResult.Vulnerabilities, false, false)
			if err != nil {
				return nil, err
			}
			for _, vulnerability := range vulnerabilities {
				if vulnerability.FixedVersions != nil && len(vulnerability.FixedVersions) > 0 {
					fixVersion := parseVersionChangeString(vulnerability.FixedVersions[0])
					fixVersionInfo, exists := fixVersionsMap[vulnerability.ImpactedPackageName]
					if exists {
						// Fix version for current impacted package already exists, so we need to select between the existing fix version and the current.
						fixVersionInfo.UpdateFixVersion(fixVersion)
					} else {
						// First appearance of a version that fixes the current impacted package
						fixVersionsMap[vulnerability.ImpactedPackageName] = NewFixVersionInfo(fixVersion, PackageType(vulnerability.ImpactedPackageType))
					}
				}
			}
		}
	}
	return fixVersionsMap, nil
}

func fixSinglePackageAndCreatePR(impactedPackage string, fixVersionInfo FixVersionInfo, params *utils.FrogbotParams, client vcsclient.VcsClient, gitManager *utils.GitManager) (err error) {
	fixBranchName := fmt.Sprintf("%s-%s-%s-%s", "frogbot", fixVersionInfo.packageType, impactedPackage, fixVersionInfo.fixVersion)
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
	defer func() {
		// After finishing to work on the current vulnerability we go back to the base branch to start the next vulnerability fix
		clientLog.Info("Running git checkout to base branch:", params.BaseBranch)
		e := gitManager.Checkout(params.BaseBranch)
		if err == nil {
			err = e
		}
	}()

	err = updatePackageToFixedVersion(fixVersionInfo.packageType, impactedPackage, fixVersionInfo.fixVersion)
	if err != nil {
		return err
	}

	clientLog.Info("Running git add all and commit")
	commitString := fmt.Sprintf("[frogbot] Upgrade %s to %s", impactedPackage, fixVersionInfo.fixVersion)
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
	err = client.CreatePullRequest(context.Background(), params.RepoOwner, params.Repo, fixBranchName, params.BaseBranch, commitString, commitString)
	return
}

func updatePackageToFixedVersion(packageType PackageType, impactedPackage, fixVersion string) error {
	switch packageType {
	case "Go":
		fixedImpactPackage := impactedPackage + "@v" + fixVersion
		clientLog.Info(fmt.Sprintf("Running 'go get %s'", fixedImpactPackage))
		var output []byte
		output, err := exec.Command("go", "get", fixedImpactPackage).CombinedOutput() // #nosec G204
		if err != nil {
			return fmt.Errorf("go get command failed: %s - %s", err.Error(), output)
		}
	default:
		return fmt.Errorf("package type: %s is currently not supported", string(packageType))
	}
	return nil
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
	// todo: change to NewVersion with error handling
	if fvi.fixVersion == "" || semver.New(newFixVersion).LessThan(*semver.New(fvi.fixVersion)) {
		fvi.fixVersion = newFixVersion
	}
}
