package commands

import (
	"fmt"
	"github.com/coreos/go-semver/semver"
	"github.com/jfrog/frogbot/commands/utils"
	"github.com/jfrog/froggit-go/vcsclient"
	xrayutils "github.com/jfrog/jfrog-cli-core/v2/xray/utils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	clientLog "github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray/services"
	clitool "github.com/urfave/cli/v2"
	"os"
	"os/exec"
	"strings"
)

func CreateFixPullRequests(c *clitool.Context) error {
	// Get params and VCS client
	params, client, err := utils.GetParamsAndClient()
	if err != nil {
		return err
	}
	// Send usage report
	usageReportSent := make(chan error)
	go utils.ReportUsage(c.Command.Name, &params.Server, usageReportSent)

	// Do scan commit
	scanResults, err := scanCommit(params)
	if err != nil {
		return err
	}

	// Fix and create PRs
	err = fixImpactedPackagesAndCreatePRs(params, client, scanResults)
	if err != nil {
		return err
	}

	// Wait for usage report
	<-usageReportSent
	return err
}

// Audit the dependencies of the current commit.
func scanCommit(params *utils.FrogbotParams) ([]services.ScanResponse, error) {
	// Audit commit code
	xrayScanParams := createXrayScanParams(params.Watches, params.Project)
	scanResults, err := auditSource(xrayScanParams, params)
	if err != nil {
		return nil, err
	}
	clientLog.Info("Xray scan completed")
	return scanResults, nil
}

// Audit the dependencies of the current branch.
func fixImpactedPackagesAndCreatePRs(params *utils.FrogbotParams, client vcsclient.VcsClient, scanResults []services.ScanResponse) error {
	fixVersionsMap, err := createFixVersionsMap(scanResults)
	if err != nil {
		return err
	}

	for impactedPackage, fixVersionInfo := range fixVersionsMap {
		err = fixSinglePackageAndCreatePR(impactedPackage, *fixVersionInfo)
		// todo: ignore error?
		if err != nil {
			return err
		}
	}
	//return client.AddPullRequestComment(context.Background(), params.RepoOwner, params.Repo, message, params.PullRequestID)
	return nil
}

// Create vulnerabilities rows. The rows should contain only the new issues added by this PR
func createFixVersionsMap(scanResults []services.ScanResponse) (map[string]*FixVersionInfo, error) {
	fixVersionsMap := map[string]*FixVersionInfo{}
	for _, scanResult := range scanResults {
		if len(scanResult.Violations) > 0 {
			// todo!
		} else if len(scanResult.Vulnerabilities) > 0 {
			vulnerabilities, err := xrayutils.PrepareVulnerabilities(scanResult.Vulnerabilities, false, false)
			if err != nil {
				return nil, err
			}
			for _, vulnerability := range vulnerabilities {
				if vulnerability.FixedVersions != nil && len(vulnerability.FixedVersions) > 0 {
					fixVersion := parseVersionChangeString(vulnerability.FixedVersions[0])
					fixVersionInfo, exists := fixVersionsMap[vulnerability.ImpactedPackageName]
					if exists {
						fixVersionInfo.UpdateFixVersion(fixVersion)
					} else {
						fixVersionsMap[vulnerability.ImpactedPackageName] = NewFixVersionInfo(fixVersion, vulnerability.ImpactedPackageType)
					}
				}
			}
		}
	}
	return fixVersionsMap, nil
}

func fixSinglePackageAndCreatePR(impactedPackage string, fixVersionInfo FixVersionInfo) (err error) {
	wd, err := os.Getwd()
	if err != nil {
		return err
	}

	tempDirPath, err := fileutils.CreateTempDir()
	if err != nil {
		return err
	}
	clientLog.Debug("Created temp working directory: " + tempDirPath)
	defer func() {
		e := fileutils.RemoveTempDir(tempDirPath)
		if err == nil {
			err = e
		}
	}()

	err = fileutils.CopyDir(wd, tempDirPath, true, nil)
	if err != nil {
		return
	}

	switch fixVersionInfo.packageType {
	// todo: get package types from core
	case "Go":
		// todo: place each type on different file
		fixImpactPackage := impactedPackage + "@v" + fixVersionInfo.fixVersion
		goGetCmd := exec.Command("go", "get", fixImpactPackage)
		goGetCmd.Dir = tempDirPath

		clientLog.Debug(fmt.Sprintf("Running 'go get %s'", fixImpactPackage))
		var output []byte
		output, err = goGetCmd.CombinedOutput()
		if err != nil {
			err = fmt.Errorf("go get command failed: %s - %s", err.Error(), output)
			return
		}
	case "Npm":
		packageFullName := impactedPackage + "@" + fixVersionInfo.fixVersion
		npmInstallCmd := exec.Command("npm", "install", packageFullName)
		npmInstallCmd.Dir = tempDirPath

		clientLog.Debug(fmt.Sprintf("Running 'npm install %s'", packageFullName))
		var output []byte
		output, err = npmInstallCmd.CombinedOutput()
		////////////////////
		clientLog.Info("#############")
		clientLog.Info(output)
		clientLog.Info("#############")
		////////////////////
		if err != nil {
			err = fmt.Errorf("npm install command failed: %s\n%s", err.Error(), output)
			return
		}
	default:
	}

	return
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

type FixVersionInfo struct {
	fixVersion  string
	packageType string
}

func NewFixVersionInfo(newFixVersion, packageType string) *FixVersionInfo {
	return &FixVersionInfo{newFixVersion, packageType}
}

func (fvi *FixVersionInfo) UpdateFixVersion(newFixVersion string) {
	// todo: change to NewVersion with error handling
	if fvi.fixVersion == "" || semver.New(newFixVersion).LessThan(*semver.New(fvi.fixVersion)) {
		fvi.fixVersion = newFixVersion
	}
}
