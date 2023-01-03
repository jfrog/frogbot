package utils

import (
	"context"
	"crypto"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/froggit-go/vcsutils"
	"github.com/jfrog/gofrog/datastructures"
	"github.com/jfrog/jfrog-cli-core/v2/artifactory/utils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	xrayutils "github.com/jfrog/jfrog-cli-core/v2/xray/utils"
	"github.com/jfrog/jfrog-client-go/artifactory/usage"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	clientLog "github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray/services"
	"os"
	"strings"
)

type ErrMissingEnv struct {
	VariableName string
}

func (m *ErrMissingEnv) Error() string {
	return fmt.Sprintf("'%s' environment variable is missing", m.VariableName)
}

type ErrMissingConfig struct {
	missingReason string
}

func (e *ErrMissingConfig) Error() string {
	return fmt.Sprintf("config file is missing: %s", e.missingReason)
}

func Chdir(dir string) (cbk func() error, err error) {
	wd, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	if err = os.Chdir(dir); err != nil {
		return nil, err
	}
	return func() error { return os.Chdir(wd) }, err
}

func ReportUsage(commandName string, serverDetails *config.ServerDetails, usageReportSent chan<- error) {
	var err error
	defer func() {
		// The usage reporting is meant to run asynchronously, so that the actual action isn't delayed.
		// It is however important to the application to not exit before the reporting is finished. That is, in case the reporting takes longer than the action.
		usageReportSent <- err
	}()
	if serverDetails.ArtifactoryUrl == "" {
		return
	}
	clientLog.Debug(usage.ReportUsagePrefix + "Sending info...")
	serviceManager, err := utils.CreateServiceManager(serverDetails, -1, 0, false)
	if err != nil {
		clientLog.Debug(usage.ReportUsagePrefix + err.Error())
		return
	}
	err = usage.SendReportUsage(productId, commandName, serviceManager)
	if err != nil {
		clientLog.Debug(err.Error())
		return
	}
}

func Md5Hash(values ...string) (string, error) {
	hash := crypto.MD5.New()
	for _, ob := range values {
		_, err := fmt.Fprint(hash, ob)
		if err != nil {
			return "", err
		}
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// UploadScanToGitProvider uploads scan results to the relevant git provider in order to view the scan in the Git provider code scanning UI
func UploadScanToGitProvider(scanResults []services.ScanResponse, repo *FrogbotRepoConfig, branch string, client vcsclient.VcsClient) error {
	if repo.GitProvider.String() != vcsutils.GitHub.String() {
		clientLog.Debug("Upload Scan to " + repo.GitProvider.String() + " is currently unsupported.")
		return nil
	}

	includeVulnerabilities := repo.JFrogProjectKey == "" && len(repo.Watches) == 0
	scan, err := xrayutils.GenerateSarifFileFromScan(scanResults, includeVulnerabilities, false)
	if err != nil {
		return err
	}
	_, err = client.UploadCodeScanning(context.Background(), repo.RepoOwner, repo.RepoName, branch, scan)
	if err != nil {
		return fmt.Errorf("upload code scanning for %s branch failed with: %s", branch, err.Error())
	}

	return err
}

// SimplifyScanResults specifies which alerts should be displayed when uploading code scanning.
// To avoid uploading many of the same vulnerabilities/violations that could differ only in their impact paths,
// This function returns a scan response with only unique vulnerabilities/violations.
func SimplifyScanResults(scanResults []services.ScanResponse) []services.ScanResponse {
	var simplifiedResults []services.ScanResponse
	simplifiedResults = append(simplifiedResults, scanResults...)

	for resultId, result := range simplifiedResults {
		if len(result.Violations) > 0 {
			simplifiedResults[resultId].Violations = simplifyViolations(result.Violations)
		} else if len(result.Vulnerabilities) > 0 {
			simplifiedResults[resultId].Vulnerabilities = simplifyVulnerabilities(result.Vulnerabilities)
		}
	}

	return simplifiedResults
}

// simplifyVulnerabilities returns vulnerabilities array without duplicates.
func simplifyVulnerabilities(vulnerabilities []services.Vulnerability) []services.Vulnerability {
	var uniqueVulnerabilities = datastructures.MakeSet[string]()
	var cleanVulnerabilities []services.Vulnerability
	for i, vulnerability := range vulnerabilities {
		var cvesBuilder strings.Builder
		for _, cve := range vulnerability.Cves {
			cvesBuilder.WriteString(cve.Id + ", ")
		}
		cves := strings.TrimSuffix(cvesBuilder.String(), ", ")
		for componentId := range vulnerability.Components {
			impactedPackage, _, _ := xrayutils.SplitComponentId(componentId)
			fullPackageKey := "[" + cves + "] " + impactedPackage
			if exist := uniqueVulnerabilities.Exists(fullPackageKey); !exist {
				uniqueVulnerabilities.Add(fullPackageKey)
				continue
			}
			delete(vulnerabilities[i].Components, componentId)
		}
		if len(vulnerability.Components) != 0 {
			cleanVulnerabilities = append(cleanVulnerabilities, vulnerability)
		}
	}

	return cleanVulnerabilities
}

// simplifyViolations returns violations array without duplicates.
func simplifyViolations(violations []services.Violation) []services.Violation {
	var uniqueViolations = datastructures.MakeSet[string]()
	var cleanViolations []services.Violation
	for _, violation := range violations {
		for componentId := range violation.Components {
			impactedPackage, _, _ := xrayutils.SplitComponentId(componentId)
			if exist := uniqueViolations.Exists(impactedPackage); !exist {
				uniqueViolations.Add(impactedPackage)
				continue
			}
			delete(violation.Components, componentId)
		}
		if len(violation.Components) != 0 {
			cleanViolations = append(cleanViolations, violation)
		}
	}

	return cleanViolations
}

func DownloadRepoToTempDir(client vcsclient.VcsClient, branch string, git *Git) (wd string, cleanup func() error, err error) {
	wd, err = fileutils.CreateTempDir()
	if err != nil {
		return
	}
	cleanup = func() error {
		return fileutils.RemoveTempDir(wd)
	}
	clientLog.Debug("Created temp working directory: ", wd)
	clientLog.Debug(fmt.Sprintf("Downloading %s/%s , branch: %s to: %s", git.RepoOwner, git.RepoName, branch, wd))
	if err = client.DownloadRepository(context.Background(), git.RepoOwner, git.RepoName, branch, wd); err != nil {
		return
	}
	clientLog.Debug("Repository download completed")
	return
}

func ValidateSingleRepoConfiguration(configAggregator *FrogbotConfigAggregator) error {
	// Multi repository configuration is supported only in the scanpullrequests and scanandfixrepos commands.
	if len(*configAggregator) > 1 {
		return errors.New(errUnsupportedMultiRepo)
	}
	return nil
}

// GetRelativeWd receive a base working directory along with a full path containing the base working directory, and the relative part is returned without the base prefix.
func GetRelativeWd(fullPathWd, baseWd string) string {
	fullPathWd = strings.TrimSuffix(fullPathWd, string(os.PathSeparator))
	if fullPathWd == baseWd {
		return ""
	}

	return strings.TrimPrefix(fullPathWd, baseWd+string(os.PathSeparator))
}
