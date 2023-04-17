package utils

import (
	"context"
	"crypto"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/froggit-go/vcsutils"
	"github.com/jfrog/jfrog-cli-core/v2/artifactory/utils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/xray/formats"
	xrayutils "github.com/jfrog/jfrog-cli-core/v2/xray/utils"
	"github.com/jfrog/jfrog-client-go/artifactory/usage"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray/services"
	"os"
	"strconv"
	"strings"
)

const RootDir = "."

var (
	TrueVal        = true
	FrogbotVersion = "0.0.0"
)

const (
	Patch = 3
	Minor = 2
	Major = 1
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

type ErrUnsupportedIndirectFix struct {
	PackageName string
}

func (e *ErrUnsupportedIndirectFix) Error() string {
	return fmt.Sprintf("Indirect dependecy %s fix it not supported ", e.PackageName)
}

type ScanDetails struct {
	services.XrayGraphScanParams
	Project
	*config.ServerDetails
	*Git
	Client                   vcsclient.VcsClient
	FailOnInstallationErrors bool
	Branch                   string
	ReleasesRepo             string
}

// The OutputWriter interface allows Frogbot output to be written in an appropriate way for each git provider.
// Some git providers support markdown only partially, whereas others support it fully.
type OutputWriter interface {
	TableRow(vulnerability formats.VulnerabilityOrViolationRow) string
	NoVulnerabilitiesTitle() string
	VulnerabiltiesTitle() string
	TableHeader() string
	IsFrogbotResultComment(comment string) bool
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
	log.Debug(usage.ReportUsagePrefix + "Sending info...")
	serviceManager, err := utils.CreateServiceManager(serverDetails, -1, 0, false)
	if err != nil {
		log.Debug(usage.ReportUsagePrefix + err.Error())
		return
	}
	err = usage.SendReportUsage(productId, commandName, serviceManager)
	if err != nil {
		log.Debug(err.Error())
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
func UploadScanToGitProvider(scanResults []services.ScanResponse, repo *FrogbotRepoConfig, branch string, client vcsclient.VcsClient, isMultipleRoots bool) error {
	if repo.GitProvider.String() != vcsutils.GitHub.String() {
		log.Debug("Upload Scan to " + repo.GitProvider.String() + " is currently unsupported.")
		return nil
	}

	scan, err := xrayutils.GenerateSarifFileFromScan(scanResults, isMultipleRoots, true)
	if err != nil {
		return err
	}
	_, err = client.UploadCodeScanning(context.Background(), repo.RepoOwner, repo.RepoName, branch, scan)
	if err != nil {
		return fmt.Errorf("upload code scanning for %s branch failed with: %s", branch, err.Error())
	}

	return err
}

func DownloadRepoToTempDir(client vcsclient.VcsClient, branch string, git *Git) (wd string, cleanup func() error, err error) {
	wd, err = fileutils.CreateTempDir()
	if err != nil {
		return
	}
	cleanup = func() error {
		return fileutils.RemoveTempDir(wd)
	}
	log.Debug("Created temp working directory: ", wd)
	log.Debug(fmt.Sprintf("Downloading %s/%s , branch: %s to: %s", git.RepoOwner, git.RepoName, branch, wd))
	if err = client.DownloadRepository(context.Background(), git.RepoOwner, git.RepoName, branch, wd); err != nil {
		return
	}
	log.Debug("Repository download completed")
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

func GetCompatibleOutputWriter(provider vcsutils.VcsProvider) OutputWriter {
	if provider == vcsutils.BitbucketServer {
		return &SimplifiedOutput{}
	}
	return &StandardOutput{}
}

// The impact graph of direct dependencies consists of only two elements.
func IsDirectDependency(impactPath [][]formats.ComponentRow) (bool, error) {
	if len(impactPath) == 0 {
		return false, fmt.Errorf("invalid impact path provided")
	}
	return len(impactPath[0]) < 3, nil
}

// Accepts current impacted version and two of it's closest neighbours, upgrade and downgrade suggestions.
// Returns the fix suggestion version by the following priority rules:
// 1. Patch up
// 2. Minor up
// 3. Patch down
// 4. Minor down
// 5. Major Up
// 5. Major down
func GetFixVersionSuggestion(current, lower, upper string) string {
	// Patch up
	if patchVersion := isVersionUpgrade(current, upper, Patch); patchVersion != "" {
		return patchVersion
	}
	// Minor up
	if patchVersion := isVersionUpgrade(current, upper, Minor); patchVersion != "" {
		return patchVersion
	}
	// Patch Down
	if patchVersion := isVersionDowngrade(current, lower, Patch); patchVersion != "" {
		return patchVersion
	}
	// Minor down
	if patchVersion := isVersionDowngrade(current, lower, Minor); patchVersion != "" {
		return patchVersion
	}
	// Major Up
	if patchVersion := isVersionUpgrade(current, upper, Major); patchVersion != "" {
		return patchVersion
	}
	// Major down
	if patchVersion := isVersionDowngrade(current, lower, Major); patchVersion != "" {
		return patchVersion
	}
	return ""
}

// isVersionUpgrade returns the version string with the higher version number
// at a specified Major, Minor or Patch indexes.
func isVersionUpgrade(v1 string, v2 string, index int) string {
	v1Parts := strings.Split(v1, ".")
	v2Parts := strings.Split(v2, ".")
	for i := 0; i < 3; i++ {
		v1Part, _ := strconv.Atoi(v1Parts[i])
		v2Part, _ := strconv.Atoi(v2Parts[i])
		if v1Part == v2Part {
			continue
		}
		if i < index-1 {
			return ""
		}
		if v1Part < v2Part {
			return v2
		}
	}
	return ""
}

// isVersionDowngrade returns the version string with the lower version number
// at a specified Major, Minor or Patch indexes.
func isVersionDowngrade(v1 string, v2 string, index int) string {
	v1Parts := strings.Split(v1, ".")
	v2Parts := strings.Split(v2, ".")
	for i := 0; i < 3; i++ {
		v1Part, _ := strconv.Atoi(v1Parts[i])
		v2Part, _ := strconv.Atoi(v2Parts[i])
		if v1Part == v2Part {
			continue
		}
		if i < index-1 {
			continue
		}
		if v1Part > v2Part {
			return v2
		}
	}
	return ""
}
