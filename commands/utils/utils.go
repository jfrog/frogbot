package utils

import (
	"context"
	"crypto"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/froggit-go/vcsutils"
	"github.com/jfrog/gofrog/version"
	"github.com/jfrog/jfrog-cli-core/v2/artifactory/utils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-core/v2/xray/formats"
	xrayutils "github.com/jfrog/jfrog-cli-core/v2/xray/utils"
	"github.com/jfrog/jfrog-client-go/artifactory/usage"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray/services"
	"os"
	"regexp"
	"sort"
	"strings"
)

const (
	RootDir         = "."
	branchNameRegex = `[~^:?\\\[\]@{}*]`

	// Branch validation error messages
	branchInvalidChars    = "branch name cannot contain the following chars  ~, ^, :, ?, *, [, ], @, {, }"
	branchInvalidPrefix   = "branch name cannot start with '-' "
	branchCharsMaxLength  = 255
	branchInvalidLength   = "branch name length exceeded " + string(rune(branchCharsMaxLength)) + " chars"
	invalidBranchTemplate = "branch template must contain " + BranchHashPlaceHolder + " placeholder "
)

var (
	TrueVal                 = true
	FrogbotVersion          = "0.0.0"
	branchInvalidCharsRegex = regexp.MustCompile(branchNameRegex)
)

var BuildToolsDependenciesMap = map[coreutils.Technology][]string{
	coreutils.Go:  {"github.com/golang/go"},
	coreutils.Pip: {"pip", "setuptools", "wheel"},
}

type ErrMissingEnv struct {
	VariableName string
}

type ErrUnsupportedIndirectFix struct {
	PackageName string
}

func (e *ErrUnsupportedIndirectFix) Error() string {
	return fmt.Sprintf("Since dependecy '%s' is indirect (transitive) its fix is skipped", e.PackageName)
}

// FixVersionInfo is a basic struct used to hold needed information about version fixing
type FixVersionInfo struct {
	FixVersion       string
	PackageType      coreutils.Technology
	DirectDependency bool
}

func NewFixVersionInfo(newFixVersion string, packageType coreutils.Technology, directDependency bool) *FixVersionInfo {
	return &FixVersionInfo{newFixVersion, packageType, directDependency}
}

func (fvi *FixVersionInfo) UpdateFixVersionIfMax(newFixVersion string) {
	// Update fvi.FixVersion as the maximum version if found a new version that is greater than the previous maximum version.
	if fvi.FixVersion == "" || version.NewVersion(fvi.FixVersion).Compare(newFixVersion) > 0 {
		fvi.FixVersion = newFixVersion
	}
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

// Generates MD5Hash from a FixVersionMap object
// The map can be returned in different order from Xray, so we need to sort the strings before hashing.
func fixVersionsMapToMd5Hash(versionsMap map[string]*FixVersionInfo) (string, error) {
	h := crypto.MD5.New()
	// Sort the package names
	keys := make([]string, 0, len(versionsMap))
	for k, v := range versionsMap {
		keys = append(keys, k+v.FixVersion)
	}
	sort.Strings(keys)
	for key, value := range keys {
		if _, err := fmt.Fprint(h, key, value); err != nil {
			return "", err
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
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

func validateBranchName(branchName string) error {
	// Default is "" which will be replaced with default template
	if len(branchName) == 0 {
		return nil
	}
	branchNameWithoutPlaceHolders := formatStringWithPlaceHolders(branchName, "", "", "", true)
	if branchInvalidCharsRegex.MatchString(branchNameWithoutPlaceHolders) {
		return fmt.Errorf(branchInvalidChars)
	}
	// Prefix cannot be '-'
	if branchName[0] == '-' {
		return fmt.Errorf(branchInvalidPrefix)
	}
	if len(branchName) > branchCharsMaxLength {
		return fmt.Errorf(branchInvalidLength)
	}
	if !strings.Contains(branchName, BranchHashPlaceHolder) {
		return fmt.Errorf(invalidBranchTemplate)
	}
	return nil
}
