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
	"github.com/jfrog/jfrog-cli-core/v2/common/commands"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	audit "github.com/jfrog/jfrog-cli-core/v2/xray/commands/audit/generic"
	"github.com/jfrog/jfrog-cli-core/v2/xray/formats"
	xrayutils "github.com/jfrog/jfrog-cli-core/v2/xray/utils"
	"github.com/jfrog/jfrog-client-go/artifactory/usage"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"os"
	"regexp"
	"sort"
	"strings"
)

const (
	RootDir         = "."
	branchNameRegex = `[~^:?\\\[\]@{}*]`

	// Branch validation error messages
	branchInvalidChars             = "branch name cannot contain the following chars  ~, ^, :, ?, *, [, ], @, {, }"
	branchInvalidPrefix            = "branch name cannot start with '-' "
	branchCharsMaxLength           = 255
	branchInvalidLength            = "branch name length exceeded " + string(rune(branchCharsMaxLength)) + " chars"
	invalidBranchTemplate          = "branch template must contain " + BranchHashPlaceHolder + " placeholder "
	skipIndirectVulnerabilitiesMsg = "\n%s is an indirect dependency that will not be updated to version %s.\nFixing indirect dependencies can potentially cause conflicts with other dependencies that depend on the previous version.\nFrogbot skips this to avoid potential incompatibilities and breaking changes."
	skipBuildToolDependencyMsg     = "Skipping vulnerable package %s since it is not defined in your package descriptor file. " +
		"Update %s version to %s to fix this vulnerability."
	JfrogHomeDirEnv = "JFROG_CLI_HOME_DIR"
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

type ErrUnsupportedFix struct {
	PackageName  string
	FixedVersion string
	ErrorType    UnsupportedErrorType
}

// Custom error for unsupported fixes
// Currently we hold two unsupported reasons, indirect and build tools dependencies.
func (err *ErrUnsupportedFix) Error() string {
	if err.ErrorType == IndirectDependencyFixNotSupported {
		return fmt.Sprintf(skipIndirectVulnerabilitiesMsg, err.PackageName, err.FixedVersion)
	}
	return fmt.Sprintf(skipBuildToolDependencyMsg, err.PackageName, err.PackageName, err.FixedVersion)
}

// VulnerabilityDetails serves as a container for essential information regarding a vulnerability that is going to be addressed and resolved
type VulnerabilityDetails struct {
	*formats.VulnerabilityOrViolationRow
	// Suggested fix version
	SuggestedFixedVersion string
	// States whether the dependency is direct or transitive
	IsDirectDependency bool
	// Cves as a list of string
	Cves []string
}

func NewVulnerabilityDetails(vulnerability *formats.VulnerabilityOrViolationRow, fixVersion string) *VulnerabilityDetails {
	vulnDetails := &VulnerabilityDetails{
		VulnerabilityOrViolationRow: vulnerability,
		SuggestedFixedVersion:       fixVersion,
	}
	vulnDetails.SetCves(vulnerability.Cves)
	return vulnDetails
}

func (vd *VulnerabilityDetails) SetIsDirectDependency(isDirectDependency bool) {
	vd.IsDirectDependency = isDirectDependency
}

func (vd *VulnerabilityDetails) SetCves(cves []formats.CveRow) {
	for _, cve := range cves {
		vd.Cves = append(vd.Cves, cve.Id)
	}
}

func (vd *VulnerabilityDetails) UpdateFixVersionIfMax(fixVersion string) {
	// Update vd.FixVersion as the maximum version if found a new version that is greater than the previous maximum version.
	if vd.SuggestedFixedVersion == "" || version.NewVersion(vd.SuggestedFixedVersion).Compare(fixVersion) > 0 {
		vd.SuggestedFixedVersion = fixVersion
	}
}

type ErrMissingEnv struct {
	VariableName string
}

func (e *ErrMissingEnv) Error() string {
	return fmt.Sprintf("'%s' environment variable is missing", e.VariableName)
}

// IsMissingEnvErr returns true if err is a type of ErrMissingEnv, otherwise false
func (e *ErrMissingEnv) IsMissingEnvErr(err error) bool {
	return errors.As(err, &e)
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
		return nil, fmt.Errorf("could not change dir to: %s\n%s", dir, err.Error())
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

// Generates MD5Hash from a vulnerabilityDetails
// The map can be returned in different order from Xray, so we need to sort the strings before hashing.
func VulnerabilityDetailsToMD5Hash(vulnerabilities ...*VulnerabilityDetails) (string, error) {
	hash := crypto.MD5.New()
	var keys []string
	for _, vuln := range vulnerabilities {
		keys = append(keys, GetUniqueID(*vuln.VulnerabilityOrViolationRow))
	}
	sort.Strings(keys)
	for key, value := range keys {
		if _, err := fmt.Fprint(hash, key, value); err != nil {
			return "", err
		}
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// UploadScanToGitProvider uploads scan results to the relevant git provider in order to view the scan in the Git provider code scanning UI
func UploadScanToGitProvider(scanResults *audit.Results, repo *Repository, branch string, client vcsclient.VcsClient) error {
	if repo.GitProvider.String() != vcsutils.GitHub.String() {
		log.Debug("Upload Scan to " + repo.GitProvider.String() + " is currently unsupported.")
		return nil
	}

	scan, err := xrayutils.GenerateSarifFileFromScan(scanResults.ExtendedScanResults, scanResults.IsMultipleRootProject, true, "JFrog Frogbot", "https://github.com/jfrog/frogbot")
	if err != nil {
		return err
	}
	_, err = client.UploadCodeScanning(context.Background(), repo.RepoOwner, repo.RepoName, branch, scan)
	if err != nil {
		return fmt.Errorf("upload code scanning for %s branch failed with: %s", branch, err.Error())
	}
	log.Info("The complete scanning results have been uploaded to your Code Scanning alerts view")
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

func ValidateSingleRepoConfiguration(configAggregator *RepoAggregator) error {
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

func BuildServerConfigFile(server *config.ServerDetails) (previousJFrogHomeDir, currentJFrogHomeDir string, err error) {
	// Create temp dir to store server config inside
	currentJFrogHomeDir, err = fileutils.CreateTempDir()
	if err != nil {
		return
	}
	// Save current JFrog Home dir
	previousJFrogHomeDir = os.Getenv(JfrogHomeDirEnv)
	// Set the temp dir as the JFrog Home dir
	if err = os.Setenv(JfrogHomeDirEnv, currentJFrogHomeDir); err != nil {
		return
	}
	cc := commands.NewConfigCommand(commands.AddOrEdit, "frogbot").SetDetails(server)
	err = cc.Run()
	return
}

func GetUniqueID(vulnerability formats.VulnerabilityOrViolationRow) string {
	return vulnerability.ImpactedDependencyName + vulnerability.ImpactedDependencyVersion + vulnerability.IssueId
}
