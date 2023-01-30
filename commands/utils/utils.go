package utils

import (
	"context"
	"crypto"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/jfrog/build-info-go/build"
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/froggit-go/vcsutils"
	"github.com/jfrog/jfrog-cli-core/v2/artifactory/utils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	gradleutils "github.com/jfrog/jfrog-cli-core/v2/utils/gradle"
	mvnutils "github.com/jfrog/jfrog-cli-core/v2/utils/mvn"
	xrayutils "github.com/jfrog/jfrog-cli-core/v2/xray/utils"
	"github.com/jfrog/jfrog-client-go/artifactory/usage"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray/services"
	"os"
	"path/filepath"
	"strings"
)

const RootDir = "."

var extractorsRepositoryPath = filepath.Join("artifactory", "oss-release-local")

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

	includeVulnerabilities := repo.JFrogProjectKey == "" && len(repo.Watches) == 0
	scan, err := xrayutils.GenerateSarifFileFromScan(scanResults, includeVulnerabilities, isMultipleRoots, true)
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

func isSimplifiedOutput(provider vcsutils.VcsProvider) bool {
	return provider == vcsutils.BitbucketServer
}

// downloadExtractorsFromRemote downloads build-info-extractors for air-gapped environments
func downloadExtractorsFromRemote(server config.ServerDetails, remoteName string) error {
	log.Info("Downloading extractors if needed...")
	if err := downloadMavenExtractor(server, remoteName); err != nil {
		return err
	}
	return downloadGradleExtractor(server, remoteName)
}

func downloadMavenExtractor(server config.ServerDetails, remoteName string) error {
	mavenDependencyDirPath, err := mvnutils.GetMavenDependencyLocalPath()
	if err != nil {
		return err
	}
	alreadyExist, err := fileutils.IsDirExists(mavenDependencyDirPath, false)
	if err != nil || alreadyExist {
		return err
	}
	fileName := fmt.Sprintf(build.MavenExtractorRemotePath, build.MavenExtractorDependencyVersion)
	filePath := fmt.Sprintf(build.MavenExtractorFileName, build.MavenExtractorDependencyVersion)
	downloadTo := filepath.Join(mavenDependencyDirPath, fileName)
	downloadFrom := filepath.Join(extractorsRepositoryPath, fileName, filePath)
	return setRemoteAndDownloadExtractor(server, remoteName, downloadFrom, downloadTo)
}

func downloadGradleExtractor(server config.ServerDetails, remoteName string) error {
	gradleDependencyDirPath, err := gradleutils.GetGradleDependencyLocalPath()
	if err != nil {
		return err
	}
	alreadyExist, err := fileutils.IsDirExists(gradleDependencyDirPath, false)
	if err != nil || alreadyExist {
		return err
	}
	fileName := fmt.Sprintf(build.GradleExtractorFileName, build.GradleExtractorDependencyVersion)
	filePath := fmt.Sprintf(build.GradleExtractorRemotePath, build.GradleExtractorDependencyVersion)
	downloadTo := filepath.Join(gradleDependencyDirPath, fileName)
	downloadFrom := filepath.Join(extractorsRepositoryPath, filePath, fileName)
	return setRemoteAndDownloadExtractor(server, remoteName, downloadFrom, downloadTo)
}

func setRemoteAndDownloadExtractor(server config.ServerDetails, remoteName, downloadFrom, downloadTo string) error {
	remoteURL := server.ArtifactoryUrl + remoteName + string(os.PathSeparator)
	remoteServer := &config.ServerDetails{
		ArtifactoryUrl: remoteURL,
		AccessToken:    server.AccessToken,
		User:           server.User,
		Password:       server.Password,
	}

	return utils.DownloadExtractor(remoteServer, downloadFrom, downloadTo)
}
