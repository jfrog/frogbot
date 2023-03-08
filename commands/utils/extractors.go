package utils

import (
	"fmt"
	"path/filepath"

	"github.com/jfrog/build-info-go/build"
	"github.com/jfrog/jfrog-cli-core/v2/artifactory/utils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
)

var extractorsRepositoryPath = filepath.Join("artifactory", "oss-release-local")

// extractorDetails holds the relevant details to download the build-info extractors.
// Build Info is Artifactory's open integration layer for the CI servers and build tools.
// The build information is sent to Artifactory in json format.
type extractorDetails struct {
	extractorType string
	localPath     string
	remotePath    string
	fileName      string
}

func (ed *extractorDetails) downloadToPath() string {
	return filepath.Join(ed.localPath, ed.fileName)
}

func (ed *extractorDetails) downloadFromPath() string {
	return filepath.Join(extractorsRepositoryPath, ed.remotePath, ed.fileName)
}

// downloadExtractorsFromRemoteIfNeeded downloads build-info-extractors from a remote repository, if they do not yet exist on the file system.
func downloadExtractorsFromRemoteIfNeeded(server *config.ServerDetails, extractorsLocalPath string) (err error) {
	var releasesRepo string
	if releasesRepo = getTrimmedEnv(jfrogReleasesRepo); releasesRepo == "" {
		return nil
	}
	// Download extractors if remote repo environment variable is set
	log.Info("Checking whether the build-info extractors exist locally")
	if extractorsLocalPath == "" {
		extractorsLocalPath, err = config.GetJfrogDependenciesPath()
		if err != nil {
			return err
		}
	}
	mavenExtractorLocalPath := filepath.Join(extractorsLocalPath, "maven", build.MavenExtractorDependencyVersion)
	gradleExtractorLocalPath := filepath.Join(extractorsLocalPath, "gradle", build.GradleExtractorDependencyVersion)
	extractors := []extractorDetails{
		{
			extractorType: coreutils.Maven.ToString(),
			localPath:     mavenExtractorLocalPath,
			fileName:      fmt.Sprintf(build.MavenExtractorFileName, build.MavenExtractorDependencyVersion),
			remotePath:    fmt.Sprintf(build.MavenExtractorRemotePath, build.MavenExtractorDependencyVersion),
		},
		{
			extractorType: coreutils.Gradle.ToString(),
			localPath:     gradleExtractorLocalPath,
			fileName:      fmt.Sprintf(build.GradleExtractorFileName, build.GradleExtractorDependencyVersion),
			remotePath:    fmt.Sprintf(build.GradleExtractorRemotePath, build.GradleExtractorDependencyVersion),
		},
	}
	return downloadExtractors(releasesRepo, server, extractors...)
}

func downloadExtractors(remoteRepoName string, server *config.ServerDetails, extractors ...extractorDetails) (err error) {
	for _, extractor := range extractors {
		var alreadyExist bool
		if alreadyExist, err = fileutils.IsDirExists(extractor.localPath, false); alreadyExist {
			log.Debug(extractor.extractorType, "extractor already exists, no download necessary")
			continue
		}
		if err != nil {
			return err
		}
		log.Info("Downloading", extractor.extractorType, "extractor to path:", extractor.localPath)
		remoteServer := getRemoteServer(server, remoteRepoName)
		if err = utils.DownloadExtractor(remoteServer, extractor.downloadFromPath(), extractor.downloadToPath()); err != nil {
			return err
		}
	}
	return
}

func getRemoteServer(server *config.ServerDetails, remoteName string) *config.ServerDetails {
	remoteURL := server.ArtifactoryUrl + remoteName + "/"
	return &config.ServerDetails{
		ArtifactoryUrl: remoteURL,
		AccessToken:    server.AccessToken,
		User:           server.User,
		Password:       server.Password,
	}
}
