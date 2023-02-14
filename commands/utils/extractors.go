package utils

import (
	"fmt"
	"path/filepath"

	"github.com/jfrog/build-info-go/build"
	"github.com/jfrog/jfrog-cli-core/v2/artifactory/utils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	gradleutils "github.com/jfrog/jfrog-cli-core/v2/utils/gradle"
	mvnutils "github.com/jfrog/jfrog-cli-core/v2/utils/mvn"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
)

var extractorsRepositoryPath = filepath.Join("artifactory", "oss-release-local")

type extractorDetails struct {
	extractorType string
	localPath     string
	remotePath    string
	fileName      string
}

func (ed *extractorDetails) DownloadToPath() string {
	return filepath.Join(ed.localPath, ed.fileName)
}

func (ed *extractorDetails) DownloadFromPath() string {
	return filepath.Join(extractorsRepositoryPath, ed.remotePath, ed.fileName)
}

// downloadExtractorsFromRemoteIfNeeded downloads build-info-extractors for air-gapped environments, if they're not exist on the remote repository yet.
func downloadExtractorsFromRemoteIfNeeded(server *config.ServerDetails, remoteRepoName string, forceDownload bool) error {
	log.Info("Downloading extractors if needed from", remoteRepoName)
	mavenExtractorLocalPath, err := mvnutils.GetMavenDependencyLocalPath()
	if err != nil {
		return err
	}
	gradleExtractorLocalPath, err := gradleutils.GetGradleDependencyLocalPath()
	if err != nil {
		return err
	}
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
	return downloadExtractors(remoteRepoName, server, forceDownload, extractors...)
}

func downloadExtractors(remoteRepoName string, server *config.ServerDetails, forceDownload bool, extractors ...extractorDetails) (err error) {
	for _, extractor := range extractors {
		if !forceDownload {
			var alreadyExist bool
			if alreadyExist, err = fileutils.IsDirExists(extractor.localPath, false); alreadyExist {
				log.Debug(extractor.extractorType, "extractor already exists, no download necessary")
				continue
			}
			if err != nil {
				return err
			}
		}
		remoteServer := getRemoteServer(server, remoteRepoName)
		if err = utils.DownloadExtractor(remoteServer, extractor.DownloadFromPath(), extractor.DownloadToPath()); err != nil {
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
