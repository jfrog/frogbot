package utils

import (
	"fmt"
	"github.com/jfrog/build-info-go/build"
	"github.com/jfrog/jfrog-cli-core/v2/artifactory/utils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	gradleutils "github.com/jfrog/jfrog-cli-core/v2/utils/gradle"
	mvnutils "github.com/jfrog/jfrog-cli-core/v2/utils/mvn"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"path/filepath"
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

// DownloadExtractorsFromRemoteIfNeeded downloads build-info-extractors for air-gapped environments, if they're not exist on the remote repository yet.
func DownloadExtractorsFromRemoteIfNeeded(server *config.ServerDetails, remoteName string) error {
	log.Info("Downloading extractors if needed...")
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
	return downloadExtractors(remoteName, server, extractors...)
}

// TODO: check the already exists and error mechanism
func downloadExtractors(remoteName string, server *config.ServerDetails, extractors ...extractorDetails) (err error) {
	for _, extractor := range extractors {
		var alreadyExist bool
		if alreadyExist, err = fileutils.IsDirExists(extractor.localPath, false); alreadyExist {
			log.Debug(extractor.extractorType, "extractor already exists, no download necessary")
			continue
		}
		if err != nil {
			return err
		}
		if err = setRemoteAndDownloadExtractor(server, remoteName, extractor); err != nil {
			return err
		}
	}
	return
}

func setRemoteAndDownloadExtractor(server *config.ServerDetails, remoteName string, extractor extractorDetails) error {
	remoteURL := server.ArtifactoryUrl + remoteName + "/"
	remoteServer := &config.ServerDetails{
		ArtifactoryUrl: remoteURL,
		AccessToken:    server.AccessToken,
		User:           server.User,
		Password:       server.Password,
	}

	return utils.DownloadExtractor(remoteServer, extractor.DownloadFromPath(), extractor.DownloadToPath())
}
