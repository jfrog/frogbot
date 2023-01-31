package utils

import (
	"fmt"
	"github.com/jfrog/build-info-go/build"
	"github.com/jfrog/jfrog-cli-core/v2/artifactory/utils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	gradleutils "github.com/jfrog/jfrog-cli-core/v2/utils/gradle"
	mvnutils "github.com/jfrog/jfrog-cli-core/v2/utils/mvn"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"os"
	"path/filepath"
)

var extractorsRepositoryPath = filepath.Join("artifactory", "oss-release-local")

type extractorDetails struct {
	localPath  string
	remotePath string
	fileName   string
}

func (ed *extractorDetails) DownloadToPath() string {
	return filepath.Join(ed.localPath, ed.fileName)
}

func (ed *extractorDetails) DownloadFromPath() string {
	return filepath.Join(extractorsRepositoryPath, ed.remotePath, ed.fileName)
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
	mavenExtractorDetails := &extractorDetails{
		localPath:  mavenDependencyDirPath,
		fileName:   fmt.Sprintf(build.MavenExtractorFileName, build.MavenExtractorDependencyVersion),
		remotePath: fmt.Sprintf(build.MavenExtractorRemotePath, build.MavenExtractorDependencyVersion),
	}
	return setRemoteAndDownloadExtractor(server, remoteName, mavenExtractorDetails)
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
	gradleExtractorDetails := &extractorDetails{
		localPath:  gradleDependencyDirPath,
		fileName:   fmt.Sprintf(build.GradleExtractorFileName, build.GradleExtractorDependencyVersion),
		remotePath: fmt.Sprintf(build.GradleExtractorRemotePath, build.GradleExtractorDependencyVersion),
	}

	return setRemoteAndDownloadExtractor(server, remoteName, gradleExtractorDetails)
}

func setRemoteAndDownloadExtractor(server config.ServerDetails, remoteName string, extractor *extractorDetails) error {
	remoteURL := server.ArtifactoryUrl + remoteName + string(os.PathSeparator)
	remoteServer := &config.ServerDetails{
		ArtifactoryUrl: remoteURL,
		AccessToken:    server.AccessToken,
		User:           server.User,
		Password:       server.Password,
	}

	return utils.DownloadExtractor(remoteServer, extractor.DownloadFromPath(), extractor.DownloadToPath())
}
