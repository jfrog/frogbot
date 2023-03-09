package utils

import (
	"fmt"
	"github.com/jfrog/build-info-go/build"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestDownloadExtractorsFromRemoteIfNeeded(t *testing.T) {
	serverDetails := &config.ServerDetails{
		AccessToken: "eyJ0eXAiOiJKV1QifQ.eyJzdWIiOiJmYWtlXC91c2Vyc1wvdGVzdCJ9.MTIzNDU2Nzg5MA",
	}
	assert.NoError(t, os.Setenv(jfrogReleasesRepoEnv, "remote-repo"))
	defer assert.NoError(t, os.Unsetenv(jfrogReleasesRepoEnv))
	tmpDir, err := fileutils.CreateTempDir()
	assert.NoError(t, err)
	restoreDir, err := Chdir(tmpDir)
	assert.NoError(t, err)
	defer func() {
		assert.NoError(t, restoreDir())
		assert.NoError(t, fileutils.RemoveTempDir(tmpDir))
	}()
	testServer := httptest.NewServer(createRemoteArtifactoryHandler())
	defer testServer.Close()
	serverDetails.ArtifactoryUrl = testServer.URL + "/artifactory/"
	assert.NoError(t, downloadExtractorsFromRemoteIfNeeded(serverDetails, tmpDir))
}

// Create HTTP handler to mock remote artifactory server
func createRemoteArtifactoryHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		expectedMavenUri := fmt.Sprintf("/artifactory/remote-repo/artifactory/oss-release-local/%s/%s",
			fmt.Sprintf(build.MavenExtractorRemotePath, build.MavenExtractorDependencyVersion),
			fmt.Sprintf(build.MavenExtractorFileName, build.MavenExtractorDependencyVersion))
		expectedGradleUri := fmt.Sprintf("/artifactory/remote-repo/artifactory/oss-release-local/%s/%s",
			fmt.Sprintf(build.GradleExtractorRemotePath, build.GradleExtractorDependencyVersion),
			fmt.Sprintf(build.GradleExtractorFileName, build.GradleExtractorDependencyVersion))
		if r.RequestURI == expectedMavenUri || r.RequestURI == expectedGradleUri {
			w.WriteHeader(http.StatusOK)
			return
		}
	}
}
