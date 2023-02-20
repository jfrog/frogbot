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
	remoteRepo := "remote-repo"
	tmpDir, err := fileutils.CreateTempDir()
	assert.NoError(t, err)
	restoreDir, err := Chdir(tmpDir)
	assert.NoError(t, err)
	extractorsDir := os.Getenv("JFROG_CLI_DEPENDENCIES_DIR")
	// JFROG_CLI_DEPENDENCIES_DIR is set to avoid downloading empty extractor to the default extractor dir as this test does.
	assert.NoError(t, os.Setenv("JFROG_CLI_DEPENDENCIES_DIR", tmpDir))
	defer func() {
		assert.NoError(t, os.Setenv("JFROG_CLI_DEPENDENCIES_DIR", extractorsDir))
		assert.NoError(t, restoreDir())
	}()
	testServer := httptest.NewServer(createRemoteArtifactoryHandler())
	defer testServer.Close()
	serverDetails.ArtifactoryUrl = testServer.URL + "/artifactory/"
	assert.NoError(t, downloadExtractorsFromRemoteIfNeeded(serverDetails, remoteRepo, true))
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
