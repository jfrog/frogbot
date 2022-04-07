package utils

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/stretchr/testify/assert"
)

func TestChdir(t *testing.T) {
	originCwd, err := os.Getwd()
	assert.NoError(t, err)

	callback, err := Chdir("..")
	assert.NoError(t, err)

	cwd, err := os.Getwd()
	assert.NoError(t, err)
	assert.Equal(t, filepath.Dir(originCwd), cwd)

	callback()
	cwd, err = os.Getwd()
	assert.NoError(t, err)
	assert.Equal(t, originCwd, cwd)
}

func TestChdirErr(t *testing.T) {
	originCwd, err := os.Getwd()
	assert.NoError(t, err)

	_, err = Chdir("not-existed")
	assert.Error(t, err)

	cwd, err := os.Getwd()
	assert.NoError(t, err)
	assert.Equal(t, originCwd, cwd)
}

func TestReportUsage(t *testing.T) {
	const commandName = "test-command"
	server := httptest.NewServer(createUsageHandler(t, commandName))
	defer server.Close()

	serverDetails := &config.ServerDetails{ArtifactoryUrl: server.URL + "/"}
	channel := make(chan error)
	go ReportUsage(commandName, serverDetails, channel)
	assert.NoError(t, <-channel)
}

func TestReportUsageError(t *testing.T) {
	channel := make(chan error)
	go ReportUsage("", &config.ServerDetails{}, channel)
	assert.NoError(t, <-channel)

	channel = make(chan error)
	go ReportUsage("", &config.ServerDetails{ArtifactoryUrl: "http://httpbin.org/status/404"}, channel)
	assert.Error(t, <-channel)
}

// Create HTTP handler to mock an Artifactory server suitable for report usage requests
func createUsageHandler(t *testing.T, commandName string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.RequestURI == "/api/system/version" {
			w.WriteHeader(http.StatusOK)
			_, err := w.Write([]byte(`{"version":"6.9.0"}`))
			assert.NoError(t, err)
			return
		}
		if r.RequestURI == "/api/system/usage" {
			// Check request
			buf := new(bytes.Buffer)
			_, err := buf.ReadFrom(r.Body)
			assert.NoError(t, err)
			assert.Equal(t, fmt.Sprintf(`{"productId":"%s","features":[{"featureId":"%s"}]}`, productId, commandName), buf.String())

			// Send response OK
			w.WriteHeader(http.StatusOK)
			_, err = w.Write([]byte("{}"))
			assert.NoError(t, err)
		}
	}
}
