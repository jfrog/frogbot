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

	restoreDir, err := Chdir("..")
	assert.NoError(t, err)

	cwd, err := os.Getwd()
	assert.NoError(t, err)
	assert.Equal(t, filepath.Dir(originCwd), cwd)

	assert.NoError(t, restoreDir())
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

func TestMd5Hash(t *testing.T) {
	tests := []struct {
		values       []string
		expectedHash string
	}{
		{[]string{"frogbot", "dev", "gopkg.in/yaml.v3", "3.0.0"},
			"d61bde82dc594e5ccc5a042fe224bf7c"},

		{[]string{"frogbot", "master", "gopkg.in/yaml.v3", "3.0.0"},
			"41405528994061bd108e3bbd4c039a03"},

		{[]string{"frogbot", "master", "gopkg.in/yaml.v3", "4.0.0"},
			"54d9e69ea1cba0c009445ad94778c083"},

		{[]string{"frogbot", "master", "go", "1.17"},
			"cedc1e5462e504fc992318d24e343e48"},

		{[]string{"frogbot", "master", "go", "17.1"},
			"67c768266553d80deb21fe6e2e9ec652"},

		{[]string{"frogbot", "frogbot-Go-golang.org/x/crypto-0.0.0-20220314234659-1baeb1ce4c0b", "golang.org/x/crypto", "0.0.0-20220314234659-1baeb1ce4c0b"},
			"a7f1c0ffb51035f860521ce11ac38288"},

		{[]string{"frogbot"},
			"99990025ad24adf5d780bbed740a2868"},

		{[]string{""},
			"d41d8cd98f00b204e9800998ecf8427e"},
	}

	for _, test := range tests {
		t.Run(test.expectedHash, func(t *testing.T) {
			hash, err := Md5Hash(test.values...)
			assert.NoError(t, err)
			assert.Equal(t, test.expectedHash, hash)
		})
	}
}
