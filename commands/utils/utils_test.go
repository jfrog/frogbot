package utils

import (
	"bytes"
	"fmt"
	"github.com/jfrog/jfrog-cli-core/v2/xray/formats"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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

func TestGetRelativeWd(t *testing.T) {
	fullPath := filepath.Join("a", "b", "c", "d", "e")
	baseWd := filepath.Join("a", "b", "c")
	assert.Equal(t, filepath.Join("d", "e"), GetRelativeWd(fullPath, baseWd))

	baseWd = filepath.Join("a", "b", "c", "d", "e")
	assert.Equal(t, "", GetRelativeWd(fullPath, baseWd))
	fullPath += string(os.PathSeparator)
	assert.Equal(t, "", GetRelativeWd(fullPath, baseWd))
}

func TestIsDirectDependency(t *testing.T) {
	tests := []struct {
		impactPath    [][]formats.ComponentRow
		expected      bool
		expectedError bool
	}{
		{
			impactPath:    [][]formats.ComponentRow{{{Name: "jfrog:pack1", Version: "1.2.3"}, {Name: "jfrog:pack2", Version: "1.2.3"}}},
			expected:      true,
			expectedError: false,
		}, {
			impactPath:    [][]formats.ComponentRow{{{Name: "jfrog:pack1", Version: "1.2.3"}, {Name: "jfrog:pack21", Version: "1.2.3"}, {Name: "jfrog:pack3", Version: "1.2.3"}}, {{Name: "jfrog:pack1", Version: "1.2.3"}, {Name: "jfrog:pack22", Version: "1.2.3"}, {Name: "jfrog:pack3", Version: "1.2.3"}}},
			expected:      false,
			expectedError: false,
		}, {
			impactPath:    [][]formats.ComponentRow{},
			expected:      false,
			expectedError: true,
		},
	}
	for _, test := range tests {
		t.Run("", func(t *testing.T) {
			isDirect, err := IsDirectDependency(test.impactPath)
			assert.Equal(t, test.expected, isDirect)
			if test.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestGitManager_GenerateCommitMessage(t *testing.T) {
	tests := []struct {
		gitManager      GitManager
		impactedPackage string
		fixVersion      FixVersionInfo
		expected        string
		description     string
	}{
		{
			gitManager:      GitManager{commitMessageFormat: "<type>"},
			impactedPackage: "mquery",
			fixVersion:      FixVersionInfo{FixVersion: "3.4.5"},
			expected:        "<type>: Upgrade mquery to 3.4.5",
			description:     "Custom prefix",
		},
		{
			gitManager:      GitManager{commitMessageFormat: "<type>[scope]"},
			impactedPackage: "mquery", fixVersion: FixVersionInfo{FixVersion: "3.4.5"},
			expected:    "<type>[scope]: Upgrade mquery to 3.4.5",
			description: "Default format",
		}, {
			gitManager:      GitManager{commitMessageFormat: ""},
			impactedPackage: "mquery", fixVersion: FixVersionInfo{FixVersion: "3.4.5"},
			expected:    "Upgrade mquery to 3.4.5",
			description: "Default format",
		},
	}
	for _, test := range tests {
		t.Run(test.expected, func(t *testing.T) {
			commitMessage := test.gitManager.GenerateCommitMessage(test.impactedPackage, test.fixVersion.FixVersion)
			assert.Equal(t, test.expected, commitMessage)
		})
	}
}

func TestGitManager_GenerateFixBranchName(t *testing.T) {
	tests := []struct {
		gitManager      GitManager
		impactedPackage string
		fixVersion      FixVersionInfo
		expected        string
		description     string
	}{
		{
			gitManager:      GitManager{branchNameFormat: "[MyPrefix]-%v"},
			impactedPackage: "mquery",
			fixVersion:      FixVersionInfo{FixVersion: "3.4.5"},
			expected:        "[MyPrefix]-mquery-41b1f45136b25e3624b15999bd57a476",
			description:     "Custom format",
		},
		{
			gitManager:      GitManager{branchNameFormat: ""},
			impactedPackage: "mquery",
			fixVersion:      FixVersionInfo{FixVersion: "3.4.5"},
			expected:        "frogbot-mquery-41b1f45136b25e3624b15999bd57a476",
			description:     "No format",
		},
	}
	for _, test := range tests {
		t.Run(test.expected, func(t *testing.T) {
			commitMessage, err := test.gitManager.GenerateFixBranchName("md5Branch", test.impactedPackage, test.fixVersion.FixVersion)
			assert.NoError(t, err)
			assert.Equal(t, test.expected, commitMessage)
		})
	}
}

func TestGitManager_GeneratePullRequestTitle(t *testing.T) {
	tests := []struct {
		gitManager      GitManager
		impactedPackage string
		fixVersion      FixVersionInfo
		expected        string
		description     string
	}{
		{
			gitManager:      GitManager{pullRequestTitleFormat: "[CustomPR] update $PACKAGE_NAME to $FIX_VERSION"},
			impactedPackage: "mquery",
			fixVersion:      FixVersionInfo{FixVersion: "3.4.5"},
			expected:        "[CustomPR] update mquery to 3.4.5",
			description:     "Custom format",
		},
		{
			gitManager:      GitManager{pullRequestTitleFormat: "[CustomPR] update $PACKAGE_NAME"},
			impactedPackage: "mquery",
			fixVersion:      FixVersionInfo{FixVersion: "3.4.5"},
			expected:        "[CustomPR] update mquery",
			description:     "Custom format one var",
		},
		{
			gitManager:      GitManager{branchNameFormat: ""},
			impactedPackage: "mquery",
			fixVersion:      FixVersionInfo{FixVersion: "3.4.5"},
			expected:        "[🐸 Frogbot] Upgrade mquery to 3.4.5",
			description:     "No prefix",
		},
	}
	for _, test := range tests {
		t.Run(test.expected, func(t *testing.T) {
			titleOutput := test.gitManager.GeneratePullRequestTitle(test.impactedPackage, test.fixVersion.FixVersion)
			assert.Equal(t, test.expected, titleOutput)
		})
	}

}

// Check connection details with JFrog instance.
// Return a callback method that restores the credentials after the test is done.
func verifyEnv(t *testing.T) (server config.ServerDetails, restoreFunc func()) {
	url := strings.TrimSuffix(os.Getenv(JFrogUrlEnv), "/")
	token := os.Getenv(JFrogTokenEnv)
	if url == "" {
		assert.FailNow(t, "JF_URL is not set")
	}
	if token == "" {
		assert.FailNow(t, "JF_ACCESS_TOKEN is not set")
	}
	server.Url = url
	server.XrayUrl = url + "/xray/"
	server.ArtifactoryUrl = url + "/artifactory/"
	server.AccessToken = token
	restoreFunc = func() {
		SetEnvAndAssert(t, map[string]string{
			JFrogUrlEnv:   url,
			JFrogTokenEnv: token,
		})
	}
	return
}
