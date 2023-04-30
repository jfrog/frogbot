package utils

import (
	"bytes"
	"fmt"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
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

func TestFixVersionsMapToMd5Hash(t *testing.T) {
	tests := []struct {
		fixVersionMap map[string]*FixVersionInfo
		expectedHash  string
	}{
		{
			fixVersionMap: map[string]*FixVersionInfo{
				"pkg": {FixVersion: "1.2.3", PackageType: coreutils.Npm, DirectDependency: false}},
			expectedHash: "0aa066970b613b114f8e21d11c74ff94",
		}, {
			fixVersionMap: map[string]*FixVersionInfo{
				"pkg":  {FixVersion: "5.2.3", PackageType: coreutils.Go, DirectDependency: false},
				"pkg2": {FixVersion: "1.2.3", PackageType: coreutils.Go, DirectDependency: false}},
			expectedHash: "a0d4119dfe5fc5186d6c2cf1497f8c7c",
		},
		{
			// The Same map with different order should be the same hash.
			fixVersionMap: map[string]*FixVersionInfo{
				"pkg2": {FixVersion: "1.2.3", PackageType: coreutils.Go, DirectDependency: false},
				"pkg":  {FixVersion: "5.2.3", PackageType: coreutils.Go, DirectDependency: false}},
			expectedHash: "a0d4119dfe5fc5186d6c2cf1497f8c7c",
		}, {
			fixVersionMap: map[string]*FixVersionInfo{
				"myNuget": {FixVersion: "0.2.33", PackageType: coreutils.Nuget, DirectDependency: false}},
			expectedHash: "887ac2c931920c20956409702c0dfbc7",
		},
	}
	for _, test := range tests {
		t.Run(test.expectedHash, func(t *testing.T) {
			hash, err := fixVersionsMapToMd5Hash(test.fixVersionMap)
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

func TestValidatedBranchName(t *testing.T) {
	tests := []struct {
		branchName    string
		expectedError bool
		errorMessage  string
	}{
		{
			branchName:    "thi?s-is-my-test",
			expectedError: true,
			errorMessage:  branchInvalidChars,
		}, {
			branchName:    "thi^s-is-my-test",
			expectedError: true,
			errorMessage:  branchInvalidChars,
		}, {
			branchName:    "thi~s-is-my-test",
			expectedError: true,
			errorMessage:  branchInvalidChars,
		}, {
			branchName:    "this[]-is-my-test",
			expectedError: true,
			errorMessage:  branchInvalidChars,
		}, {
			branchName:    "this@-is-my-test",
			expectedError: true,
			errorMessage:  branchInvalidChars,
		}, {
			branchName:    "this is myt est ${BRANCH_NAME_HASH}",
			expectedError: false,
			errorMessage:  "",
		}, {
			branchName:    "(Feature)New branch ${BRANCH_NAME_HASH}",
			expectedError: false,
			errorMessage:  "",
		}, {
			branchName:    "(frogbot)(feature) ${BRANCH_NAME_HASH} my name",
			expectedError: false,
			errorMessage:  "",
		}, {
			branchName:    "-this_should_not_work_prefix",
			expectedError: true,
			errorMessage:  branchInvalidPrefix,
		}, {
			branchName:    "Lorem ipsum dolor sit amet, consectetuer adipiscing elit. Aenean commodo ligula eget dolor. Aenean massa. Cum sociis natoque penatibus et magnis dis parturient montes, nascetur ridiculus mus. Donec quam felis, ultricies nec, pellentesque eu, pretium quis, sem. Nulla consequat massa quis enim. Donec pede justo, fringilla vel, aliquet nec, vulputate eget, arcu. In enim justo, rhoncus ut, imperdiet a, venenatis vitae, justo. Nullam dictum felis eu pede mollis pretium. Integer tincidunt. Cras dapibus. Vivamus elementum semper nisi. Aenean vulputate eleifend tellus. Aenean leo ligula, porttitor eu, consequat vitae, eleifend ac, enim. Aliquam lorem ante, dapibus in, viverra quis, feugiat a, tellus. Phasellus viverra nulla ut metus varius laoreet. Quisque rutrum. Aenean imperdiet. Etiam ultricies nisi vel augue. Curabitur ullamcorper ultricies nisi. Nam eget dui. Etiam rhoncus. Maecenas tempus, tellus eget condimentum rhoncus, sem quam semper libero, sit amet adipiscing sem neque sed ipsum. Nam quam nunc, blandit vel, luctus pulvinar, hendrerit id, lorem. Maecenas nec odio et ante tincidunt tempus. Donec vitae sapien ut libero venenatis faucibus. Nullam quis ante. Etiam sit amet orci eget eros faucibus tincidunt. Duis leo. Sed fringilla mauris sit amet nibh. Donec sodales sagittis magna. Sed consequat, leo eget bibendum sodales, augue velit cursus nunc, quis gravida magna mi a libero. Fusce vulputate eleifend sapien. Vestibulum purus quam, scelerisque ut, mollis sed, nonummy id, metus. Nullam accumsan lorem in dui. Cras ultricies mi eu turpis hendrerit fringilla. Vestibulum ante ipsum primis in faucibus orci luctus et ultrices posuere cubilia Curae; In ac dui quis mi consectetuer lacinia. Nam pretium turpis et",
			expectedError: true,
			errorMessage:  branchInvalidLength,
		}, {
			branchName:    "",
			expectedError: false,
			errorMessage:  "",
		},
	}
	for _, test := range tests {
		t.Run(test.branchName, func(t *testing.T) {
			err := validateBranchName(test.branchName)
			if test.expectedError {
				assert.Error(t, err)
				assert.Equal(t, err.Error(), test.errorMessage)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
