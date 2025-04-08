package utils

import (
	"encoding/json"
	"fmt"
	"github.com/jfrog/jfrog-client-go/xsc/services"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	goGitConfig "github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing/object"
	biutils "github.com/jfrog/build-info-go/utils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	xscutils "github.com/jfrog/jfrog-client-go/xsc/services/utils"

	"github.com/stretchr/testify/assert"
)

const (
	ValidConfigProfile          = "default-profile"
	InvalidPathConfigProfile    = "invalid-path-from-root-profile"
	InvalidModulesConfigProfile = "invalid-modules-profile"
	NonExistingProfile          = "non-existing-profile"
)

// Receive an environment variables key-values map, set and assert the environment variables.
// Return a callback that sets the previous values.
func SetEnvAndAssert(t *testing.T, env map[string]string) {
	for key, val := range env {
		setEnvAndAssert(t, key, val)
	}
}

// Make sure the environment variables does not contain any Frogbot variables
func AssertSanitizedEnv(t *testing.T) {
	for _, env := range os.Environ() {
		assert.False(t, strings.HasPrefix(env, "JF_"))
	}
}

func setEnvAndAssert(t *testing.T, key, value string) {
	assert.NoError(t, os.Setenv(key, value))
}

func unsetEnvAndAssert(t *testing.T, key string) {
	assert.NoError(t, os.Unsetenv(key))
}

// This function takes a map of environment variables and sets them, and returns a callback to UNSET them all
func SetEnvsAndAssertWithCallback(t *testing.T, envs map[string]string) func() {
	for key, val := range envs {
		setEnvAndAssert(t, key, val)
	}
	return func() {
		for key := range envs {
			unsetEnvAndAssert(t, key)
		}
	}
}

func MockHasConnection() *UrlAccessChecker {
	return &UrlAccessChecker{url: "url", connected: true}
}

// Create a temporary directory and copy the content of "testdata/testDir" into it
func CopyTestdataProjectsToTemp(t *testing.T, testDir string) (tmpDir string, restoreFunc func()) {
	// Copy project to a temporary directory
	tmpDir, err := fileutils.CreateTempDir()
	assert.NoError(t, err)
	err = biutils.CopyDir(filepath.Join("..", "testdata", testDir), tmpDir, true, []string{})
	assert.NoError(t, err)
	restoreFunc = func() {
		assert.NoError(t, fileutils.RemoveTempDir(tmpDir))
	}
	return
}

func ChangeToTempDirWithCallback(t *testing.T) (string, func() error) {
	tmpDir, err := fileutils.CreateTempDir()
	assert.NoError(t, err)
	callback, err := Chdir(tmpDir)
	assert.NoError(t, err)
	return tmpDir, callback
}

// Check connection details with JFrog instance.
// Return a callback method that restores the credentials after the test is done.
func VerifyEnv(t *testing.T) (server config.ServerDetails, restoreFunc func()) {
	url := strings.TrimSuffix(os.Getenv(JFrogUrlEnv), "/")
	username := os.Getenv(JFrogUserEnv)
	password := os.Getenv(JFrogPasswordEnv)
	token := os.Getenv(JFrogTokenEnv)
	if url == "" {
		assert.FailNow(t, fmt.Sprintf("'%s' is not set", JFrogUrlEnv))
	}
	if token == "" && (username == "" || password == "") {
		assert.FailNow(t, fmt.Sprintf("'%s' or '%s' and '%s' are not set", JFrogTokenEnv, JFrogUserEnv, JFrogPasswordEnv))
	}
	server.Url = url
	server.XrayUrl = url + "/xray/"
	server.ArtifactoryUrl = url + "/artifactory/"
	server.User = username
	server.Password = password
	server.AccessToken = token
	restoreFunc = func() {
		SetEnvAndAssert(t, map[string]string{
			JFrogUrlEnv:          url,
			JFrogTokenEnv:        token,
			JFrogUserEnv:         username,
			JFrogPasswordEnv:     password,
			GitAggregateFixesEnv: "FALSE",
		})
	}
	return
}

func CreateDotGitWithCommit(t *testing.T, wd, port string, repositoriesPath ...string) {
	for _, repositoryPath := range repositoriesPath {
		fullWdPath := filepath.Join(wd, repositoryPath)
		dotGit, err := git.PlainInit(fullWdPath, false)
		assert.NoError(t, err)
		_, err = dotGit.CreateRemote(&goGitConfig.RemoteConfig{
			Name: "origin",
			URLs: []string{fmt.Sprintf("http://127.0.0.1:%s/%s", port, repositoryPath)},
		})
		assert.NoError(t, err)
		worktree, err := dotGit.Worktree()
		assert.NoError(t, err)
		assert.NoError(t, worktree.AddWithOptions(&git.AddOptions{All: true}))
		_, err = worktree.Commit("first commit", &git.CommitOptions{
			Author: &object.Signature{
				Name:  "JFrog-Frogbot",
				Email: "eco-system+frogbot@jfrog.com",
				When:  time.Now(),
			},
		})
		assert.NoError(t, err)
	}
}

func CreateTempJfrogHomeWithCallback(t *testing.T) (string, func()) {
	newJfrogHomeDir, err := fileutils.CreateTempDir()
	assert.NoError(t, err)
	prevJfrogHomeDir := os.Getenv(JfrogHomeDirEnv)
	assert.NoError(t, os.Setenv(JfrogHomeDirEnv, newJfrogHomeDir))
	return newJfrogHomeDir, func() {
		assert.NoError(t, os.Setenv(JfrogHomeDirEnv, prevJfrogHomeDir))
		assert.NoError(t, fileutils.RemoveTempDir(newJfrogHomeDir))
	}
}

func CreateXscMockServerForConfigProfile(t *testing.T, xrayVersion string) (mockServer *httptest.Server, serverDetails *config.ServerDetails) {
	mockServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiUrlPart := "api/v1/"
		var isXrayAfterXscMigration bool
		if isXrayAfterXscMigration = xscutils.IsXscXrayInnerService(xrayVersion); isXrayAfterXscMigration {
			apiUrlPart = ""
		}

		secondModule := services.Module{
			ModuleId:        999,
			ModuleName:      "second-module",
			PathFromRoot:    ".",
			ExcludePatterns: nil,
			ScanConfig:      services.ScanConfig{},
			DepsRepo:        "",
		}

		switch {
		// Endpoints for Profile by name
		case strings.Contains(r.RequestURI, "/xsc/"+apiUrlPart+"profile/"): // xsc/api/v1/profile
			assert.Equal(t, http.MethodGet, r.Method)
			if strings.Contains(r.RequestURI, NonExistingProfile) {
				w.WriteHeader(http.StatusNotFound)
				return
			}

			content, err := os.ReadFile("../testdata/configprofile/configProfileExample.json")
			assert.NoError(t, err)

			if strings.Contains(r.RequestURI, "/profile/"+InvalidModulesConfigProfile) {
				// Adding a second module to make the profile invalid, as we currently support ONLY profile with a single module
				var profile services.ConfigProfile
				err = json.Unmarshal(content, &profile)
				assert.NoError(t, err)
				profile.Modules = append(profile.Modules, secondModule)
				content, err = json.Marshal(profile)
				assert.NoError(t, err)
			}

			if strings.Contains(r.RequestURI, "/profile/"+InvalidPathConfigProfile) {
				// Changing 'path_from_root' to a path different from '.' to make the module invalid, as we currently support ONLY a single module with '.' path
				updatedContent := string(content)
				updatedContent = strings.Replace(updatedContent, `"path_from_root": "."`, `"path_from_root": "backend"`, 1)
				content = []byte(updatedContent)
			}
			w.WriteHeader(http.StatusOK)
			_, err = w.Write(content)
			assert.NoError(t, err)

		// Endpoint to profile by URL
		case strings.Contains(r.RequestURI, "/xsc/profile_repos") && isXrayAfterXscMigration:
			assert.Equal(t, http.MethodPost, r.Method)
			content, err := os.ReadFile("../testdata/configprofile/configProfileExample.json")
			assert.NoError(t, err)
			w.WriteHeader(http.StatusOK)
			_, err = w.Write(content)
			assert.NoError(t, err)

		case r.RequestURI == fmt.Sprintf("/%s/%ssystem/version", apiUrlPart, "xsc"):
			_, err := w.Write([]byte(fmt.Sprintf(`{"xsc_version": "%s"}`, services.ConfigProfileMinXscVersion)))
			assert.NoError(t, err)
		default:
			assert.Fail(t, "received an unexpected request")
		}
	}))

	url := mockServer.URL
	serverDetails = &config.ServerDetails{
		Url:     url + "/",
		XrayUrl: url + "/xray/",
		XscUrl:  url + "/xsc/",
	}
	return
}
