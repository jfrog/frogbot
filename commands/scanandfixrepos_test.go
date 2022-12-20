package commands

import (
	"bytes"
	"fmt"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/protocol/packp"
	"github.com/go-git/go-git/v5/plumbing/protocol/packp/capability"
	"github.com/jfrog/frogbot/commands/utils"
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/froggit-go/vcsutils"
	"github.com/mholt/archiver/v3"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const cmdDirName = "scanandfixrepos"

var testScanAndFixReposConfigPath = filepath.Join("testdata", "config", "frogbot-config-scan-and-fix-repos.yml")
var testRepositories = []string{"pip-repo", "npm-repo", "mvn-repo"}

func TestScanAndFixRepos(t *testing.T) {
	serverParams, restoreEnv := verifyEnv(t)
	defer restoreEnv()

	var port string
	server := httptest.NewServer(createHttpHandler(t, &port, testRepositories...))
	defer server.Close()
	port = server.URL[strings.LastIndex(server.URL, ":")+1:]

	gitParams := utils.Git{
		GitProvider:   vcsutils.GitHub,
		RepoOwner:     "jfrog",
		Token:         "123456",
		ApiEndpoint:   server.URL,
		PullRequestID: 1,
	}

	client, err := vcsclient.NewClientBuilder(vcsutils.GitHub).ApiEndpoint(server.URL).Token("123456").Build()
	assert.NoError(t, err)

	configData, err := utils.ReadConfig(testScanAndFixReposConfigPath)
	assert.NoError(t, err)

	tmpDir, cleanUp := utils.PrepareTestEnvironment(t, "", cmdDirName)
	defer cleanUp()

	createReposGitEnvironment(t, tmpDir, port, testRepositories...)

	failOnSecurityIssue := false
	var configAggregator utils.FrogbotConfigAggregator
	for _, conf := range *configData {
		gitParams.RepoName = conf.RepoName
		gitParams.Branches = conf.Branches
		conf.FailOnSecurityIssues = &failOnSecurityIssue
		conf.Git = gitParams
		params := utils.Params{
			Scan:          conf.Scan,
			Git:           conf.Git,
			JFrogPlatform: conf.JFrogPlatform,
		}
		configAggregator = append(configAggregator, utils.FrogbotRepoConfig{
			Server:           serverParams,
			SimplifiedOutput: conf.SimplifiedOutput,
			Params:           params,
		})
	}

	var cmd = ScanAndFixRepositories{dryRun: true, repoPath: filepath.Join("testdata", "scanandfixrepos")}
	assert.NoError(t, cmd.Run(configAggregator, client))
}

func createReposGitEnvironment(t *testing.T, wd, port string, repositories ...string) {
	for _, repository := range repositories {
		fullWdPath := filepath.Join(wd, repository)
		dotGitDetails, err := git.PlainOpen(fullWdPath)
		assert.NoError(t, err)
		_, err = dotGitDetails.CreateRemote(&config.RemoteConfig{
			Name: "origin",
			URLs: []string{fmt.Sprintf("http://127.0.0.1:%s/%s", port, repository)},
		})
		assert.NoError(t, err)
		assert.NoError(t, archiver.Archive([]string{fullWdPath}, repository+".tar.gz"))
	}
}

func createHttpHandler(t *testing.T, port *string, projectNames ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		for _, projectName := range projectNames {
			if r.RequestURI == fmt.Sprintf("/%s/info/refs?service=git-upload-pack", projectName) {
				hash := plumbing.NewHash("5e3021cf22da163f0d312d8fcf299abaa79726fb")
				capabilities := capability.NewList()
				assert.NoError(t, capabilities.Add(capability.SymRef, "HEAD:/refs/heads/master"))
				ar := &packp.AdvRefs{
					References: map[string]plumbing.Hash{
						"refs/heads/master": plumbing.NewHash("5e3021cf22da163f0d312d8fcf299abaa79726fb"),
					},
					Head:         &hash,
					Capabilities: capabilities,
				}
				var buf bytes.Buffer
				assert.NoError(t, ar.Encode(&buf))
				_, err := w.Write(buf.Bytes())
				assert.NoError(t, err)
				w.WriteHeader(http.StatusOK)
				return
			}
			if r.RequestURI == fmt.Sprintf("/repos/jfrog/%s/pulls", projectName) {
				w.WriteHeader(200)
				return
			}
			if r.RequestURI == fmt.Sprintf("/%s", projectName) {
				file, err := os.ReadFile(fmt.Sprintf("%s.tar.gz", projectName))
				assert.NoError(t, err)
				_, err = w.Write(file)
				assert.NoError(t, err)
				return
			}
			if r.RequestURI == fmt.Sprintf("/repos/jfrog/%s/tarball/master", projectName) {
				w.Header().Add("Location", fmt.Sprintf("http://127.0.0.1:%s/%s", *port, projectName))
				w.WriteHeader(http.StatusFound)
				_, err := w.Write([]byte{})
				assert.NoError(t, err)
				return
			}
			if r.RequestURI == fmt.Sprintf("/repos/jfrog/%s/commits?page=1&per_page=1&sha=master", projectName) {
				w.WriteHeader(http.StatusNotFound)
				return
			}
		}
	}
}
