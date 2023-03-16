package commands

import (
	"bytes"
	"fmt"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
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
	"time"
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

	gitTestParams := &utils.Git{
		GitProvider:   vcsutils.GitHub,
		RepoOwner:     "jfrog",
		Token:         "123456",
		ApiEndpoint:   server.URL,
		PullRequestID: 1,
	}

	client, err := vcsclient.NewClientBuilder(vcsutils.GitHub).ApiEndpoint(server.URL).Token("123456").Build()
	assert.NoError(t, err)

	configData, err := utils.ReadConfigFromFileSystem(testScanAndFixReposConfigPath)
	assert.NoError(t, err)

	tmpDir, cleanUp := utils.PrepareTestEnvironment(t, "", cmdDirName)
	defer cleanUp()

	createReposGitEnvironment(t, tmpDir, port, testRepositories...)
	configAggregator, err := utils.NewConfigAggregatorFromFile(configData, gitTestParams, &serverParams)
	assert.NoError(t, err)

	var cmd = ScanAndFixRepositories{dryRun: true, dryRunRepoPath: filepath.Join("testdata", "scanandfixrepos")}
	assert.NoError(t, cmd.Run(configAggregator, client))
}

func createReposGitEnvironment(t *testing.T, wd, port string, repositories ...string) {
	for _, repository := range repositories {
		fullWdPath := filepath.Join(wd, repository)
		dotGit, err := git.PlainInit(fullWdPath, false)
		assert.NoError(t, err)
		_, err = dotGit.CreateRemote(&config.RemoteConfig{
			Name: "origin",
			URLs: []string{fmt.Sprintf("http://127.0.0.1:%s/%s", port, repository)},
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

func TestShouldScanBranchByStatus(t *testing.T) {
	commitStatusTestCases := []struct {
		statuses    []vcsclient.CommitStatus
		description string
		expected    bool
	}{
		{
			statuses: []vcsclient.CommitStatus{
				{
					State:       "success",
					Description: "description",
					DetailsUrl:  utils.FrogbotReadMeUrl,
					Creator:     "test",
				}, {
					State:       "pending",
					Description: "this is the latest commit",
					DetailsUrl:  utils.FrogbotReadMeUrl,
					Creator:     "test",
				},
			},
			description: "Latest status is not successful",
			expected:    true,
		},
		{
			statuses: []vcsclient.CommitStatus{
				{
					State:       "pending",
					Description: "description",
					DetailsUrl:  utils.FrogbotReadMeUrl,
					Creator:     "test",
				}, {
					State:       "success",
					Description: "this is the latest commit",
					DetailsUrl:  utils.FrogbotReadMeUrl,
					Creator:     "test",
				},
			},
			description: "Latest status is successful",
			expected:    false,
		},
		{
			statuses:    []vcsclient.CommitStatus{},
			description: "Empty statuses",
			expected:    true,
		},
		{
			statuses: []vcsclient.CommitStatus{
				{
					State:       "failed",
					Description: "description",
					DetailsUrl:  utils.FrogbotReadMeUrl,
					Creator:     "test",
				}, {
					State:       "pending",
					Description: "this is the latest commit",
					DetailsUrl:  utils.FrogbotReadMeUrl,
					Creator:     "test",
				},
			},
			description: "FrogBot failed statues should scan",
			expected:    true,
		},
		{
			statuses: []vcsclient.CommitStatus{
				{
					State:       "failed",
					Description: "description",
					DetailsUrl:  "some other url",
					Creator:     "test",
				}, {
					State:       "pending",
					Description: "this is the latest commit",
					DetailsUrl:  "some other url",
					Creator:     "test",
				},
				{
					State:       "success",
					Description: "this is the latest commit",
					DetailsUrl:  "some other url",
					Creator:     "test",
				},
			},
			description: "Non FrogBot statues",
			expected:    true,
		},
	}
	for _, tt := range commitStatusTestCases {
		t.Run(tt.description, func(t *testing.T) {
			shouldScan := shouldScanBranchByStatus(tt.statuses)
			assert.Equal(t, tt.expected, shouldScan)
		})
	}
}
