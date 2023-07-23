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

	gitTestParams := utils.Git{
		ClientInfo: utils.ClientInfo{
			GitProvider: vcsutils.GitHub,
			RepoOwner:   "jfrog",
			VcsInfo: vcsclient.VcsInfo{
				Token:       "123456",
				APIEndpoint: server.URL,
			},
		},
	}

	client, err := vcsclient.NewClientBuilder(vcsutils.GitHub).ApiEndpoint(server.URL).Token("123456").Build()
	assert.NoError(t, err)

	configData, err := utils.ReadConfigFromFileSystem(testScanAndFixReposConfigPath)
	assert.NoError(t, err)

	tmpDir, cleanUp := utils.PrepareTestEnvironment(t, "", cmdDirName)
	defer cleanUp()

	createReposGitEnvironment(t, tmpDir, port, testRepositories...)
	configAggregator, err := utils.BuildRepoAggregator(configData, &gitTestParams, &serverParams)
	assert.NoError(t, err)

	var cmd = ScanAndFixRepositories{dryRun: true}
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
				w.WriteHeader(http.StatusOK)
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
				w.WriteHeader(http.StatusOK)
				rawJson := "[\n  {\n    \"url\": \"https://api.github.com/repos/octocat/Hello-World/commits/6dcb09b5b57875f334f61aebed695e2e4193db5e\",\n    \"sha\": \"6dcb09b5b57875f334f61aebed695e2e4193db5e\",\n    \"node_id\": \"MDY6Q29tbWl0NmRjYjA5YjViNTc4NzVmMzM0ZjYxYWViZWQ2OTVlMmU0MTkzZGI1ZQ==\",\n    \"html_url\": \"https://github.com/octocat/Hello-World/commit/6dcb09b5b57875f334f61aebed695e2e4193db5e\",\n    \"comments_url\": \"https://api.github.com/repos/octocat/Hello-World/commits/6dcb09b5b57875f334f61aebed695e2e4193db5e/comments\",\n    \"commit\": {\n      \"url\": \"https://api.github.com/repos/octocat/Hello-World/git/commits/6dcb09b5b57875f334f61aebed695e2e4193db5e\",\n      \"author\": {\n        \"name\": \"Monalisa Octocat\",\n        \"email\": \"support@github.com\",\n        \"date\": \"2011-04-14T16:00:49Z\"\n      },\n      \"committer\": {\n        \"name\": \"Monalisa Octocat\",\n        \"email\": \"support@github.com\",\n        \"date\": \"2011-04-14T16:00:49Z\"\n      },\n      \"message\": \"Fix all the bugs\",\n      \"tree\": {\n        \"url\": \"https://api.github.com/repos/octocat/Hello-World/tree/6dcb09b5b57875f334f61aebed695e2e4193db5e\",\n        \"sha\": \"6dcb09b5b57875f334f61aebed695e2e4193db5e\"\n      },\n      \"comment_count\": 0,\n      \"verification\": {\n        \"verified\": false,\n        \"reason\": \"unsigned\",\n        \"signature\": null,\n        \"payload\": null\n      }\n    },\n    \"author\": {\n      \"login\": \"octocat\",\n      \"id\": 1,\n      \"node_id\": \"MDQ6VXNlcjE=\",\n      \"avatar_url\": \"https://github.com/images/error/octocat_happy.gif\",\n      \"gravatar_id\": \"\",\n      \"url\": \"https://api.github.com/users/octocat\",\n      \"html_url\": \"https://github.com/octocat\",\n      \"followers_url\": \"https://api.github.com/users/octocat/followers\",\n      \"following_url\": \"https://api.github.com/users/octocat/following{/other_user}\",\n      \"gists_url\": \"https://api.github.com/users/octocat/gists{/gist_id}\",\n      \"starred_url\": \"https://api.github.com/users/octocat/starred{/owner}{/repo}\",\n      \"subscriptions_url\": \"https://api.github.com/users/octocat/subscriptions\",\n      \"organizations_url\": \"https://api.github.com/users/octocat/orgs\",\n      \"repos_url\": \"https://api.github.com/users/octocat/repos\",\n      \"events_url\": \"https://api.github.com/users/octocat/events{/privacy}\",\n      \"received_events_url\": \"https://api.github.com/users/octocat/received_events\",\n      \"type\": \"User\",\n      \"site_admin\": false\n    },\n    \"committer\": {\n      \"login\": \"octocat\",\n      \"id\": 1,\n      \"node_id\": \"MDQ6VXNlcjE=\",\n      \"avatar_url\": \"https://github.com/images/error/octocat_happy.gif\",\n      \"gravatar_id\": \"\",\n      \"url\": \"https://api.github.com/users/octocat\",\n      \"html_url\": \"https://github.com/octocat\",\n      \"followers_url\": \"https://api.github.com/users/octocat/followers\",\n      \"following_url\": \"https://api.github.com/users/octocat/following{/other_user}\",\n      \"gists_url\": \"https://api.github.com/users/octocat/gists{/gist_id}\",\n      \"starred_url\": \"https://api.github.com/users/octocat/starred{/owner}{/repo}\",\n      \"subscriptions_url\": \"https://api.github.com/users/octocat/subscriptions\",\n      \"organizations_url\": \"https://api.github.com/users/octocat/orgs\",\n      \"repos_url\": \"https://api.github.com/users/octocat/repos\",\n      \"events_url\": \"https://api.github.com/users/octocat/events{/privacy}\",\n      \"received_events_url\": \"https://api.github.com/users/octocat/received_events\",\n      \"type\": \"User\",\n      \"site_admin\": false\n    },\n    \"parents\": [\n      {\n        \"url\": \"https://api.github.com/repos/octocat/Hello-World/commits/6dcb09b5b57875f334f61aebed695e2e4193db5e\",\n        \"sha\": \"6dcb09b5b57875f334f61aebed695e2e4193db5e\"\n      }\n    ]\n  }\n]"
				b := []byte(rawJson)
				_, err := w.Write(b)
				assert.NoError(t, err)
				return
			}
			if r.RequestURI == fmt.Sprintf("/repos/jfrog/%v/code-scanning/sarifs", projectName) {
				w.WriteHeader(http.StatusAccepted)
				rawJson := "{\n  \"id\": \"47177e22-5596-11eb-80a1-c1e54ef945c6\",\n  \"url\": \"https://api.github.com/repos/octocat/hello-world/code-scanning/sarifs/47177e22-5596-11eb-80a1-c1e54ef945c6\"\n}"
				b := []byte(rawJson)
				_, err := w.Write(b)
				assert.NoError(t, err)
				return
			}
		}
	}
}
