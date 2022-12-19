package commands

import (
	"bytes"
	"fmt"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/format/pktline"
	"github.com/go-git/go-git/v5/plumbing/protocol/packp"
	"github.com/jfrog/frogbot/commands/utils"
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/froggit-go/vcsutils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
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
var testRepositories = []string{"npm-repo"}

func TestScanAndFixRepos(t *testing.T) {
	serverParams, restoreEnv := verifyEnv(t)
	defer restoreEnv()

	var port string
	var baseWd string
	server := httptest.NewServer(createHttpHandler(t, &baseWd, &port, testRepositories...))
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
	baseWd = tmpDir

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

	var cmd ScanAndFixRepositories
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

func createHttpHandler(t *testing.T, baseWd, port *string, projectNames ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		for _, projectName := range projectNames {
			if r.RequestURI == fmt.Sprintf("/%s/info/refs?service=git-upload-pack", projectName) {
				dir, err := os.Getwd()
				assert.NoError(t, err)
				assert.NoError(t, fileutils.CopyDir(filepath.Join(*baseWd, fmt.Sprintf("%s", projectName)), dir, true, nil))
				w.WriteHeader(http.StatusOK)
				assert.NoError(t, err)
				in := []string{
					"# service=git-upload-pack\n",
					pktline.FlushString,
					"ec1251782e9ad1d337049501a2a7fe01000e4875 HEAD\x00\n",
					"ec1251782e9ad1d337049501a2a7fe01000e4875 refs/heads/master\n",
					pktline.FlushString,
				}
				var buf bytes.Buffer
				p := pktline.NewEncoder(&buf)
				err = p.EncodeString(in...)
				assert.NoError(t, err)
				_, err = w.Write(buf.Bytes())
				assert.NoError(t, err)

			}
			if r.RequestURI == fmt.Sprintf("/%s/git-upload-pack", projectName) {
				r := packp.NewUploadPackRequest()
				r.Wants = append(r.Wants, plumbing.NewHash("ec1251782e9ad1d337049501a2a7fe01000e4875"))
				buf := bytes.NewBuffer(nil)
				assert.NoError(t, r.UploadRequest.Encode(buf))
				_, err := w.Write(buf.Bytes())
				assert.NoError(t, err)
			}
			if r.RequestURI == fmt.Sprintf("/%s", projectName) {
				file, err := os.ReadFile("npm-repo.tar.gz")
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
