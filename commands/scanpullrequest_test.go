package commands

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/jfrog/frogbot/commands/testdata"
	"github.com/jfrog/frogbot/commands/utils"
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/jfrog-cli-core/v2/xray/formats"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/xray/services"
	"github.com/stretchr/testify/assert"
	clitool "github.com/urfave/cli/v2"
)

//go:generate go run github.com/golang/mock/mockgen@v1.6.0 -destination=testdata/vcsclientmock.go -package=testdata github.com/jfrog/froggit-go/vcsclient VcsClient

func TestCreateXrayScanParams(t *testing.T) {
	// Project
	params := createXrayScanParams("", "")
	assert.Empty(t, params.Watches)
	assert.Equal(t, "", params.ProjectKey)
	assert.True(t, params.IncludeVulnerabilities)
	assert.False(t, params.IncludeLicenses)

	// Watches
	params = createXrayScanParams("watch-1,watch-2", "")
	assert.Equal(t, []string{"watch-1", "watch-2"}, params.Watches)
	assert.Equal(t, "", params.ProjectKey)
	assert.False(t, params.IncludeVulnerabilities)
	assert.False(t, params.IncludeLicenses)

	// Project
	params = createXrayScanParams("", "project")
	assert.Empty(t, params.Watches)
	assert.Equal(t, "project", params.ProjectKey)
	assert.False(t, params.IncludeVulnerabilities)
	assert.False(t, params.IncludeLicenses)
}

func TestCreateVulnerabilitiesRows(t *testing.T) {
	// Previous scan with only one violation - XRAY-1
	previousScan := services.ScanResponse{
		Violations: []services.Violation{{
			IssueId:       "XRAY-1",
			Summary:       "summary-1",
			Severity:      "high",
			ViolationType: "security",
			Components:    map[string]services.Component{"component-A": {}, "component-B": {}},
		}},
	}

	// Current scan with 2 violations - XRAY-1 and XRAY-2
	currentScan := services.ScanResponse{
		Violations: []services.Violation{
			{
				IssueId:       "XRAY-1",
				Summary:       "summary-1",
				Severity:      "high",
				ViolationType: "security",
				Components:    map[string]services.Component{"component-A": {}, "component-B": {}},
			},
			{
				IssueId:       "XRAY-2",
				Summary:       "summary-2",
				ViolationType: "security",
				Severity:      "low",
				Components:    map[string]services.Component{"component-C": {}, "component-D": {}},
			},
		},
	}

	// Run createVulnerabilitiesRows and make sure that only the XRAY-2 violation exists in the results
	rows := createVulnerabilitiesRows([]services.ScanResponse{previousScan}, []services.ScanResponse{currentScan})
	assert.Len(t, rows, 2)
	assert.Equal(t, "XRAY-2", rows[0].IssueId)
	assert.Equal(t, "low", rows[0].Severity)
	assert.Equal(t, "XRAY-2", rows[1].IssueId)
	assert.Equal(t, "low", rows[1].Severity)

	impactedPackageOne := rows[0].ImpactedPackageName
	impactedPackageTwo := rows[1].ImpactedPackageName
	assert.ElementsMatch(t, []string{"component-C", "component-D"}, []string{impactedPackageOne, impactedPackageTwo})
}

func TestCreateVulnerabilitiesRowsCaseNoPrevViolations(t *testing.T) {
	// Previous scan with no violation
	previousScan := services.ScanResponse{
		Violations: []services.Violation{},
	}

	// Current scan with 2 violations - XRAY-1 and XRAY-2
	currentScan := services.ScanResponse{
		Violations: []services.Violation{
			{
				IssueId:       "XRAY-1",
				Summary:       "summary-1",
				Severity:      "high",
				ViolationType: "security",
				Components:    map[string]services.Component{"component-A": {}},
			},
			{
				IssueId:       "XRAY-2",
				Summary:       "summary-2",
				ViolationType: "security",
				Severity:      "low",
				Components:    map[string]services.Component{"component-C": {}},
			},
		},
	}

	// Run createVulnerabilitiesRows and expect both XRAY-1 and XRAY-2 violation in the results
	rows := createVulnerabilitiesRows([]services.ScanResponse{previousScan}, []services.ScanResponse{currentScan})
	assert.Len(t, rows, 2)
	assert.Equal(t, "XRAY-1", rows[0].IssueId)
	assert.Equal(t, "high", rows[0].Severity)
	assert.Equal(t, "component-A", rows[0].ImpactedPackageName)
	assert.Equal(t, "XRAY-2", rows[1].IssueId)
	assert.Equal(t, "low", rows[1].Severity)
	assert.Equal(t, "component-C", rows[1].ImpactedPackageName)
}

func TestGetNewViolationsCaseNoNewViolations(t *testing.T) {
	// Previous scan with 2 violations - XRAY-1 and XRAY-2
	previousScan := services.ScanResponse{
		Violations: []services.Violation{
			{
				IssueId:       "XRAY-1",
				Summary:       "summary-1",
				Severity:      "high",
				ViolationType: "security",
				Components:    map[string]services.Component{"component-A": {}},
			},
			{
				IssueId:       "XRAY-2",
				Summary:       "summary-2",
				ViolationType: "security",
				Severity:      "low",
				Components:    map[string]services.Component{"component-C": {}},
			},
		},
	}

	// Current scan with no violation
	currentScan := services.ScanResponse{
		Violations: []services.Violation{},
	}

	// Run createVulnerabilitiesRows and expect no violations in the results
	rows := createVulnerabilitiesRows([]services.ScanResponse{previousScan}, []services.ScanResponse{currentScan})
	assert.Len(t, rows, 0)
}

func TestGetNewVulnerabilities(t *testing.T) {
	// Previous scan with only one vulnerability - XRAY-1
	previousScan := services.ScanResponse{
		Vulnerabilities: []services.Vulnerability{{
			IssueId:    "XRAY-1",
			Summary:    "summary-1",
			Severity:   "high",
			Components: map[string]services.Component{"component-A": {}, "component-B": {}},
		}},
	}

	// Current scan with 2 vulnerabilities - XRAY-1 and XRAY-2
	currentScan := services.ScanResponse{
		Vulnerabilities: []services.Vulnerability{
			{
				IssueId:    "XRAY-1",
				Summary:    "summary-1",
				Severity:   "high",
				Components: map[string]services.Component{"component-A": {}, "component-B": {}},
			},
			{
				IssueId:    "XRAY-2",
				Summary:    "summary-2",
				Severity:   "low",
				Components: map[string]services.Component{"component-C": {}, "component-D": {}},
			},
		},
	}

	// Run createVulnerabilitiesRows and make sure that only the XRAY-2 vulnerability exists in the results
	rows := createVulnerabilitiesRows([]services.ScanResponse{previousScan}, []services.ScanResponse{currentScan})
	assert.Len(t, rows, 2)
	assert.Equal(t, "XRAY-2", rows[0].IssueId)
	assert.Equal(t, "low", rows[0].Severity)
	assert.Equal(t, "XRAY-2", rows[1].IssueId)
	assert.Equal(t, "low", rows[1].Severity)

	impactedPackageOne := rows[0].ImpactedPackageName
	impactedPackageTwo := rows[1].ImpactedPackageName
	assert.ElementsMatch(t, []string{"component-C", "component-D"}, []string{impactedPackageOne, impactedPackageTwo})
}

func TestGetNewVulnerabilitiesCaseNoPrevVulnerabilities(t *testing.T) {
	// Previous scan with no vulnerabilities
	previousScan := services.ScanResponse{
		Vulnerabilities: []services.Vulnerability{},
	}

	// Current scan with 2 vulnerabilities - XRAY-1 and XRAY-2
	currentScan := services.ScanResponse{
		Vulnerabilities: []services.Vulnerability{
			{
				IssueId:    "XRAY-1",
				Summary:    "summary-1",
				Severity:   "high",
				Components: map[string]services.Component{"component-A": {}},
			},
			{
				IssueId:    "XRAY-2",
				Summary:    "summary-2",
				Severity:   "low",
				Components: map[string]services.Component{"component-B": {}},
			},
		},
	}

	// Run createVulnerabilitiesRows and expect both XRAY-1 and XRAY-2 vulnerability in the results
	rows := createVulnerabilitiesRows([]services.ScanResponse{previousScan}, []services.ScanResponse{currentScan})
	assert.Len(t, rows, 2)
	assert.Equal(t, "XRAY-1", rows[0].IssueId)
	assert.Equal(t, "high", rows[0].Severity)
	assert.Equal(t, "component-A", rows[0].ImpactedPackageName)
	assert.Equal(t, "XRAY-2", rows[1].IssueId)
	assert.Equal(t, "low", rows[1].Severity)
	assert.Equal(t, "component-B", rows[1].ImpactedPackageName)
}

func TestGetNewVulnerabilitiesCaseNoNewVulnerabilities(t *testing.T) {
	// Previous scan with 2 vulnerabilities - XRAY-1 and XRAY-2
	previousScan := services.ScanResponse{
		Vulnerabilities: []services.Vulnerability{
			{
				IssueId:    "XRAY-1",
				Summary:    "summary-1",
				Severity:   "high",
				Components: map[string]services.Component{"component-A": {}},
			},
			{
				IssueId:    "XRAY-2",
				Summary:    "summary-2",
				Severity:   "low",
				Components: map[string]services.Component{"component-B": {}},
			},
		},
	}

	// Current scan with no vulnerabilities
	currentScan := services.ScanResponse{
		Vulnerabilities: []services.Vulnerability{},
	}

	// Run createVulnerabilitiesRows and expect no vulnerability in the results
	rows := createVulnerabilitiesRows([]services.ScanResponse{previousScan}, []services.ScanResponse{currentScan})
	assert.Len(t, rows, 0)
}

var params = &utils.FrogbotParams{
	GitParam: utils.GitParam{
		RepoOwner:     "repo-owner",
		Repo:          "repo-name",
		PullRequestID: 5,
		BaseBranch:    "master",
	},
}

func TestHandleFrogbotLabel(t *testing.T) {
	// Init mock
	client, finish := mockVcsClient(t)
	defer finish()

	// Label is expected to exist in pull request
	client.EXPECT().GetLabel(context.Background(), params.RepoOwner, params.Repo, string(utils.LabelName)).Return(&vcsclient.LabelInfo{
		Name:        string(utils.LabelName),
		Description: string(utils.LabelDescription),
		Color:       string(utils.LabelDescription),
	}, nil)
	client.EXPECT().ListPullRequestLabels(context.Background(), params.RepoOwner, params.Repo, params.PullRequestID).Return([]string{"label-1", string(utils.LabelName)}, nil)
	client.EXPECT().UnlabelPullRequest(context.Background(), params.RepoOwner, params.Repo, string(utils.LabelName), 5).Return(nil)

	// Run handleFrogbotLabel
	shouldScan, err := handleFrogbotLabel(params, client)
	assert.NoError(t, err)
	assert.True(t, shouldScan)
}

func TestHandleFrogbotLabelGetLabelErr(t *testing.T) {
	// Init mock
	client, finish := mockVcsClient(t)
	defer finish()

	// Get label is expected to return an error
	expectedError := errors.New("Couldn't get label")
	client.EXPECT().GetLabel(context.Background(), params.RepoOwner, params.Repo, string(utils.LabelName)).Return(&vcsclient.LabelInfo{}, expectedError)

	// Run handleFrogbotLabel
	shouldScan, err := handleFrogbotLabel(params, client)
	assert.ErrorIs(t, err, expectedError)
	assert.False(t, shouldScan)
}

func TestHandleFrogbotLabelLabelNotExist(t *testing.T) {
	// Init mock
	client, finish := mockVcsClient(t)
	defer finish()

	// Label is expected to not exists
	client.EXPECT().GetLabel(context.Background(), params.RepoOwner, params.Repo, string(utils.LabelName)).Return(nil, nil)
	client.EXPECT().CreateLabel(context.Background(), params.RepoOwner, params.Repo, vcsclient.LabelInfo{
		Name:        string(utils.LabelName),
		Description: string(utils.LabelDescription),
		Color:       string(utils.LabelColor),
	}).Return(nil)

	// Run handleFrogbotLabel
	shouldScan, err := handleFrogbotLabel(params, client)
	assert.False(t, shouldScan)
	assert.EqualError(t, err, fmt.Sprintf("please add the '%s' label to trigger an Xray scan", string(utils.LabelName)))
}

func TestHandleFrogbotLabelCreateLabelErr(t *testing.T) {
	// Init mock
	client, finish := mockVcsClient(t)
	defer finish()

	// Create label is expected to return error
	expectedError := errors.New("Couldn't create label")
	client.EXPECT().GetLabel(context.Background(), params.RepoOwner, params.Repo, string(utils.LabelName)).Return(nil, nil)
	client.EXPECT().CreateLabel(context.Background(), params.RepoOwner, params.Repo, vcsclient.LabelInfo{
		Name:        string(utils.LabelName),
		Description: string(utils.LabelDescription),
		Color:       string(utils.LabelColor),
	}).Return(expectedError)

	// Run handleFrogbotLabel
	shouldScan, err := handleFrogbotLabel(params, client)
	assert.ErrorIs(t, err, expectedError)
	assert.False(t, shouldScan)
}

func TestHandleFrogbotLabelUnlabeled(t *testing.T) {
	// Init mock
	client, finish := mockVcsClient(t)
	defer finish()

	// Pull request is expected to be unlabeled
	client.EXPECT().GetLabel(context.Background(), params.RepoOwner, params.Repo, string(utils.LabelName)).Return(&vcsclient.LabelInfo{
		Name:        string(utils.LabelName),
		Description: string(utils.LabelDescription),
		Color:       string(utils.LabelDescription),
	}, nil)
	client.EXPECT().ListPullRequestLabels(context.Background(), params.RepoOwner, params.Repo, params.PullRequestID).Return([]string{"label-1"}, nil)

	// Run handleFrogbotLabel
	shouldScan, err := handleFrogbotLabel(params, client)
	assert.False(t, shouldScan)
	assert.EqualError(t, err, fmt.Sprintf("please add the '%s' label to trigger an Xray scan", string(utils.LabelName)))
}

func TestHandleFrogbotLabelCreateListLabelsErr(t *testing.T) {
	// Init mock
	client, finish := mockVcsClient(t)
	defer finish()

	// Create label is expected to return error
	expectedError := errors.New("Couldn't list labels")
	client.EXPECT().GetLabel(context.Background(), params.RepoOwner, params.Repo, string(utils.LabelName)).Return(&vcsclient.LabelInfo{
		Name:        string(utils.LabelName),
		Description: string(utils.LabelDescription),
		Color:       string(utils.LabelDescription),
	}, nil)
	client.EXPECT().CreateLabel(context.Background(), params.RepoOwner, params.Repo, vcsclient.LabelInfo{
		Name:        string(utils.LabelName),
		Description: string(utils.LabelDescription),
		Color:       string(utils.LabelColor),
	}).Return(nil)
	client.EXPECT().ListPullRequestLabels(context.Background(), params.RepoOwner, params.Repo, params.PullRequestID).Return([]string{}, expectedError)

	// Run handleFrogbotLabel
	shouldScan, err := handleFrogbotLabel(params, client)
	assert.ErrorIs(t, err, expectedError)
	assert.False(t, shouldScan)
}

func mockVcsClient(t *testing.T) (*testdata.MockVcsClient, func()) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()
	return testdata.NewMockVcsClient(mockCtrl), mockCtrl.Finish
}

func TestCreatePullRequestMessageNoVulnerabilities(t *testing.T) {
	vulnerabilities := []formats.VulnerabilityOrViolationRow{}
	message := createPullRequestMessage(vulnerabilities)

	expectedMessageByte, err := os.ReadFile(filepath.Join("testdata", "messages", "novulnerabilities.md"))
	assert.NoError(t, err)
	expectedMessage := strings.ReplaceAll(string(expectedMessageByte), "\r\n", "\n")
	assert.Equal(t, expectedMessage, message)
}

func TestCreatePullRequestMessage(t *testing.T) {
	vulnerabilities := []formats.VulnerabilityOrViolationRow{
		{
			Severity:               "High",
			ImpactedPackageName:    "github.com/nats-io/nats-streaming-server",
			ImpactedPackageVersion: "v0.21.0",
			FixedVersions:          []string{"[0.24.1]"},
			Components: []formats.ComponentRow{
				{
					Name:    "github.com/nats-io/nats-streaming-server",
					Version: "v0.21.0",
				},
			},
			Cves: []formats.CveRow{{Id: "CVE-2022-24450"}},
		},
		{
			Severity:               "High",
			ImpactedPackageName:    "github.com/mholt/archiver/v3",
			ImpactedPackageVersion: "v3.5.1",
			Components: []formats.ComponentRow{
				{
					Name:    "github.com/mholt/archiver/v3",
					Version: "v3.5.1",
				},
			},
			Cves: []formats.CveRow{},
		},
		{
			Severity:               "Medium",
			ImpactedPackageName:    "github.com/nats-io/nats-streaming-server",
			ImpactedPackageVersion: "v0.21.0",
			FixedVersions:          []string{"[0.24.3]"},
			Components: []formats.ComponentRow{
				{
					Name:    "github.com/nats-io/nats-streaming-server",
					Version: "v0.21.0",
				},
			},
			Cves: []formats.CveRow{{Id: "CVE-2022-26652"}},
		},
	}
	message := createPullRequestMessage(vulnerabilities)

	expectedMessageByte, err := os.ReadFile(filepath.Join("testdata", "messages", "dummyvulnerabilities.md"))
	assert.NoError(t, err)
	expectedMessage := strings.ReplaceAll(string(expectedMessageByte), "\r\n", "\n")
	assert.Equal(t, expectedMessage, message)
}

func TestRunInstallIfNeeded(t *testing.T) {
	params := &utils.FrogbotParams{}
	assert.NoError(t, runInstallIfNeeded(params, "", true))

	params = &utils.FrogbotParams{
		InstallCommandName: "echo",
		InstallCommandArgs: []string{"Hello"},
	}
	assert.NoError(t, runInstallIfNeeded(params, "", true))

	params = &utils.FrogbotParams{
		InstallCommandName: "not-existed",
		InstallCommandArgs: []string{"1", "2"},
	}
	assert.NoError(t, runInstallIfNeeded(params, "", false))

	params = &utils.FrogbotParams{
		InstallCommandName: "not-existed",
		InstallCommandArgs: []string{"1", "2"},
	}
	assert.Error(t, runInstallIfNeeded(params, "", true))
}

func TestScanPullRequest(t *testing.T) {
	testScanPullRequest(t, "", "test-proj")
}

func TestScanPullRequestSubdir(t *testing.T) {
	testScanPullRequest(t, "subdir", "test-proj-subdir")
}

func testScanPullRequest(t *testing.T, workingDirectory, projectName string) {
	restoreEnv := verifyEnv(t)
	defer restoreEnv()

	cleanUp := prepareTestEnvironment(t, projectName)
	defer cleanUp()

	// Create mock GitLab server
	server := httptest.NewServer(createGitLabHandler(t, projectName))
	defer server.Close()

	// Set required environment variables
	utils.SetEnvAndAssert(t, map[string]string{
		utils.GitProvider:         string(utils.GitLab),
		utils.GitApiEndpointEnv:   server.URL,
		utils.GitRepoOwnerEnv:     "jfrog",
		utils.GitRepoEnv:          projectName,
		utils.GitTokenEnv:         "123456",
		utils.GitBaseBranchEnv:    "master",
		utils.GitPullRequestIDEnv: "1",
		utils.InstallCommandEnv:   "npm i",
		utils.WorkingDirectoryEnv: workingDirectory,
	})

	// Run "frogbot spr"
	app := clitool.App{Commands: GetCommands()}
	assert.NoError(t, app.Run([]string{"frogbot", "spr"}))
	utils.AssertSanitizedEnv(t)
}

// Prepare test environment for the integration tests
// projectName - 'test-proj' or 'test-proj-subdir'
// Return a cleanup function
func prepareTestEnvironment(t *testing.T, projectName string) func() {
	// Copy project to a temporary directory
	tmpDir, err := fileutils.CreateTempDir()
	assert.NoError(t, err)
	err = fileutils.CopyDir(filepath.Join("testdata", "scanpullrequest"), tmpDir, true, []string{})
	assert.NoError(t, err)

	restoreDir, err := utils.Chdir(filepath.Join(tmpDir, projectName))
	assert.NoError(t, err)
	return func() {
		restoreDir()
		assert.NoError(t, fileutils.RemoveTempDir(tmpDir))
	}
}

func TestScanPullRequestError(t *testing.T) {
	app := clitool.App{Commands: GetCommands()}
	assert.Error(t, app.Run([]string{"frogbot", "spr"}))
}

func TestUseLabelsError(t *testing.T) {
	_ = verifyEnv(t)
	// Set required environment variables
	utils.SetEnvAndAssert(t, map[string]string{
		utils.GitProvider:         string(utils.GitHub),
		utils.GitRepoOwnerEnv:     "jfrog",
		utils.GitApiEndpointEnv:   "https://httpbin.org/status/404",
		utils.GitRepoEnv:          "test-proj",
		utils.GitTokenEnv:         "123456",
		utils.GitBaseBranchEnv:    "master",
		utils.GitPullRequestIDEnv: "1",
	})
	app := clitool.App{Commands: GetCommands()}
	assert.ErrorContains(t, app.Run([]string{"frogbot", "spr", "--use-labels"}), "404")
	utils.AssertSanitizedEnv(t)
}

// Create HTTP handler to mock GitLab server
func createGitLabHandler(t *testing.T, projectName string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Return 200 on ping
		if r.RequestURI == "/api/v4/" {
			w.WriteHeader(http.StatusOK)
			return
		}

		// Return test-proj.tar.gz when using DownloadRepository
		if r.RequestURI == fmt.Sprintf("/api/v4/projects/jfrog%s/repository/archive.tar.gz?sha=master", "%2F"+projectName) {
			w.WriteHeader(http.StatusOK)
			repoFile, err := os.ReadFile(filepath.Join("..", projectName+".tar.gz"))
			assert.NoError(t, err)
			_, err = w.Write(repoFile)
			assert.NoError(t, err)
		}

		// Return 200 when using the REST that creates the comment
		if r.RequestURI == fmt.Sprintf("/api/v4/projects/jfrog%s/merge_requests/1/notes", "%2F"+projectName) {
			buf := new(bytes.Buffer)
			_, err := buf.ReadFrom(r.Body)
			assert.NoError(t, err)

			expectedReponse, err := os.ReadFile(filepath.Join("..", "expectedReponse.json"))
			assert.NoError(t, err)
			assert.Equal(t, string(expectedReponse), buf.String())

			w.WriteHeader(http.StatusOK)
			_, err = w.Write([]byte("{}"))
			assert.NoError(t, err)
		}
	}
}

// Check connection details with JFrog instance.
// Return a callback method that restores the credentials after the test is done.
func verifyEnv(t *testing.T) func() {
	url := os.Getenv(utils.JFrogUrlEnv)
	username := os.Getenv(utils.JFrogUserEnv)
	password := os.Getenv(utils.JFrogPasswordEnv)
	token := os.Getenv(utils.JFrogTokenEnv)
	if url == "" {
		assert.FailNow(t, fmt.Sprintf("'%s' is not set", utils.JFrogUrlEnv))
	}
	if token == "" && (username == "" || password == "") {
		assert.FailNow(t, fmt.Sprintf("'%s' or '%s' and '%s' are not set", utils.JFrogTokenEnv, utils.JFrogUserEnv, utils.JFrogPasswordEnv))
	}
	return func() {
		utils.SetEnvAndAssert(t, map[string]string{
			utils.JFrogUrlEnv:      url,
			utils.JFrogTokenEnv:    token,
			utils.JFrogUserEnv:     username,
			utils.JFrogPasswordEnv: password,
		})
	}
}
