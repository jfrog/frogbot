package commands

import (
	"context"
	"fmt"
	"github.com/jfrog/frogbot/commands/utils"
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/froggit-go/vcsutils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-core/v2/xray/formats"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray/services"
	"github.com/stretchr/testify/assert"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const (
	aggregatedBranchConstName = "frogbot-update-dependencies-0"
	mockUpdatePrBody          = "\n## Summary\n\n<div align=\"center\">\n\n| SEVERITY                | CONTEXTUAL ANALYSIS                  | DIRECT DEPENDENCIES                  | IMPACTED DEPENDENCY                   | FIXED VERSIONS                       |\n| :---------------------: | :----------------------------------: | :----------------------------------: | :-----------------------------------: | :---------------------------------: | \n| ![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/applicableCriticalSeverity.png)<br>Critical | $\\color{#FFFFFFFF}{\\textsf{Undetermined}}$ |mongoose:5.10.10 | mongoose:5.10.10 | 5.13.15 |\n| ![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/applicableCriticalSeverity.png)<br>Critical | $\\color{#FFFFFFFF}{\\textsf{Undetermined}}$ |mpath:0.7.0 | mpath:0.7.0 | 0.8.4 |\n\n</div>\n\n## Details\n\n\n<details>\n<summary> <b>mongoose 5.10.10</b> </summary>\n<br>\n\n- **Severity:** Critical 💀\n- **Package Name:** mongoose\n- **Current Version:** 5.10.10\n- **Fixed Version:** 5.13.15\n- **CVEs:** CVE-2022-2564\n\n**Description:**\n\nPrototype Pollution in GitHub repository automattic/mongoose prior to 6.4.6.\n\n\n</details>\n\n\n<details>\n<summary> <b>mpath 0.7.0</b> </summary>\n<br>\n\n- **Severity:** Critical 💀\n- **Package Name:** mpath\n- **Current Version:** 0.7.0\n- **Fixed Version:** 0.8.4\n- **CVEs:** CVE-2021-23438\n\n**Description:**\n\nThis affects the package mpath before 0.8.4. A type confusion vulnerability can lead to a bypass of CVE-2018-16490. In particular, the condition ignoreProperties.indexOf(parts[i]) !== -1 returns -1 if parts[i] is ['__proto__']. This is because the method that has been called if the input is an array is Array.prototype.indexOf() and not String.prototype.indexOf(). They behave differently depending on the type of the input.\n\n\n</details>\n\n"
)

var testPackagesData = []struct {
	packageType coreutils.Technology
	commandName string
	commandArgs []string
}{
	{
		packageType: coreutils.Go,
	},
	{
		packageType: coreutils.Maven,
	},
	{
		packageType: coreutils.Gradle,
	},
	{
		packageType: coreutils.Npm,
		commandName: "npm",
		commandArgs: []string{"install"},
	},
	{
		packageType: coreutils.Yarn,
		commandName: "yarn",
		commandArgs: []string{"install"},
	},
	{
		packageType: coreutils.Dotnet,
		commandName: "dotnet",
		commandArgs: []string{"restore"},
	},
	{
		packageType: coreutils.Pip,
	},
	{
		packageType: coreutils.Pipenv,
	},
	{
		packageType: coreutils.Poetry,
	},
}

func TestCreateFixPullRequestsCmd_Run(t *testing.T) {
	tests := []struct {
		repoName           string
		testDir            string
		configPath         string
		expectedBranchName string
		expectedDiff       string
		dependencyFileName string
		aggregateFixes     bool
	}{
		{
			repoName:           "aggregate",
			testDir:            "createfixpullrequests/aggregate",
			expectedBranchName: aggregatedBranchConstName,
			expectedDiff:       "diff --git a/package.json b/package.json\nindex 8f0367a..62133f2 100644\n--- a/package.json\n+++ b/package.json\n@@ -14,15 +14,16 @@\n     \"json5\": \"^1.0.2\",\n     \"jsonwebtoken\": \"^9.0.0\",\n     \"ldapjs\": \"^3.0.1\",\n+    \"lodash\": \"4.16.4\",\n+    \"moment\": \"2.29.1\",\n+    \"mongoose\": \"^5.13.15\",\n+    \"mpath\": \"^0.8.4\",\n     \"primeflex\": \"^3.3.0\",\n     \"primeicons\": \"^6.0.1\",\n     \"primereact\": \"^9.2.1\",\n     \"sass\": \"^1.59.3\",\n     \"scss\": \"^0.2.4\",\n     \"typescript\": \"5.0.2\",\n-    \"uuid\": \"^9.0.0\",\n-    \"moment\": \"2.29.1\",\n-    \"lodash\": \"4.16.4\",\n-    \"mongoose\":\"5.10.10\"\n+    \"uuid\": \"^9.0.0\"\n   }\n-}\n\\ No newline at end of file\n+}\n",
			dependencyFileName: "package.json",
			aggregateFixes:     true,
		},
		{
			repoName:           "aggregate-no-vul",
			testDir:            "createfixpullrequests/aggregate-no-vul",
			expectedBranchName: "main", // No branch should be created
			expectedDiff:       "",
			dependencyFileName: "package.json",
			aggregateFixes:     true,
		},
		{
			repoName:           "aggregate-cant-fix",
			testDir:            "createfixpullrequests/aggregate-cant-fix",
			expectedBranchName: aggregatedBranchConstName,
			expectedDiff:       "",         // No diff expected
			dependencyFileName: "setup.py", // This is a build tool dependency which should not be fixed
			aggregateFixes:     true,
		},
		{
			repoName:           "non-aggregate",
			testDir:            "createfixpullrequests/non-aggregate",
			expectedBranchName: "frogbot-mongoose-8ed82a82c26133b1bcf556d6dc2db0d3",
			expectedDiff:       "diff --git a/package.json b/package.json\nindex e016d1b..a4bf5ed 100644\n--- a/package.json\n+++ b/package.json\n@@ -9,6 +9,6 @@\n   \"author\": \"\",\n   \"license\": \"ISC\",\n   \"dependencies\": {\n-    \"mongoose\":\"5.10.10\"\n+    \"mongoose\": \"^5.13.15\"\n   }\n-}\n\\ No newline at end of file\n+}\n",
			dependencyFileName: "package.json",
			aggregateFixes:     false,
		},
	}
	for _, test := range tests {
		t.Run(test.repoName, func(t *testing.T) {
			// Prepare
			serverParams, restoreEnv := verifyEnv(t)
			var port string
			server := httptest.NewServer(createHttpHandler(t, &port, test.repoName))
			port = server.URL[strings.LastIndex(server.URL, ":")+1:]
			gitTestParams := utils.Git{
				ClientInfo: utils.ClientInfo{
					GitProvider: vcsutils.GitHub,
					VcsInfo: vcsclient.VcsInfo{
						Token:       "123456",
						APIEndpoint: server.URL,
					},
					RepoName: test.repoName,
				},
				AggregateFixes: test.aggregateFixes,
			}
			client, err := vcsclient.NewClientBuilder(vcsutils.GitHub).ApiEndpoint(server.URL).Token("123456").Build()
			assert.NoError(t, err)

			// Read config or resolve to default
			var configData []byte
			if test.configPath != "" {
				configData, err = utils.ReadConfigFromFileSystem(test.configPath)
				assert.NoError(t, err)
			} else {
				configData = []byte{}
				// Manual set of "JF_GIT_BASE_BRANCH"
				gitTestParams.Branches = []string{"main"}
			}

			envPath, cleanUp := utils.PrepareTestEnvironment(t, "", test.testDir)
			defer cleanUp()
			configAggregator, err := utils.BuildRepoAggregator(configData, &gitTestParams, &serverParams)
			assert.NoError(t, err)
			// Run
			var cmd = CreateFixPullRequestsCmd{dryRun: true, dryRunRepoPath: envPath}
			err = cmd.Run(configAggregator, client)
			// Validate
			assert.NoError(t, err)
			resultDiff, err := verifyDependencyFileDiff("main", test.expectedBranchName, test.dependencyFileName)
			assert.NoError(t, err)
			assert.Equal(t, test.expectedDiff, string(resultDiff))
			// Defers
			restoreEnv()
			server.Close()
		})
	}
}

// Tests the lifecycle of aggregated pull request
// No open pull request -> Open
// Pull request already active  ->
//
//			Compare scan results for current and remote branch
//	   	 	 Same scan results -> does thing.
//	   	     Different scan results -> Update the pull request branch & body.
func TestAggregatePullRequestLifecycle(t *testing.T) {
	mockPrId := int64(1)
	tests := []struct {
		repoName                string
		testDir                 string
		expectedDiff            string
		mockPullRequestResponse []vcsclient.PullRequestInfo
	}{
		{
			repoName:     "aggregate-dont-update-pr",
			testDir:      "createfixpullrequests/aggregate-dont-update-pr",
			expectedDiff: "",
			mockPullRequestResponse: []vcsclient.PullRequestInfo{{ID: mockPrId,
				Source: vcsclient.BranchInfo{Name: aggregatedBranchConstName},
				Target: vcsclient.BranchInfo{Name: "main"},
			}},
		},
		{
			repoName:     "aggregate-update-pr",
			testDir:      "createfixpullrequests/aggregate-update-pr",
			expectedDiff: "diff --git a/package.json b/package.json\nindex cf91c35..1ed85f0 100644\n--- a/package.json\n+++ b/package.json\n@@ -9,7 +9,7 @@\n   \"author\": \"\",\n   \"license\": \"ISC\",\n   \"dependencies\": {\n-    \"mpath\": \"0.7.0\",\n-    \"mongoose\":\"5.10.10\"\n+    \"mongoose\": \"^5.13.15\",\n+    \"mpath\": \"^0.8.4\"\n   }\n-}\n\\ No newline at end of file\n+}\n",
			mockPullRequestResponse: []vcsclient.PullRequestInfo{{ID: mockPrId,
				Source: vcsclient.BranchInfo{Name: aggregatedBranchConstName},
				Target: vcsclient.BranchInfo{Name: "main"},
			}},
		},
	}
	for _, test := range tests {
		t.Run(test.repoName, func(t *testing.T) {
			// Prepare
			serverParams, restoreEnv := verifyEnv(t)
			var port string
			server := httptest.NewServer(createHttpHandler(t, &port, test.repoName))
			port = server.URL[strings.LastIndex(server.URL, ":")+1:]
			gitTestParams := utils.Git{ClientInfo: utils.ClientInfo{
				GitProvider: vcsutils.GitHub,
				VcsInfo: vcsclient.VcsInfo{
					Token:       "123456",
					APIEndpoint: server.URL,
				}, RepoName: test.repoName,
			}, AggregateFixes: true,
			}
			// Set up mock VCS responses
			client := mockVcsClient(t)
			if test.mockPullRequestResponse != nil {
				client.EXPECT().ListOpenPullRequests(context.Background(), "", gitTestParams.RepoName).Return(test.mockPullRequestResponse, nil)
			}
			// If were expecting a diff, we expect a call to update pull request.
			if test.expectedDiff != "" {
				client.EXPECT().UpdatePullRequest(context.Background(), "", gitTestParams.RepoName, utils.AggregatedPullRequestTitleTemplate, mockUpdatePrBody, "", int(mockPrId), vcsutils.Open).Return(nil)
			}
			// Load default configurations
			var configData []byte
			// Manual set of "JF_GIT_BASE_BRANCH"
			gitTestParams.Branches = []string{"main"}
			envPath, cleanUp := utils.PrepareTestEnvironment(t, "", test.testDir)
			defer cleanUp()
			configAggregator, err := utils.BuildRepoAggregator(configData, &gitTestParams, &serverParams)
			assert.NoError(t, err)

			// Run
			var cmd = CreateFixPullRequestsCmd{dryRun: true, dryRunRepoPath: envPath}
			err = cmd.Run(configAggregator, client)
			assert.NoError(t, err)
			// Validate
			resultDiff, err := verifyDependencyFileDiff("main", aggregatedBranchConstName, "package.json")
			assert.NoError(t, err)
			assert.Equal(t, test.expectedDiff, string(resultDiff))
			// Defers
			restoreEnv()
			server.Close()
		})
	}
}

// /      1.0         --> 1.0 ≤ x
// /      (,1.0]      --> x ≤ 1.0
// /      (,1.0)      --> x < 1.0
// /      [1.0]       --> x == 1.0
// /      (1.0,)      --> 1.0 < x
// /      (1.0, 2.0)   --> 1.0 < x < 2.0
// /      [1.0, 2.0]   --> 1.0 ≤ x ≤ 2.0
func TestParseVersionChangeString(t *testing.T) {
	tests := []struct {
		versionChangeString string
		expectedVersion     string
	}{
		{"1.2.3", "1.2.3"},
		{"[1.2.3]", "1.2.3"},
		{"[1.2.3, 2.0.0]", "1.2.3"},

		{"(,1.2.3]", ""},
		{"(,1.2.3)", ""},
		{"(1.2.3,)", ""},
		{"(1.2.3, 2.0.0)", ""},
	}

	for _, test := range tests {
		t.Run(test.versionChangeString, func(t *testing.T) {
			assert.Equal(t, test.expectedVersion, parseVersionChangeString(test.versionChangeString))
		})
	}
}

func TestGenerateFixBranchName(t *testing.T) {
	tests := []struct {
		baseBranch      string
		impactedPackage string
		fixVersion      string
		expectedName    string
	}{
		{"dev", "gopkg.in/yaml.v3", "3.0.0", "frogbot-gopkg.in/yaml.v3-d61bde82dc594e5ccc5a042fe224bf7c"},
		{"master", "gopkg.in/yaml.v3", "3.0.0", "frogbot-gopkg.in/yaml.v3-41405528994061bd108e3bbd4c039a03"},
		{"dev", "replace:colons:colons", "3.0.0", "frogbot-replace_colons_colons-89e555131b4a70a32fe9d9c44d6ff0fc"},
	}
	gitManager := utils.GitManager{}
	for _, test := range tests {
		t.Run(test.expectedName, func(t *testing.T) {
			branchName, err := gitManager.GenerateFixBranchName(test.baseBranch, test.impactedPackage, test.fixVersion)
			assert.NoError(t, err)
			assert.Equal(t, test.expectedName, branchName)
		})
	}
}

func TestPackageTypeFromScan(t *testing.T) {
	environmentVars, restoreEnv := verifyEnv(t)
	defer restoreEnv()
	var testScan CreateFixPullRequestsCmd
	trueVal := true
	params := utils.Params{
		Scan: utils.Scan{Projects: []utils.Project{{UseWrapper: &trueVal}}},
	}
	var frogbotParams = utils.Repository{
		Server: environmentVars,
		Params: params,
	}
	for _, pkg := range testPackagesData {
		// Create temp technology project
		projectPath := filepath.Join("testdata", "projects", pkg.packageType.ToString())
		t.Run(pkg.packageType.ToString(), func(t *testing.T) {
			tmpDir, err := fileutils.CreateTempDir()
			assert.NoError(t, err)
			defer func() {
				assert.NoError(t, fileutils.RemoveTempDir(tmpDir))
			}()
			assert.NoError(t, fileutils.CopyDir(projectPath, tmpDir, true, nil))
			if pkg.packageType == coreutils.Gradle {
				assert.NoError(t, os.Chmod(filepath.Join(tmpDir, "gradlew"), 0777))
				assert.NoError(t, os.Chmod(filepath.Join(tmpDir, "gradlew.bat"), 0777))
			}
			frogbotParams.Projects[0].WorkingDirs = []string{tmpDir}
			files, err := fileutils.ListFiles(tmpDir, true)
			assert.NoError(t, err)
			for _, file := range files {
				log.Info(file)
			}
			frogbotParams.Projects[0].InstallCommandName = pkg.commandName
			frogbotParams.Projects[0].InstallCommandArgs = pkg.commandArgs
			scanSetup := utils.ScanDetails{
				XrayGraphScanParams: &services.XrayGraphScanParams{},
				Project:             &frogbotParams.Projects[0],
				ServerDetails:       &frogbotParams.Server,
			}
			testScan.details = &scanSetup
			scanResponse, err := testScan.scan(tmpDir)
			assert.NoError(t, err)
			verifyTechnologyNaming(t, scanResponse.ExtendedScanResults.XrayResults, pkg.packageType)
		})
	}
}

func TestGetMinimalFixVersion(t *testing.T) {
	tests := []struct {
		impactedVersionPackage string
		fixVersions            []string
		expected               string
	}{
		{impactedVersionPackage: "1.6.2", fixVersions: []string{"1.5.3", "1.6.1", "1.6.22", "1.7.0"}, expected: "1.6.22"},
		{impactedVersionPackage: "v1.6.2", fixVersions: []string{"1.5.3", "1.6.1", "1.6.22", "1.7.0"}, expected: "1.6.22"},
		{impactedVersionPackage: "1.7.1", fixVersions: []string{"1.5.3", "1.6.1", "1.6.22", "1.7.0"}, expected: ""},
		{impactedVersionPackage: "1.7.1", fixVersions: []string{"2.5.3"}, expected: "2.5.3"},
		{impactedVersionPackage: "v1.7.1", fixVersions: []string{"0.5.3", "0.9.9"}, expected: ""},
	}
	for _, test := range tests {
		t.Run(test.expected, func(t *testing.T) {
			expected := getMinimalFixVersion(test.impactedVersionPackage, test.fixVersions)
			assert.Equal(t, test.expected, expected)
		})
	}
}

// Verifies unsupported packages return specific error
// Other logic is implemented inside each package-handler.
func TestUpdatePackageToFixedVersion(t *testing.T) {
	var testScan CreateFixPullRequestsCmd
	for tech, buildToolsDependencies := range utils.BuildToolsDependenciesMap {
		for _, impactedDependency := range buildToolsDependencies {
			vulnDetails := &utils.VulnerabilityDetails{FixVersion: "3.3.3", VulnerabilityOrViolationRow: &formats.VulnerabilityOrViolationRow{Technology: tech, ImpactedDependencyName: impactedDependency}, IsDirectDependency: true}
			err := testScan.updatePackageToFixedVersion(vulnDetails)
			assert.Error(t, err, "Expected error to occur")
			assert.IsType(t, &utils.ErrUnsupportedFix{}, err, "Expected unsupported fix error")
		}
	}
}

func verifyTechnologyNaming(t *testing.T, scanResponse []services.ScanResponse, expectedType coreutils.Technology) {
	for _, resp := range scanResponse {
		for _, vulnerability := range resp.Vulnerabilities {
			assert.Equal(t, expectedType.ToString(), vulnerability.Technology)
		}
	}
}

// Executing git diff to ensure that the intended changes to the dependent file have been made
func verifyDependencyFileDiff(baseBranch string, fixBranch string, dependencyFilename string) ([]byte, error) {
	var cmd *exec.Cmd
	log.Debug(fmt.Sprintf("Checking differance in the file %s between branches %s and %s", dependencyFilename, baseBranch, fixBranch))
	// Suppress condition always false warning
	//goland:noinspection ALL
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/c", "git", "diff", baseBranch, fixBranch, "--", dependencyFilename)
	} else {
		cmd = exec.Command("git", "diff", baseBranch, fixBranch, "--", dependencyFilename)
	}
	return cmd.Output()
}
