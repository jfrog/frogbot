package scanrepository

import (
	"errors"
	"fmt"
	"github.com/google/go-github/v45/github"
	"github.com/jfrog/frogbot/utils"
	"github.com/jfrog/frogbot/utils/outputwriter"
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/froggit-go/vcsutils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-core/v2/xray/formats"
	xrayutils "github.com/jfrog/jfrog-cli-core/v2/xray/utils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray/services"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const rootTestDir = "scanrepository"

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

func TestScanRepositoryCmd_Run(t *testing.T) {
	tests := []struct {
		testName               string
		configPath             string
		expectedDiff           []string
		expectedBranches       []string
		packageDescriptorPaths []string
		aggregateFixes         bool
	}{
		{
			testName:               "aggregate",
			expectedBranches:       []string{"frogbot-update-npm-dependencies"},
			expectedDiff:           []string{"diff --git a/package.json b/package.json\nindex c5ea932..1176f2d 100644\n--- a/package.json\n+++ b/package.json\n@@ -9,8 +9,8 @@\n   \"author\": \"\",\n   \"license\": \"ISC\",\n   \"dependencies\": {\n-    \"uuid\": \"^9.0.0\",\n-    \"minimist\":\"1.2.5\",\n-    \"mpath\": \"0.7.0\"\n+    \"minimist\": \"^1.2.6\",\n+    \"mpath\": \"^0.8.4\",\n+    \"uuid\": \"^9.0.0\"\n   }\n-}\n\\ No newline at end of file\n+}\n"},
			packageDescriptorPaths: []string{"package.json"},
			aggregateFixes:         true,
		},
		{
			testName:               "aggregate-multi-dir",
			expectedBranches:       []string{"frogbot-update-npm-dependencies"},
			expectedDiff:           []string{"diff --git a/npm1/package.json b/npm1/package.json\nindex ae09978..286211d 100644\n--- a/npm1/package.json\n+++ b/npm1/package.json\n@@ -9,8 +9,8 @@\n   \"author\": \"\",\n   \"license\": \"ISC\",\n   \"dependencies\": {\n-    \"uuid\": \"^9.0.0\",\n-    \"minimatch\":\"3.0.2\",\n-    \"mpath\": \"0.7.0\"\n+    \"minimatch\": \"^3.0.5\",\n+    \"mpath\": \"^0.8.4\",\n+    \"uuid\": \"^9.0.0\"\n   }\n-}\n\\ No newline at end of file\n+}\ndiff --git a/npm2/package.json b/npm2/package.json\nindex ff94a18..14b5c7a 100644\n--- a/npm2/package.json\n+++ b/npm2/package.json\n@@ -1,5 +1,5 @@\n {\n   \"dependencies\": {\n-    \"minimist\": \"1.2.5\"\n+    \"minimist\": \"^1.2.6\"\n   }\n }\n"},
			packageDescriptorPaths: []string{"npm1/package.json", "npm2/package.json"},
			aggregateFixes:         true,
			configPath:             "../testdata/scanrepository/aggregate-multi-dir/.frogbot/frogbot-config.yml",
		},
		{
			testName:               "aggregate-multi-project",
			expectedBranches:       []string{"frogbot-update-npm-dependencies", "frogbot-update-pip-dependencies"},
			expectedDiff:           []string{"diff --git a/npm/package.json b/npm/package.json\nindex ae09978..286211d 100644\n--- a/npm/package.json\n+++ b/npm/package.json\n@@ -9,8 +9,8 @@\n   \"author\": \"\",\n   \"license\": \"ISC\",\n   \"dependencies\": {\n-    \"uuid\": \"^9.0.0\",\n-    \"minimatch\":\"3.0.2\",\n-    \"mpath\": \"0.7.0\"\n+    \"minimatch\": \"^3.0.5\",\n+    \"mpath\": \"^0.8.4\",\n+    \"uuid\": \"^9.0.0\"\n   }\n-}\n\\ No newline at end of file\n+}\n", "diff --git a/pip/requirements.txt b/pip/requirements.txt\nindex 65c9637..7788edc 100644\n--- a/pip/requirements.txt\n+++ b/pip/requirements.txt\n@@ -1,2 +1,2 @@\n pexpect==4.8.0\n-pyjwt==1.7.1\n\\ No newline at end of file\n+pyjwt==2.4.0\n\\ No newline at end of file\n"},
			packageDescriptorPaths: []string{"npm/package.json", "pip/requirements.txt"},
			aggregateFixes:         true,
			configPath:             "../testdata/scanrepository/aggregate-multi-project/.frogbot/frogbot-config.yml",
		},
		{
			testName:               "aggregate-no-vul",
			expectedBranches:       []string{"master"}, // No branch should be created
			expectedDiff:           []string{""},
			packageDescriptorPaths: []string{"package.json"},
			aggregateFixes:         true,
		},
		{
			testName:               "aggregate-cant-fix",
			expectedBranches:       []string{"frogbot-update-pip-dependencies"},
			expectedDiff:           []string{""},         // No diff expected
			packageDescriptorPaths: []string{"setup.py"}, // This is a build tool dependency which should not be fixed
			aggregateFixes:         true,
		},
		{
			testName:               "non-aggregate",
			expectedBranches:       []string{"frogbot-minimist-258ad6a538b5ba800f18ae4f6d660302"},
			expectedDiff:           []string{"diff --git a/package.json b/package.json\nindex 5c4b711..134c416 100644\n--- a/package.json\n+++ b/package.json\n@@ -9,6 +9,6 @@\n   \"author\": \"\",\n   \"license\": \"ISC\",\n   \"dependencies\": {\n-    \"minimist\":\"1.2.5\"\n+    \"minimist\": \"^1.2.6\"\n   }\n-}\n\\ No newline at end of file\n+}\n"},
			packageDescriptorPaths: []string{"package.json"},
			aggregateFixes:         false,
		},
	}
	baseDir, err := os.Getwd()
	assert.NoError(t, err)
	testDir, cleanup := utils.PrepareTestEnvironment(t, "", rootTestDir, false)
	defer cleanup()
	for _, test := range tests {
		t.Run(test.testName, func(t *testing.T) {
			// Prepare
			serverParams, restoreEnv := utils.VerifyEnv(t)
			if test.aggregateFixes {
				assert.NoError(t, os.Setenv(utils.GitAggregateFixesEnv, "true"))
				defer func() {
					assert.NoError(t, os.Setenv(utils.GitAggregateFixesEnv, "false"))
				}()
			}
			var port string
			server := httptest.NewServer(createScanRepoGitHubHandler(t, &port, nil, test.testName))
			port = server.URL[strings.LastIndex(server.URL, ":")+1:]
			gitTestParams := utils.Git{
				GitProvider: vcsutils.GitHub,
				VcsInfo: vcsclient.VcsInfo{
					Token:       "123456",
					APIEndpoint: server.URL,
				},
				RepoName:  test.testName,
				RepoOwner: "jfrog",
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
				gitTestParams.Branches = []string{"master"}
			}

			utils.CreateDotGitWithCommit(t, testDir, port, test.testName)
			configAggregator, err := utils.BuildRepoAggregator(configData, &gitTestParams, &serverParams)
			assert.NoError(t, err)
			// Run
			var cmd = ScanRepositoryCmd{dryRun: true, dryRunRepoPath: testDir}
			err = cmd.Run(configAggregator, client)
			// Validate
			assert.NoError(t, err)
			for _, branch := range test.expectedBranches {
				resultDiff, err := verifyDependencyFileDiff("master", branch, test.packageDescriptorPaths...)
				assert.NoError(t, err)
				assert.Contains(t, test.expectedDiff, string(resultDiff))
			}
			// Defers
			defer func() {
				assert.NoError(t, os.Chdir(baseDir))
				restoreEnv()
				server.Close()
			}()
		})
	}
}

// Tests the lifecycle of aggregated pull request
// No open pull request -> Open
// If Pull request already active, compare scan results for current and remote branch
// Same scan results -> do nothing.
// Different scan results -> Update the pull request branch & body.
func TestAggregatePullRequestLifecycle(t *testing.T) {
	mockPrId := 1
	sourceBranchName := "frogbot-update-npm-dependencies"
	targetBranchName := "main"
	sourceLabel := "repo:frogbot-update-npm-dependencies"
	targetLabel := "repo:main"
	firstBody := `
[comment]: <> (Checksum: 4608a55b621cb6337ac93487979ac09c)
pr body
`
	secondBody := `
[comment]: <> (Checksum: 01373ac4d2c32e7da9be22f3e4b4e665)
pr body
 `
	tests := []struct {
		testName                string
		expectedUpdate          bool
		mockPullRequestResponse []*github.PullRequest
	}{
		{
			testName:       "aggregate-dont-update-pr",
			expectedUpdate: false,
			mockPullRequestResponse: []*github.PullRequest{{
				Number: &mockPrId,
				Head: &github.PullRequestBranch{
					Label: &sourceLabel,
					Repo:  &github.Repository{Name: &sourceBranchName, Owner: &github.User{}},
				},
				Base: &github.PullRequestBranch{
					Label: &targetLabel,
					Repo:  &github.Repository{Name: &targetBranchName, Owner: &github.User{}},
				},
				Body: &firstBody,
			}},
		},
		{
			testName:       "aggregate-update-pr",
			expectedUpdate: true,
			mockPullRequestResponse: []*github.PullRequest{{
				Number: &mockPrId,
				Head: &github.PullRequestBranch{
					Label: &sourceLabel,
					Repo:  &github.Repository{Name: &sourceBranchName, Owner: &github.User{}},
				},
				Base: &github.PullRequestBranch{
					Label: &targetLabel,
					Repo:  &github.Repository{Name: &targetBranchName, Owner: &github.User{}},
				},
				Body: &secondBody,
			}},
		},
	}
	serverParams, restoreEnv := utils.VerifyEnv(t)
	defer restoreEnv()
	testDir, cleanup := utils.PrepareTestEnvironment(t, "", rootTestDir, false)
	defer cleanup()
	for _, test := range tests {
		t.Run(test.testName, func(t *testing.T) {
			var port string
			server := httptest.NewServer(createScanRepoGitHubHandler(t, &port, test.mockPullRequestResponse, test.testName))
			defer func() {
				server.Close()
			}()
			port = server.URL[strings.LastIndex(server.URL, ":")+1:]

			assert.NoError(t, os.Setenv(utils.GitAggregateFixesEnv, "true"))
			defer func() {
				assert.NoError(t, os.Setenv(utils.GitAggregateFixesEnv, "false"))
			}()

			gitTestParams := &utils.Git{
				GitProvider: vcsutils.GitHub,
				RepoOwner:   "jfrog",
				VcsInfo: vcsclient.VcsInfo{
					Token:       "123456",
					APIEndpoint: server.URL,
				}, RepoName: test.testName,
			}

			utils.CreateDotGitWithCommit(t, testDir, port, test.testName)
			client, err := vcsclient.NewClientBuilder(vcsutils.GitHub).ApiEndpoint(server.URL).Token("123456").Build()
			assert.NoError(t, err)
			// Load default configurations
			var configData []byte
			gitTestParams.Branches = []string{"master"}
			configAggregator, err := utils.BuildRepoAggregator(configData, gitTestParams, &serverParams)
			assert.NoError(t, err)
			// Run
			var cmd = ScanRepositoryCmd{dryRun: true, dryRunRepoPath: testDir}
			err = cmd.Run(configAggregator, client)
			assert.NoError(t, err)
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
	environmentVars, restoreEnv := utils.VerifyEnv(t)
	defer restoreEnv()
	testScan := &ScanRepositoryCmd{OutputWriter: &outputwriter.StandardOutput{}}
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
		projectPath := filepath.Join("..", "testdata", "projects", pkg.packageType.ToString())
		t.Run(pkg.packageType.ToString(), func(t *testing.T) {
			tmpDir, err := fileutils.CreateTempDir()
			defer func() {
				err = fileutils.RemoveTempDir(tmpDir)
			}()
			assert.NoError(t, err)
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

func TestCreateVulnerabilitiesMap(t *testing.T) {
	cfp := &ScanRepositoryCmd{}

	testCases := []struct {
		name            string
		scanResults     *xrayutils.ExtendedScanResults
		isMultipleRoots bool
		expectedMap     map[string]*utils.VulnerabilityDetails
	}{
		{
			name: "Scan results with no violations and vulnerabilities",
			scanResults: &xrayutils.ExtendedScanResults{
				XrayResults: []services.ScanResponse{},
			},
			expectedMap: map[string]*utils.VulnerabilityDetails{},
		},
		{
			name: "Scan results with vulnerabilities and no violations",
			scanResults: &xrayutils.ExtendedScanResults{
				XrayResults: []services.ScanResponse{
					{
						Vulnerabilities: []services.Vulnerability{
							{
								Cves: []services.Cve{
									{Id: "CVE-2023-1234", CvssV3Score: "9.1"},
									{Id: "CVE-2023-4321", CvssV3Score: "8.9"},
								},
								Severity: "Critical",
								Components: map[string]services.Component{
									"vuln1": {
										FixedVersions: []string{"1.9.1", "2.0.3", "2.0.5"},
										ImpactPaths:   [][]services.ImpactPathNode{{{ComponentId: "root"}, {ComponentId: "vuln1"}}},
									},
								},
							},
							{
								Cves: []services.Cve{
									{Id: "CVE-2022-1234", CvssV3Score: "7.1"},
									{Id: "CVE-2022-4321", CvssV3Score: "7.9"},
								},
								Severity: "High",
								Components: map[string]services.Component{
									"vuln2": {
										FixedVersions: []string{"2.4.1", "2.6.3", "2.8.5"},
										ImpactPaths:   [][]services.ImpactPathNode{{{ComponentId: "root"}, {ComponentId: "vuln1"}, {ComponentId: "vuln2"}}},
									},
								},
							},
						},
					},
				},
			},
			expectedMap: map[string]*utils.VulnerabilityDetails{
				"vuln1": {
					SuggestedFixedVersion: "1.9.1",
					IsDirectDependency:    true,
					Cves:                  []string{"CVE-2023-1234", "CVE-2023-4321"},
				},
				"vuln2": {
					SuggestedFixedVersion: "2.4.1",
					Cves:                  []string{"CVE-2022-1234", "CVE-2022-4321"},
				},
			},
		},
		{
			name: "Scan results with violations and no vulnerabilities",
			scanResults: &xrayutils.ExtendedScanResults{
				XrayResults: []services.ScanResponse{
					{
						Violations: []services.Violation{
							{
								ViolationType: "security",
								Cves: []services.Cve{
									{Id: "CVE-2023-1234", CvssV3Score: "9.1"},
									{Id: "CVE-2023-4321", CvssV3Score: "8.9"},
								},
								Severity: "Critical",
								Components: map[string]services.Component{
									"viol1": {
										FixedVersions: []string{"1.9.1", "2.0.3", "2.0.5"},
										ImpactPaths:   [][]services.ImpactPathNode{{{ComponentId: "root"}, {ComponentId: "viol1"}}},
									},
								},
							},
							{
								ViolationType: "security",
								Cves: []services.Cve{
									{Id: "CVE-2022-1234", CvssV3Score: "7.1"},
									{Id: "CVE-2022-4321", CvssV3Score: "7.9"},
								},
								Severity: "High",
								Components: map[string]services.Component{
									"viol2": {
										FixedVersions: []string{"2.4.1", "2.6.3", "2.8.5"},
										ImpactPaths:   [][]services.ImpactPathNode{{{ComponentId: "root"}, {ComponentId: "viol1"}, {ComponentId: "viol2"}}},
									},
								},
							},
						},
					},
				},
			},
			expectedMap: map[string]*utils.VulnerabilityDetails{
				"viol1": {
					SuggestedFixedVersion: "1.9.1",
					IsDirectDependency:    true,
					Cves:                  []string{"CVE-2023-1234", "CVE-2023-4321"},
				},
				"viol2": {
					SuggestedFixedVersion: "2.4.1",
					Cves:                  []string{"CVE-2022-1234", "CVE-2022-4321"},
				},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			fixVersionsMap, err := cfp.createVulnerabilitiesMap(testCase.scanResults, testCase.isMultipleRoots)
			assert.NoError(t, err)
			for name, expectedVuln := range testCase.expectedMap {
				actualVuln, exists := fixVersionsMap[name]
				require.True(t, exists)
				assert.Equal(t, expectedVuln.IsDirectDependency, actualVuln.IsDirectDependency)
				assert.Equal(t, expectedVuln.SuggestedFixedVersion, actualVuln.SuggestedFixedVersion)
				assert.ElementsMatch(t, expectedVuln.Cves, actualVuln.Cves)
			}
		})
	}
}

// Verifies unsupported packages return specific error
// Other logic is implemented inside each package-handler.
func TestUpdatePackageToFixedVersion(t *testing.T) {
	var testScan ScanRepositoryCmd
	for tech, buildToolsDependencies := range utils.BuildToolsDependenciesMap {
		for _, impactedDependency := range buildToolsDependencies {
			vulnDetails := &utils.VulnerabilityDetails{SuggestedFixedVersion: "3.3.3", VulnerabilityOrViolationRow: formats.VulnerabilityOrViolationRow{Technology: tech, ImpactedDependencyName: impactedDependency}, IsDirectDependency: true}
			err := testScan.updatePackageToFixedVersion(vulnDetails)
			assert.Error(t, err, "Expected error to occur")
			assert.IsType(t, &utils.ErrUnsupportedFix{}, err, "Expected unsupported fix error")
		}
	}
}

func TestGetRemoteBranchScanHash(t *testing.T) {
	prBody := `
[![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/vulnerabilitiesBannerMR.png)](https://github.com/jfrog/frogbot#readme)
## 📦 Vulnerable Dependencies 

### ✍️ Summary

<div align="center">

| SEVERITY                | CONTEXTUAL ANALYSIS                  | DIRECT DEPENDENCIES                  | IMPACTED DEPENDENCY                   | FIXED VERSIONS                       |
| :---------------------: | :----------------------------------: | :----------------------------------: | :-----------------------------------: | :---------------------------------: | 
| ![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/applicableHighSeverity.png)<br>    High | $\color{}{\textsf{Undetermined}}$ |github.com/nats-io/nats-streaming-server:v0.21.0 | github.com/nats-io/nats-streaming-server:v0.21.0 | [0.24.1] |
| ![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/applicableHighSeverity.png)<br>    High | $\color{}{\textsf{Undetermined}}$ |github.com/mholt/archiver/v3:v3.5.1 | github.com/mholt/archiver/v3:v3.5.1 |  |
| ![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/applicableMediumSeverity.png)<br>  Medium | $\color{}{\textsf{Undetermined}}$ |github.com/nats-io/nats-streaming-server:v0.21.0 | github.com/nats-io/nats-streaming-server:v0.21.0 | [0.24.3] |

</div>

## 👇 Details


<details>
<summary> <b>github.com/nats-io/nats-streaming-server v0.21.0</b> </summary>
<br>

- **Severity** 🔥 High
- **Contextual Analysis:** $\color{}{\textsf{Undetermined}}$
- **Package Name:** github.com/nats-io/nats-streaming-server
- **Current Version:** v0.21.0
- **Fixed Version:** [0.24.1]
- **CVEs:** CVE-2022-24450


</details>


<details>
<summary> <b>github.com/mholt/archiver/v3 v3.5.1</b> </summary>
<br>

- **Severity** 🔥 High
- **Contextual Analysis:** $\color{}{\textsf{Undetermined}}$
- **Package Name:** github.com/mholt/archiver/v3
- **Current Version:** v3.5.1


</details>


<details>
<summary> <b>github.com/nats-io/nats-streaming-server v0.21.0</b> </summary>
<br>

- **Severity** 🎃 Medium
- **Contextual Analysis:** $\color{}{\textsf{Undetermined}}$
- **Package Name:** github.com/nats-io/nats-streaming-server
- **Current Version:** v0.21.0
- **Fixed Version:** [0.24.3]
- **CVEs:** CVE-2022-26652


</details>


## 🛠️ Infrastructure as Code 

<div align="center">


| SEVERITY                | FILE                  | LINE:COLUMN                   | FINDING                       |
| :---------------------: | :----------------------------------: | :-----------------------------------: | :---------------------------------: | 
| ![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/applicableLowSeverity.png)<br>     Low | test.js | 1:20 | kms_key_id='' was detected |
| ![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/applicableHighSeverity.png)<br>    High | test2.js | 4:30 | Deprecated TLS version was detected |

</div>


<div align="center">

[JFrog Frogbot](https://github.com/jfrog/frogbot#readme)

</div>

[Comment]: <> (Checksum: myhash4321)
`
	cfp := &ScanRepositoryCmd{}
	result := cfp.getRemoteBranchScanHash(prBody)
	assert.Equal(t, "myhash4321", result)
	prBody = `
random body
`
	result = cfp.getRemoteBranchScanHash(prBody)
	assert.Equal(t, "", result)
}

func TestPreparePullRequestDetails(t *testing.T) {
	cfp := ScanRepositoryCmd{OutputWriter: &outputwriter.StandardOutput{}, gitManager: &utils.GitManager{}}
	vulnerabilities := []formats.VulnerabilityOrViolationRow{
		{
			Summary:                   "summary",
			Severity:                  "High",
			ImpactedDependencyName:    "package1",
			ImpactedDependencyVersion: "1.0.0",
			FixedVersions:             []string{"1.0.0", "2.0.0"},
			Cves:                      []formats.CveRow{{Id: "CVE-2022-1234"}},
		},
	}
	expectedPrBody := "<div align='center'>\n\n[![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/vulnerabilitiesFixBannerPR.png)](https://github.com/jfrog/frogbot#readme)\n\n</div>\n\n\n\n## 📦 Vulnerable Dependencies \n\n### ✍️ Summary\n\n<div align=\"center\">\n\n\n| SEVERITY                | DIRECT DEPENDENCIES                  | IMPACTED DEPENDENCY                   | FIXED VERSIONS                       |\n| :---------------------: | :----------------------------------: | :-----------------------------------: | :---------------------------------: | \n| ![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/applicableHighSeverity.png)<br>    High |  | package1:1.0.0 | 1.0.0<br><br>2.0.0 |\n\n</div>\n\n## 👇 Details\n\n\n\n\n- **Severity** 🔥 High\n- **Package Name:** package1\n- **Current Version:** 1.0.0\n- **Fixed Versions:** 1.0.0,2.0.0\n- **CVE:** CVE-2022-1234\n\n**Description:**\n\nsummary\n\n\n\n\n---\n\n<div align=\"center\">\n\n**Frogbot** also supports **Contextual Analysis, Secret Detection and IaC Vulnerabilities Scanning**. This features are included as part of the [JFrog Advanced Security](https://jfrog.com/xray/) package, which isn't enabled on your system.\n\n</div>\n\n<div align=\"center\">\n\n[JFrog Frogbot](https://github.com/jfrog/frogbot#readme)\n\n</div>\n"
	prTitle, prBody := cfp.preparePullRequestDetails("hash", vulnerabilities)
	assert.Equal(t, "[🐸 Frogbot] Update version of package1 to 1.0.0", prTitle)
	assert.Equal(t, expectedPrBody, prBody)
	vulnerabilities = append(vulnerabilities, formats.VulnerabilityOrViolationRow{
		Summary:                   "summary",
		Severity:                  "Critical",
		ImpactedDependencyName:    "package2",
		ImpactedDependencyVersion: "2.0.0",
		FixedVersions:             []string{"2.0.0", "3.0.0"},
		Cves:                      []formats.CveRow{{Id: "CVE-2022-4321"}},
	})
	cfp.aggregateFixes = true
	expectedPrBody = "<div align='center'>\n\n[![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/vulnerabilitiesFixBannerPR.png)](https://github.com/jfrog/frogbot#readme)\n\n</div>\n\n\n\n## 📦 Vulnerable Dependencies \n\n### ✍️ Summary\n\n<div align=\"center\">\n\n\n| SEVERITY                | DIRECT DEPENDENCIES                  | IMPACTED DEPENDENCY                   | FIXED VERSIONS                       |\n| :---------------------: | :----------------------------------: | :-----------------------------------: | :---------------------------------: | \n| ![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/applicableHighSeverity.png)<br>    High |  | package1:1.0.0 | 1.0.0<br><br>2.0.0 |\n| ![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/applicableCriticalSeverity.png)<br>Critical |  | package2:2.0.0 | 2.0.0<br><br>3.0.0 |\n\n</div>\n\n## 👇 Details\n\n\n<details>\n<summary> <b>package1 1.0.0</b> </summary>\n<br>\n\n- **Severity** 🔥 High\n- **Package Name:** package1\n- **Current Version:** 1.0.0\n- **Fixed Versions:** 1.0.0,2.0.0\n- **CVE:** CVE-2022-1234\n\n**Description:**\n\nsummary\n\n\n\n</details>\n\n\n<details>\n<summary> <b>package2 2.0.0</b> </summary>\n<br>\n\n- **Severity** 💀 Critical\n- **Package Name:** package2\n- **Current Version:** 2.0.0\n- **Fixed Versions:** 2.0.0,3.0.0\n- **CVE:** CVE-2022-4321\n\n**Description:**\n\nsummary\n\n\n\n</details>\n\n\n---\n\n<div align=\"center\">\n\n**Frogbot** also supports **Contextual Analysis, Secret Detection and IaC Vulnerabilities Scanning**. This features are included as part of the [JFrog Advanced Security](https://jfrog.com/xray/) package, which isn't enabled on your system.\n\n</div>\n\n<div align=\"center\">\n\n[JFrog Frogbot](https://github.com/jfrog/frogbot#readme)\n\n</div>\n\n[comment]: <> (Checksum: hash)\n"
	prTitle, prBody = cfp.preparePullRequestDetails("hash", vulnerabilities)
	assert.Equal(t, outputwriter.GetAggregatedPullRequestTitle(""), prTitle)
	assert.Equal(t, expectedPrBody, prBody)
	cfp.OutputWriter = &outputwriter.SimplifiedOutput{}
	expectedPrBody = "**🚨 This automated pull request was created by Frogbot and fixes the below:**\n\n\n---\n## 📦 Vulnerable Dependencies\n---\n\n### ✍️ Summary \n\n\n| SEVERITY                | DIRECT DEPENDENCIES                  | IMPACTED DEPENDENCY                   | FIXED VERSIONS                       |\n| :---------------------: | :----------------------------------: | :-----------------------------------: | :---------------------------------: | \n| High |   | package1:1.0.0 | 1.0.0, 2.0.0 |\n| Critical |   | package2:2.0.0 | 2.0.0, 3.0.0 |\n\n---\n### 👇 Details\n---\n\n\n#### package1 1.0.0\n\n\n- **Severity** 🔥 High\n- **Package Name:** package1\n- **Current Version:** 1.0.0\n- **Fixed Versions:** 1.0.0,2.0.0\n- **CVE:** CVE-2022-1234\n\n**Description:**\n\nsummary\n\n\n\n\n#### package2 2.0.0\n\n\n- **Severity** 💀 Critical\n- **Package Name:** package2\n- **Current Version:** 2.0.0\n- **Fixed Versions:** 2.0.0,3.0.0\n- **CVE:** CVE-2022-4321\n\n**Description:**\n\nsummary\n\n\n\n\n---\n\n\n**Frogbot** also supports **Contextual Analysis, Secret Detection and IaC Vulnerabilities Scanning**. This features are included as part of the [JFrog Advanced Security](https://jfrog.com/xray/) package, which isn't enabled on your system.\n\n[JFrog Frogbot](https://github.com/jfrog/frogbot#readme)\n[comment]: <> (Checksum: hash)\n"
	prTitle, prBody = cfp.preparePullRequestDetails("hash", vulnerabilities)
	assert.Equal(t, outputwriter.GetAggregatedPullRequestTitle(""), prTitle)
	assert.Equal(t, expectedPrBody, prBody)
}

func verifyTechnologyNaming(t *testing.T, scanResponse []services.ScanResponse, expectedType coreutils.Technology) {
	for _, resp := range scanResponse {
		for _, vulnerability := range resp.Vulnerabilities {
			assert.Equal(t, expectedType.ToString(), vulnerability.Technology)
		}
	}
}

// Executing git diff to ensure that the intended changes to the dependent file have been made
func verifyDependencyFileDiff(baseBranch string, fixBranch string, packageDescriptorPaths ...string) (output []byte, err error) {
	log.Debug(fmt.Sprintf("Checking differences in %s between branches %s and %s", packageDescriptorPaths, baseBranch, fixBranch))
	// Suppress condition always false warning
	//goland:noinspection ALL
	var args []string
	if coreutils.IsWindows() {
		args = []string{"/c", "git", "diff", baseBranch, fixBranch}
		args = append(args, packageDescriptorPaths...)
		output, err = exec.Command("cmd", args...).Output()
	} else {
		args = []string{"diff", baseBranch, fixBranch}
		args = append(args, packageDescriptorPaths...)
		output, err = exec.Command("git", args...).Output()
	}
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		err = errors.New("git error: " + string(exitError.Stderr))
	}
	return
}
