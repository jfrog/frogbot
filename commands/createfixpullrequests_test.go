package commands

import (
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/froggit-go/vcsutils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/stretchr/testify/assert"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/jfrog/frogbot/commands/utils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-client-go/xray/services"
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
			configPath:         filepath.Join("testdata", "config", "frogbot-config-create-fix-pull-requests-aggregate.yml"),
			expectedBranchName: "frogobt-b371dfb6a09ce867624ff27a8c069c50",
			expectedDiff:       "diff --git a/package.json b/package.json\nindex 8f0367a..62133f2 100644\n--- a/package.json\n+++ b/package.json\n@@ -14,15 +14,16 @@\n     \"json5\": \"^1.0.2\",\n     \"jsonwebtoken\": \"^9.0.0\",\n     \"ldapjs\": \"^3.0.1\",\n+    \"lodash\": \"4.16.4\",\n+    \"moment\": \"2.29.1\",\n+    \"mongoose\": \"^5.13.15\",\n+    \"mpath\": \"^0.8.4\",\n     \"primeflex\": \"^3.3.0\",\n     \"primeicons\": \"^6.0.1\",\n     \"primereact\": \"^9.2.1\",\n     \"sass\": \"^1.59.3\",\n     \"scss\": \"^0.2.4\",\n     \"typescript\": \"5.0.2\",\n-    \"uuid\": \"^9.0.0\",\n-    \"moment\": \"2.29.1\",\n-    \"lodash\": \"4.16.4\",\n-    \"mongoose\":\"5.10.10\"\n+    \"uuid\": \"^9.0.0\"\n   }\n-}\n\\ No newline at end of file\n+}\n",
			dependencyFileName: "package.json",
			aggregateFixes:     true,
		},
		{
			repoName:           "aggregate-no-vul",
			testDir:            "createfixpullrequests/aggregate-no-vul",
			configPath:         filepath.Join("testdata", "config", "frogbot-config-create-fix-pull-requests-aggregate-no-vul.yml"),
			expectedBranchName: "main", // No branch should be created
			expectedDiff:       "",
			dependencyFileName: "package.json",
			aggregateFixes:     true,
		},
		{
			repoName:           "aggregate-cant-fix",
			testDir:            "createfixpullrequests/aggregate-cant-fix",
			configPath:         filepath.Join("testdata", "config", "frogbot-config-create-fix-pull-requests-aggregate-cant-fix.yml"),
			expectedBranchName: "frogobt-9e636d7e3dfa13c96e213ca243758525",
			expectedDiff:       "",         // No diff expected
			dependencyFileName: "setup.py", // This is a build tool dependency which should not be fixed
			aggregateFixes:     true,
		},
		{
			repoName:           "non-aggregate",
			testDir:            "createfixpullrequests/non-aggregate",
			configPath:         filepath.Join("testdata", "config", "frogbot-config-create-fix-pull-requests-non-aggregate.yml"),
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
				PullRequestID:  0,
				AggregateFixes: test.aggregateFixes,
			}
			client, err := vcsclient.NewClientBuilder(vcsutils.GitHub).ApiEndpoint(server.URL).Token("123456").Build()
			assert.NoError(t, err)
			configData, err := utils.ReadConfigFromFileSystem(test.configPath)
			assert.NoError(t, err)
			envPath, cleanUp := utils.PrepareTestEnvironment(t, "", test.testDir)
			defer cleanUp()
			configAggregator, err := utils.BuildRepoAggregator(configData, &gitTestParams.ClientInfo, &serverParams)
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
			scanResponse, _, err := testScan.scan(&scanSetup, tmpDir)
			assert.NoError(t, err)
			verifyTechnologyNaming(t, scanResponse, pkg.packageType)
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
			fixDetails := &utils.FixDetails{FixVersion: "3.3.3", PackageType: tech, ImpactedDependency: impactedDependency, DirectDependency: true}
			err := testScan.updatePackageToFixedVersion(fixDetails)
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
	// Suppress condition always false warning
	//goland:noinspection ALL
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/c", "git", "diff", baseBranch, fixBranch, "--", dependencyFilename)
	} else {
		cmd = exec.Command("git", "diff", baseBranch, fixBranch, "--", dependencyFilename)
	}
	return cmd.Output()
}
