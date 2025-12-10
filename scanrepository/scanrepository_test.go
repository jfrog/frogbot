package scanrepository

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/protocol/packp"
	"github.com/go-git/go-git/v5/plumbing/protocol/packp/capability"

	"github.com/jfrog/jfrog-cli-security/utils/xsc"

	"github.com/google/go-github/v45/github"
	biutils "github.com/jfrog/build-info-go/utils"
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/froggit-go/vcsutils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray/services"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jfrog/frogbot/v2/utils"
	"github.com/jfrog/frogbot/v2/utils/outputwriter"
)

const rootTestDir = "scanrepository"

var testPackagesData = []struct {
	packageType string
	commandName string
	commandArgs []string
}{
	{
		packageType: techutils.Go.String(),
	},
	{
		packageType: techutils.Maven.String(),
	},
	{
		packageType: techutils.Gradle.String(),
	},
	{
		packageType: techutils.Npm.String(),
		commandName: "npm",
		commandArgs: []string{"install"},
	},
	{
		packageType: "yarn1",
		commandName: "yarn",
		commandArgs: []string{"install"},
	},
	{
		packageType: "yarn2",
		commandName: "yarn",
		commandArgs: []string{"install"},
	},
	{
		packageType: techutils.Dotnet.String(),
		commandName: "dotnet",
		commandArgs: []string{"restore"},
	},
	{
		packageType: techutils.Nuget.String(),
		commandName: "nuget",
		commandArgs: []string{"restore"},
	},
	{
		packageType: techutils.Pip.String(),
	},
	{
		packageType: techutils.Pipenv.String(),
	},
	{
		packageType: techutils.Poetry.String(),
	},
}

func TestScanRepositoryCmd_Run(t *testing.T) {
	tests := []struct {
		testName                       string
		expectedPackagesInBranch       map[string][]string
		expectedVersionUpdatesInBranch map[string][]string
		expectedMissingFilesInBranch   map[string][]string
		packageDescriptorPaths         []string
		aggregateFixes                 bool
		allowPartialResults            bool
	}{
		{
			testName:                       "aggregate",
			expectedPackagesInBranch:       map[string][]string{"frogbot-update-68d9dee2475e5986e783d85dfa11baa0-dependencies-master": {"uuid", "minimist", "mpath"}},
			expectedVersionUpdatesInBranch: map[string][]string{"frogbot-update-68d9dee2475e5986e783d85dfa11baa0-dependencies-master": {"^1.2.6", "^9.0.0", "^0.8.4"}},
			packageDescriptorPaths:         []string{"package.json"},
			aggregateFixes:                 true,
		},
		{
			testName:                       "aggregate-multi-dir",
			expectedPackagesInBranch:       map[string][]string{"frogbot-update-68d9dee2475e5986e783d85dfa11baa0-dependencies-master": {"uuid", "minimatch", "mpath", "minimist"}},
			expectedVersionUpdatesInBranch: map[string][]string{"frogbot-update-68d9dee2475e5986e783d85dfa11baa0-dependencies-master": {"^1.2.6", "^9.0.0", "^0.8.4", "^3.0.5"}},
			expectedMissingFilesInBranch:   map[string][]string{"frogbot-update-68d9dee2475e5986e783d85dfa11baa0-dependencies-master": {"npm1/package-lock.json", "npm2/package-lock.json"}},
			packageDescriptorPaths:         []string{"npm1/package.json", "npm2/package.json"},
			aggregateFixes:                 true,
		},
		{
			testName: "aggregate-no-vul",
			// No branch is being created because there are no vulnerabilities.
			expectedPackagesInBranch:       map[string][]string{"master": {}},
			expectedVersionUpdatesInBranch: map[string][]string{"master": {}},
			packageDescriptorPaths:         []string{"package.json"},
			aggregateFixes:                 true,
		},
		{
			testName: "aggregate-cant-fix",
			// Branch name stays master as no new branch is being created
			expectedPackagesInBranch:       map[string][]string{"master": {}},
			expectedVersionUpdatesInBranch: map[string][]string{"master": {}},
			// This is a build tool dependency which should not be fixed.
			packageDescriptorPaths: []string{"setup.py"},
			aggregateFixes:         true,
		},
		{
			testName:                       "non-aggregate",
			expectedPackagesInBranch:       map[string][]string{"frogbot-minimist-258ad6a538b5ba800f18ae4f6d660302": {"minimist"}},
			expectedVersionUpdatesInBranch: map[string][]string{"frogbot-minimist-258ad6a538b5ba800f18ae4f6d660302": {"^1.2.6"}},
			packageDescriptorPaths:         []string{"package.json"},
			aggregateFixes:                 false,
		},
		{
			// This testcase checks the partial results feature. It simulates a failure in the dependency tree construction in the test's project inner module
			testName:                       "partial-results-enabled",
			expectedPackagesInBranch:       map[string][]string{"frogbot-update-68d9dee2475e5986e783d85dfa11baa0-dependencies-master": {"minimist", "mpath"}},
			expectedVersionUpdatesInBranch: map[string][]string{"frogbot-update-68d9dee2475e5986e783d85dfa11baa0-dependencies-master": {"1.2.6", "0.8.4"}},
			packageDescriptorPaths:         []string{"package.json", "inner-project/package.json"},
			aggregateFixes:                 true,
			allowPartialResults:            true,
		},
	}
	baseDir, err := os.Getwd()
	assert.NoError(t, err)
	testDir, cleanup := utils.CopyTestdataProjectsToTemp(t, filepath.Join(rootTestDir, "cmd"))
	defer cleanup()
	for _, test := range tests {
		t.Run(test.testName, func(t *testing.T) {
			// Prepare
			serverParams, _ := utils.VerifyEnv(t)
			xrayVersion, xscVersion, err := xsc.GetJfrogServicesVersion(&serverParams)
			assert.NoError(t, err)

			var port string
			server := httptest.NewServer(createScanRepoGitHubHandler(t, &port, nil, test.testName))
			defer server.Close()
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

			// Manual set of "JF_GIT_BASE_BRANCH"
			gitTestParams.Branches = []string{"master"}

			utils.CreateDotGitWithCommit(t, testDir, port, test.testName)
			config, err := utils.BuildRepository(xrayVersion, xscVersion, client, &gitTestParams, &serverParams, utils.ScanRepository)
			assert.NoError(t, err)
			// Run
			var cmd = ScanRepositoryCmd{XrayVersion: xrayVersion, XscVersion: xscVersion, dryRun: true, dryRunRepoPath: testDir}
			err = cmd.Run(config, client, utils.MockHasConnection())
			defer func() {
				assert.NoError(t, os.Chdir(baseDir))
			}()

			// Validate
			assert.NoError(t, err)
			for branch, packages := range test.expectedPackagesInBranch {
				resultDiff, err := verifyDependencyFileDiff("master", branch, test.packageDescriptorPaths...)
				assert.NoError(t, err)
				if len(packages) > 0 {
					assert.NotEmpty(t, resultDiff)
				}
				for _, packageToUpdate := range packages {
					assert.Contains(t, string(resultDiff), packageToUpdate)
				}
				packageVersionUpdatesInBranch := test.expectedVersionUpdatesInBranch[branch]
				for _, updatedVersion := range packageVersionUpdatesInBranch {
					assert.Contains(t, string(resultDiff), updatedVersion)
				}
			}

			if len(test.expectedMissingFilesInBranch) > 0 {
				for branch, expectedMissingFiles := range test.expectedMissingFilesInBranch {
					resultDiff, err := verifyLockFileDiff(branch, expectedMissingFiles...)
					assert.NoError(t, err)
					assert.Empty(t, resultDiff)
				}
			}
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
	userLogin := "user"
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
				User: &github.User{Login: &userLogin},
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
				User: &github.User{Login: &userLogin},
				Body: &secondBody,
			}},
		},
	}

	baseDir, err := os.Getwd()
	assert.NoError(t, err)
	serverParams, restoreEnv := utils.VerifyEnv(t)
	defer restoreEnv()
	testDir, cleanup := utils.CopyTestdataProjectsToTemp(t, filepath.Join(rootTestDir, "aggregate-pr-lifecycle"))
	defer cleanup()
	xrayVersion, xscVersion, err := xsc.GetJfrogServicesVersion(&serverParams)
	assert.NoError(t, err)
	for _, test := range tests {
		t.Run(test.testName, func(t *testing.T) {
			var port string
			server := httptest.NewServer(createScanRepoGitHubHandler(t, &port, test.mockPullRequestResponse, test.testName))
			defer server.Close()
			port = server.URL[strings.LastIndex(server.URL, ":")+1:]
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
			gitTestParams.Branches = []string{"master"}
			repoConfig, err := utils.BuildRepository(xrayVersion, xscVersion, client, gitTestParams, &serverParams, utils.ScanRepository)
			assert.NoError(t, err)
			// Run
			var cmd = ScanRepositoryCmd{dryRun: true, dryRunRepoPath: testDir}
			err = cmd.Run(repoConfig, client, utils.MockHasConnection())
			defer func() {
				assert.NoError(t, os.Chdir(baseDir))
			}()
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
	xrayVersion, xscVersion, err := xsc.GetJfrogServicesVersion(&environmentVars)
	assert.NoError(t, err)

	testScan := &ScanRepositoryCmd{OutputWriter: &outputwriter.StandardOutput{}}
	params := utils.Params{
		Scan: utils.Scan{},
	}
	var frogbotParams = utils.Repository{
		Server: environmentVars,
		Params: params,
	}
	for _, pkg := range testPackagesData {
		// Create temp technology project
		projectPath := filepath.Join("..", "testdata", "projects", pkg.packageType)
		t.Run(pkg.packageType, func(t *testing.T) {
			tmpDir, err := fileutils.CreateTempDir()
			defer func() {
				err = fileutils.RemoveTempDir(tmpDir)
			}()
			assert.NoError(t, err)
			assert.NoError(t, biutils.CopyDir(projectPath, tmpDir, true, nil))
			if pkg.packageType == techutils.Gradle.String() {
				assert.NoError(t, os.Chmod(filepath.Join(tmpDir, "gradlew"), 0777))
				assert.NoError(t, os.Chmod(filepath.Join(tmpDir, "gradlew.bat"), 0777))
			}
			files, err := fileutils.ListFiles(tmpDir, true)
			assert.NoError(t, err)
			for _, file := range files {
				log.Info(file)
			}
			scanSetup := utils.ScanDetails{
				XrayVersion:   xrayVersion,
				XscVersion:    xscVersion,
				ServerDetails: &frogbotParams.Server,
			}
			testScan.scanDetails = &scanSetup
			scanResponse, err := testScan.scan()
			require.NoError(t, err)
			verifyTechnologyNaming(t, scanResponse.GetScaScansXrayResults(), pkg.packageType)
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
		name        string
		scanResults *results.SecurityCommandResults
		expectedMap map[string]*utils.VulnerabilityDetails
	}{
		{
			name: "Scan results with no violations and vulnerabilities",
			scanResults: &results.SecurityCommandResults{Targets: []*results.TargetResults{{
				ScanTarget: results.ScanTarget{Target: "target1"},
			}}},
			expectedMap: map[string]*utils.VulnerabilityDetails{},
		},
		{
			name: "Scan results with vulnerabilities and no violations",
			scanResults: &results.SecurityCommandResults{
				ResultsMetaData: results.ResultsMetaData{
					ResultContext: results.ResultContext{IncludeVulnerabilities: true}},
				Targets: []*results.TargetResults{{
					ScanTarget: results.ScanTarget{Target: "target1"},
					ScaResults: &results.ScaScanResults{},
					JasResults: &results.JasScansResults{},
				}},
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
			scanResults: &results.SecurityCommandResults{
				ResultsMetaData: results.ResultsMetaData{
					ResultContext: results.ResultContext{IncludeVulnerabilities: true, Watches: []string{"w1"}}},
				Targets: []*results.TargetResults{{
					ScanTarget: results.ScanTarget{Target: "target1"},
					ScaResults: &results.ScaScanResults{},
					JasResults: &results.JasScansResults{},
				}},
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
			fixVersionsMap, err := cfp.createVulnerabilitiesMap(testCase.scanResults)
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
			vulnDetails := &utils.VulnerabilityDetails{SuggestedFixedVersion: "3.3.3", VulnerabilityOrViolationRow: formats.VulnerabilityOrViolationRow{Technology: tech, ImpactedDependencyDetails: formats.ImpactedDependencyDetails{ImpactedDependencyName: impactedDependency}}, IsDirectDependency: true}
			err := testScan.updatePackageToFixedVersion(vulnDetails)
			assert.Error(t, err, "Expected error to occur")
			assert.IsType(t, &utils.ErrUnsupportedFix{}, err, "Expected unsupported fix error")
		}
	}
}

func TestGetRemoteBranchScanHash(t *testing.T) {
	prBody := `
a body

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
	cfp.OutputWriter.SetJasOutputFlags(true, false)
	vulnerabilities := []*utils.VulnerabilityDetails{
		{
			VulnerabilityOrViolationRow: formats.VulnerabilityOrViolationRow{
				Summary: "summary",
				ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
					SeverityDetails:           formats.SeverityDetails{Severity: "High", SeverityNumValue: 10},
					ImpactedDependencyName:    "package1",
					ImpactedDependencyVersion: "1.0.0",
				},
				FixedVersions: []string{"1.0.0", "2.0.0"},
				Cves:          []formats.CveRow{{Id: "CVE-2022-1234"}},
			},
			SuggestedFixedVersion: "1.0.0",
		},
	}
	expectedPrBody, expectedExtraComments := utils.GenerateFixPullRequestDetails(utils.ExtractVulnerabilitiesDetailsToRows(vulnerabilities), cfp.OutputWriter)
	prTitle, prBody, extraComments, err := cfp.preparePullRequestDetails(vulnerabilities...)
	assert.NoError(t, err)
	assert.Equal(t, "[🐸 Frogbot] Update version of package1 to 1.0.0", prTitle)
	assert.Equal(t, expectedPrBody, prBody)
	assert.ElementsMatch(t, expectedExtraComments, extraComments)
	vulnerabilities = append(vulnerabilities, &utils.VulnerabilityDetails{
		VulnerabilityOrViolationRow: formats.VulnerabilityOrViolationRow{
			Summary: "summary",
			ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
				SeverityDetails:           formats.SeverityDetails{Severity: "Critical", SeverityNumValue: 12},
				ImpactedDependencyName:    "package2",
				ImpactedDependencyVersion: "2.0.0",
			},
			FixedVersions: []string{"2.0.0", "3.0.0"},
			Cves:          []formats.CveRow{{Id: "CVE-2022-4321"}},
		},
		SuggestedFixedVersion: "2.0.0",
	})
	cfp.aggregateFixes = true
	expectedPrBody, expectedExtraComments = utils.GenerateFixPullRequestDetails(utils.ExtractVulnerabilitiesDetailsToRows(vulnerabilities), cfp.OutputWriter)
	expectedPrBody += outputwriter.MarkdownComment("Checksum: bec823edaceb5d0478b789798e819bde")
	prTitle, prBody, extraComments, err = cfp.preparePullRequestDetails(vulnerabilities...)
	assert.NoError(t, err)
	assert.Equal(t, cfp.gitManager.GenerateAggregatedPullRequestTitle([]techutils.Technology{}), prTitle)
	assert.Equal(t, expectedPrBody, prBody)
	assert.ElementsMatch(t, expectedExtraComments, extraComments)
	cfp.OutputWriter = &outputwriter.SimplifiedOutput{}
	expectedPrBody, expectedExtraComments = utils.GenerateFixPullRequestDetails(utils.ExtractVulnerabilitiesDetailsToRows(vulnerabilities), cfp.OutputWriter)
	expectedPrBody += outputwriter.MarkdownComment("Checksum: bec823edaceb5d0478b789798e819bde")
	prTitle, prBody, extraComments, err = cfp.preparePullRequestDetails(vulnerabilities...)
	assert.NoError(t, err)
	assert.Equal(t, cfp.gitManager.GenerateAggregatedPullRequestTitle([]techutils.Technology{}), prTitle)
	assert.Equal(t, expectedPrBody, prBody)
	assert.ElementsMatch(t, expectedExtraComments, extraComments)
}

// This test simulates the cleaning action of cleanNewFilesMissingInRemote.
// Every file that has been newly CREATED after cloning the repo (here - after creating .git repo) should be removed. Every other file should be kept.
func TestCleanNewFilesMissingInRemote(t *testing.T) {
	testCases := []struct {
		name                 string
		relativeTestDirPath  string
		createFileBeforeInit bool
	}{
		{
			name:                 "new_file_should_remain",
			relativeTestDirPath:  filepath.Join(rootTestDir, "cmd", "aggregate"),
			createFileBeforeInit: true,
		},
		{
			name:                 "new_file_should_be_deleted",
			relativeTestDirPath:  filepath.Join(rootTestDir, "cmd", "aggregate"),
			createFileBeforeInit: false,
		},
	}

	baseDir, outerErr := os.Getwd()
	assert.NoError(t, outerErr)
	defer func() {
		assert.NoError(t, os.Chdir(baseDir))
	}()

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			testDir, cleanup := utils.CopyTestdataProjectsToTemp(t, test.relativeTestDirPath)
			defer cleanup()

			var file *os.File
			if test.createFileBeforeInit {
				var fileError error
				file, fileError = os.CreateTemp(testDir, test.name)
				assert.NoError(t, fileError)
			}

			utils.CreateDotGitWithCommit(t, testDir, "1234", "")

			if !test.createFileBeforeInit {
				var fileError error
				file, fileError = os.CreateTemp(testDir, test.name)
				assert.NoError(t, fileError)
			}

			// Making a change in the file so it will be modified in the working tree
			_, err := file.WriteString("My initial string")
			assert.NoError(t, err)
			assert.NoError(t, file.Close())

			scanRepoCmd := ScanRepositoryCmd{baseWd: testDir}
			assert.NoError(t, scanRepoCmd.cleanNewFilesMissingInRemote())

			exists, err := fileutils.IsFileExists(file.Name(), false)
			assert.NoError(t, err)
			if test.createFileBeforeInit {
				assert.True(t, exists)
			} else {
				assert.False(t, exists)
			}
		})
	}

}

func verifyTechnologyNaming(t *testing.T, scanResponse []services.ScanResponse, expectedType string) {
	for _, resp := range scanResponse {
		for _, vulnerability := range resp.Vulnerabilities {
			assert.Equal(t, expectedType, vulnerability.Technology)
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

func verifyLockFileDiff(branchToInspect string, lockFiles ...string) (output []byte, err error) {
	log.Debug(fmt.Sprintf("Checking lock files differences in %s between branches 'master' and '%s'", lockFiles, branchToInspect))
	// Suppress condition always false warning
	//goland:noinspection ALL
	var args []string
	if coreutils.IsWindows() {
		args = []string{"/c", "git", "ls-tree", branchToInspect, "--"}
		args = append(args, lockFiles...)
		output, err = exec.Command("cmd", args...).Output()
	} else {
		args = []string{"ls-tree", branchToInspect, "--"}
		args = append(args, lockFiles...)
		output, err = exec.Command("git", args...).Output()
	}
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		err = errors.New("git error: " + string(exitError.Stderr))
	}
	return
}

func createScanRepoGitHubHandler(t *testing.T, port *string, response interface{}, projectNames ...string) http.HandlerFunc {
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
			if r.RequestURI == fmt.Sprintf("/repos/jfrog/%s/commits?page=1&per_page=%d&sha=master", projectName, vcsutils.NumberOfCommitsToFetch) {
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
			if r.RequestURI == fmt.Sprintf("/repos/jfrog/%s/pulls?state=open", projectName) {
				jsonResponse, err := json.Marshal(response)
				assert.NoError(t, err)
				_, err = w.Write(jsonResponse)
				assert.NoError(t, err)
				return
			}
			if r.RequestURI == fmt.Sprintf("/repos/jfrog/%s", projectName) {
				jsonResponse := `{"id": 1296269,"node_id": "MDEwOlJlcG9zaXRvcnkxMjk2MjY5","name": "Hello-World","full_name": "octocat/Hello-World","private": false,"description": "This your first repo!","ssh_url": "git@github.com:octocat/Hello-World.git","clone_url": "https://github.com/octocat/Hello-World.git","visibility": "public"}`
				_, err := w.Write([]byte(jsonResponse))
				assert.NoError(t, err)
				return
			}
		}
	}
}
