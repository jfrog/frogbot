package commands

//import (
//	"github.com/jfrog/jfrog-cli-core/v2/xray/formats"
//	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
//	"github.com/jfrog/jfrog-client-go/utils/log"
//	"github.com/stretchr/testify/assert"
//	"os"
//	"path/filepath"
//	"testing"
//
//	"github.com/jfrog/frogbot/commands/utils"
//	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
//	"github.com/jfrog/jfrog-client-go/xray/services"
//)
//
//var testPackagesData = []struct {
//	packageType coreutils.Technology
//	commandName string
//	commandArgs []string
//}{
//	{
//		packageType: coreutils.Go,
//	},
//	{
//		packageType: coreutils.Maven,
//	},
//	{
//		packageType: coreutils.Gradle,
//	},
//	{
//		packageType: coreutils.Npm,
//		commandName: "npm",
//		commandArgs: []string{"install"},
//	},
//	{
//		packageType: coreutils.Yarn,
//		commandName: "yarn",
//		commandArgs: []string{"install"},
//	},
//	{
//		packageType: coreutils.Dotnet,
//		commandName: "dotnet",
//		commandArgs: []string{"restore"},
//	},
//	{
//		packageType: coreutils.Pip,
//	},
//	{
//		packageType: coreutils.Pipenv,
//	},
//	{
//		packageType: coreutils.Poetry,
//	},
//}
//
//// /      1.0         --> 1.0 ≤ x
//// /      (,1.0]      --> x ≤ 1.0
//// /      (,1.0)      --> x < 1.0
//// /      [1.0]       --> x == 1.0
//// /      (1.0,)      --> 1.0 < x
//// /      (1.0, 2.0)   --> 1.0 < x < 2.0
//// /      [1.0, 2.0]   --> 1.0 ≤ x ≤ 2.0
//func TestParseVersionChangeString(t *testing.T) {
//	tests := []struct {
//		versionChangeString string
//		expectedVersion     string
//	}{
//		{"1.2.3", "1.2.3"},
//		{"[1.2.3]", "1.2.3"},
//		{"[1.2.3, 2.0.0]", "1.2.3"},
//
//		{"(,1.2.3]", ""},
//		{"(,1.2.3)", ""},
//		{"(1.2.3,)", ""},
//		{"(1.2.3, 2.0.0)", ""},
//	}
//
//	for _, test := range tests {
//		t.Run(test.versionChangeString, func(t *testing.T) {
//			assert.Equal(t, test.expectedVersion, parseVersionChangeString(test.versionChangeString))
//		})
//	}
//}
//
//func TestGenerateFixBranchName(t *testing.T) {
//	tests := []struct {
//		baseBranch      string
//		impactedPackage string
//		fixVersion      string
//		expectedName    string
//	}{
//		{"dev", "gopkg.in/yaml.v3", "3.0.0", "frogbot-gopkg.in/yaml.v3-d61bde82dc594e5ccc5a042fe224bf7c"},
//		{"master", "gopkg.in/yaml.v3", "3.0.0", "frogbot-gopkg.in/yaml.v3-41405528994061bd108e3bbd4c039a03"},
//		{"dev", "replace:colons:colons", "3.0.0", "frogbot-replace_colons_colons-89e555131b4a70a32fe9d9c44d6ff0fc"},
//	}
//	gitManager := utils.GitManager{}
//	for _, test := range tests {
//		t.Run(test.expectedName, func(t *testing.T) {
//			branchName, err := gitManager.GenerateFixBranchName(test.baseBranch, test.impactedPackage, test.fixVersion)
//			assert.NoError(t, err)
//			assert.Equal(t, test.expectedName, branchName)
//		})
//	}
//}
//
//func TestPackageTypeFromScan(t *testing.T) {
//	environmentVars, restoreEnv := verifyEnv(t)
//	defer restoreEnv()
//	var testScan CreateFixPullRequestsCmd
//	trueVal := true
//	params := utils.Params{
//		Scan: utils.Scan{Projects: []utils.Project{{UseWrapper: &trueVal}}},
//	}
//	var frogbotParams = utils.Repository{
//		Server: environmentVars,
//		Params: params,
//	}
//	for _, pkg := range testPackagesData {
//		// Create temp technology project
//		projectPath := filepath.Join("testdata", "projects", pkg.packageType.ToString())
//		t.Run(pkg.packageType.ToString(), func(t *testing.T) {
//			tmpDir, err := fileutils.CreateTempDir()
//			assert.NoError(t, err)
//			defer func() {
//				assert.NoError(t, fileutils.RemoveTempDir(tmpDir))
//			}()
//			assert.NoError(t, fileutils.CopyDir(projectPath, tmpDir, true, nil))
//			if pkg.packageType == coreutils.Gradle {
//				assert.NoError(t, os.Chmod(filepath.Join(tmpDir, "gradlew"), 0777))
//				assert.NoError(t, os.Chmod(filepath.Join(tmpDir, "gradlew.bat"), 0777))
//			}
//			frogbotParams.Projects[0].WorkingDirs = []string{tmpDir}
//			files, err := fileutils.ListFiles(tmpDir, true)
//			assert.NoError(t, err)
//			for _, file := range files {
//				log.Info(file)
//			}
//			frogbotParams.Projects[0].InstallCommandName = pkg.commandName
//			frogbotParams.Projects[0].InstallCommandArgs = pkg.commandArgs
//			scanSetup := utils.ScanDetails{
//				XrayGraphScanParams: &services.XrayGraphScanParams{},
//				Project:             &frogbotParams.Projects[0],
//				ServerDetails:       &frogbotParams.Server,
//			}
//			testScan.details = &scanSetup
//			scanResponse, err := testScan.scan(tmpDir)
//			assert.NoError(t, err)
//			verifyTechnologyNaming(t, scanResponse.ExtendedScanResults.XrayResults, pkg.packageType)
//		})
//	}
//}
//
//func TestGetMinimalFixVersion(t *testing.T) {
//	tests := []struct {
//		impactedVersionPackage string
//		fixVersions            []string
//		expected               string
//	}{
//		{impactedVersionPackage: "1.6.2", fixVersions: []string{"1.5.3", "1.6.1", "1.6.22", "1.7.0"}, expected: "1.6.22"},
//		{impactedVersionPackage: "v1.6.2", fixVersions: []string{"1.5.3", "1.6.1", "1.6.22", "1.7.0"}, expected: "1.6.22"},
//		{impactedVersionPackage: "1.7.1", fixVersions: []string{"1.5.3", "1.6.1", "1.6.22", "1.7.0"}, expected: ""},
//		{impactedVersionPackage: "1.7.1", fixVersions: []string{"2.5.3"}, expected: "2.5.3"},
//		{impactedVersionPackage: "v1.7.1", fixVersions: []string{"0.5.3", "0.9.9"}, expected: ""},
//	}
//	for _, test := range tests {
//		t.Run(test.expected, func(t *testing.T) {
//			expected := getMinimalFixVersion(test.impactedVersionPackage, test.fixVersions)
//			assert.Equal(t, test.expected, expected)
//		})
//	}
//}
//
//// Verifies unsupported packages return specific error
//// Other logic is implemented inside each package-handler.
//func TestUpdatePackageToFixedVersion(t *testing.T) {
//	var testScan CreateFixPullRequestsCmd
//	for tech, buildToolsDependencies := range utils.BuildToolsDependenciesMap {
//		for _, impactedDependency := range buildToolsDependencies {
//			vulnDetails := &utils.VulnerabilityDetails{FixVersion: "3.3.3", VulnerabilityOrViolationRow: &formats.VulnerabilityOrViolationRow{Technology: tech, ImpactedDependencyName: impactedDependency}, IsDirectDependency: true}
//			err := testScan.updatePackageToFixedVersion(vulnDetails)
//			assert.Error(t, err, "Expected error to occur")
//			assert.IsType(t, &utils.ErrUnsupportedFix{}, err, "Expected unsupported fix error")
//		}
//	}
//}
//
//func verifyTechnologyNaming(t *testing.T, scanResponse []services.ScanResponse, expectedType coreutils.Technology) {
//	for _, resp := range scanResponse {
//		for _, vulnerability := range resp.Vulnerabilities {
//			assert.Equal(t, expectedType.ToString(), vulnerability.Technology)
//		}
//	}
//}
