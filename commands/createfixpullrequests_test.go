package commands

import (
	testdatautils "github.com/jfrog/build-info-go/build/testdata"
	"github.com/jfrog/frogbot/commands/utils/packagehandlers"
	"github.com/jfrog/jfrog-cli-core/v2/xray/formats"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/stretchr/testify/assert"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/jfrog/frogbot/commands/utils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-client-go/xray/services"
)

type FixPackagesTestFunc func(test packageFixTest) CreateFixPullRequestsCmd

type packageFixTest struct {
	technology           coreutils.Technology
	impactedPackaged     string
	fixVersion           string
	packageDescriptor    string
	testPath             string
	fixPackageVersionCmd FixPackagesTestFunc
}

var packageFixTests = []packageFixTest{
	{technology: coreutils.Maven, impactedPackaged: "junit", fixVersion: "4.11", packageDescriptor: "pom.xml", fixPackageVersionCmd: getMavenFixPackageVersionFunc()},
	{technology: coreutils.Npm, impactedPackaged: "minimatch", fixVersion: "3.0.2", packageDescriptor: "package.json", fixPackageVersionCmd: getGenericFixPackageVersionFunc()},
	{technology: coreutils.Go, impactedPackaged: "github.com/google/uuid", fixVersion: "1.3.0", packageDescriptor: "go.mod", fixPackageVersionCmd: getGenericFixPackageVersionFunc()},
	{technology: coreutils.Yarn, impactedPackaged: "minimist", fixVersion: "1.2.6", packageDescriptor: "package.json", fixPackageVersionCmd: getGenericFixPackageVersionFunc()},
	{technology: coreutils.Pipenv, impactedPackaged: "pyjwt", fixVersion: "2.4.0", packageDescriptor: "Pipfile", fixPackageVersionCmd: getGenericFixPackageVersionFunc()},
	{technology: coreutils.Pipenv, impactedPackaged: "Pyjwt", fixVersion: "2.4.0", packageDescriptor: "Pipfile", fixPackageVersionCmd: getGenericFixPackageVersionFunc()},
	{technology: coreutils.Poetry, impactedPackaged: "pyjwt", fixVersion: "2.4.0", packageDescriptor: "pyproject.toml", fixPackageVersionCmd: getGenericFixPackageVersionFunc()},
	{technology: coreutils.Poetry, impactedPackaged: "Pyjwt", fixVersion: "2.4.0", packageDescriptor: "pyproject.toml", fixPackageVersionCmd: getGenericFixPackageVersionFunc()},
	{technology: coreutils.Pip, impactedPackaged: "pyjwt", fixVersion: "2.4.0", packageDescriptor: "requirements.txt", fixPackageVersionCmd: getGenericFixPackageVersionFunc()},
	{technology: coreutils.Pip, impactedPackaged: "PyJwt", fixVersion: "2.4.0", packageDescriptor: "requirements.txt", fixPackageVersionCmd: getGenericFixPackageVersionFunc()},
	{technology: coreutils.Pip, impactedPackaged: "pyjwt", fixVersion: "2.4.0", packageDescriptor: "setup.py", fixPackageVersionCmd: getGenericFixPackageVersionFunc()},
}

var requirementsFile = "oslo.config>=1.12.1,<1.13\noslo.utils<5.0,>=4.0.0\nparamiko==2.7.2\npasslib<=1.7.4\nprance>=0.9.0\nprompt-toolkit~=1.0.15\npyinotify>0.9.6\nPyJWT>1.7.1\nurllib3 > 1.1.9, < 1.5.*"

type pipPackageRegexTest struct {
	packageName         string
	expectedRequirement string
}

var pipPackagesRegexTests = []pipPackageRegexTest{
	{"oslo.config", "oslo.config>=1.12.1,<1.13"},
	{"oslo.utils", "oslo.utils<5.0,>=4.0.0"},
	{"paramiko", "paramiko==2.7.2"},
	{"passlib", "passlib<=1.7.4"},
	{"PassLib", "passlib<=1.7.4"},
	{"prance", "prance>=0.9.0"},
	{"prompt-toolkit", "prompt-toolkit~=1.0.15"},
	{"pyinotify", "pyinotify>0.9.6"},
	{"pyjwt", "pyjwt>1.7.1"},
	{"PyJWT", "pyjwt>1.7.1"},
	{"urllib3", "urllib3 > 1.1.9, < 1.5.*"},
}

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

func getGenericFixPackageVersionFunc() FixPackagesTestFunc {
	return func(test packageFixTest) CreateFixPullRequestsCmd {
		return CreateFixPullRequestsCmd{
			details: &utils.ScanDetails{
				Project: utils.Project{
					PipRequirementsFile: test.packageDescriptor,
					WorkingDirs:         []string{test.testPath},
				},
			},
		}
	}
}

func getMavenFixPackageVersionFunc() func(test packageFixTest) CreateFixPullRequestsCmd {
	return func(test packageFixTest) CreateFixPullRequestsCmd {
		mavenDepToPropertyMap := map[string][]string{
			test.impactedPackaged: {"junit:junit", "3.8.1"},
		}
		cfp := CreateFixPullRequestsCmd{
			mavenDepToPropertyMap: mavenDepToPropertyMap,
		}
		return cfp
	}
}

func TestFixPackageVersion(t *testing.T) {
	currentDir, testdataDir := getTestDataDir(t)
	defer func() {
		assert.NoError(t, os.Chdir(currentDir))
	}()

	for _, test := range packageFixTests {
		func() {
			// Create temp technology project
			projectPath := filepath.Join(testdataDir, test.technology.ToString())
			tmpProjectPath, cleanup := testdatautils.CreateTestProject(t, projectPath)
			defer cleanup()
			test.testPath = tmpProjectPath
			assert.NoError(t, os.Chdir(tmpProjectPath))

			t.Run(test.technology.ToString(), func(t *testing.T) {
				cfg := test.fixPackageVersionCmd(test)
				// Fix impacted package for each technology
				fixVersionInfo := utils.NewFixVersionInfo(test.fixVersion, test.technology, true)
				assert.NoError(t, cfg.updatePackageToFixedVersion(test.impactedPackaged, fixVersionInfo))
				file, err := os.ReadFile(test.packageDescriptor)
				assert.NoError(t, err)
				assert.Contains(t, string(file), test.fixVersion)
				// Verify that case-sensitive packages in python are lowered
				assert.Contains(t, string(file), strings.ToLower(test.impactedPackaged))
			})
			t.Run(test.technology.ToString(), func(t *testing.T) {
				cfg := test.fixPackageVersionCmd(test)
				// Fix indirect dependency for each technology
				fixVersionInfo := utils.NewFixVersionInfo(test.fixVersion, test.technology, false)
				assert.NoError(t, cfg.updatePackageToFixedVersion(test.impactedPackaged, fixVersionInfo))
			})
		}()
	}
}
func getTestDataDir(t *testing.T) (string, string) {
	currentDir, err := os.Getwd()
	assert.NoError(t, err)
	testdataDir, err := filepath.Abs(filepath.Join("testdata/projects"))
	assert.NoError(t, err)
	return currentDir, testdataDir
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

	for _, test := range tests {
		t.Run(test.expectedName, func(t *testing.T) {
			branchName, err := generateFixBranchName(test.baseBranch, test.impactedPackage, test.fixVersion)
			assert.NoError(t, err)
			assert.Equal(t, test.expectedName, branchName)
		})
	}
}

func TestPipPackageRegex(t *testing.T) {
	for _, pack := range pipPackagesRegexTests {
		re := regexp.MustCompile(packagehandlers.PythonPackageRegexPrefix + "(" + pack.packageName + "|" + strings.ToLower(pack.packageName) + ")" + packagehandlers.PythonPackageRegexSuffix)
		found := re.FindString(requirementsFile)
		assert.Equal(t, pack.expectedRequirement, strings.ToLower(found))
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
	var frogbotParams = utils.FrogbotRepoConfig{
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
				XrayGraphScanParams: services.XrayGraphScanParams{},
				Project:             frogbotParams.Projects[0],
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
		{impactedVersionPackage: "1.7.1", fixVersions: []string{"2.5.3"}, expected: ""},
		{impactedVersionPackage: "v1.7.1", fixVersions: []string{"0.5.3", "0.9.9"}, expected: ""},
	}
	for _, test := range tests {
		t.Run(test.expected, func(t *testing.T) {
			expected := getMinimalFixVersion(test.impactedVersionPackage, test.fixVersions)
			assert.Equal(t, test.expected, expected)
		})
	}
}

func Test_createFixVersionsMap(t *testing.T) {
	var testScan CreateFixPullRequestsCmd
	packageName := "pkg"
	tests := []struct {
		vulnerability *formats.VulnerabilityOrViolationRow
		expected      map[string]*utils.FixVersionInfo
		description   string
	}{
		{
			vulnerability: &formats.VulnerabilityOrViolationRow{
				FixedVersions:             []string{"1.9.3", "1.2.2"},
				ImpactedDependencyVersion: "1.2.1",
				ImpactedDependencyName:    packageName,
				ImpactPaths:               [][]formats.ComponentRow{{}, {}},
			}, expected: map[string]*utils.FixVersionInfo{packageName: {FixVersion: "1.9.3", DirectDependency: true}},
			description: "Get the bigger version",
		}, {
			vulnerability: &formats.VulnerabilityOrViolationRow{
				FixedVersions:             []string{"2.0.0", "0.1.5"},
				ImpactedDependencyVersion: "1.2.1",
				ImpactedDependencyName:    packageName,
				ImpactPaths:               [][]formats.ComponentRow{{}, {}},
			}, expected: map[string]*utils.FixVersionInfo{packageName: {FixVersion: "", DirectDependency: true}},
			description: "Don't suggest major changes fixes",
		}, {
			vulnerability: &formats.VulnerabilityOrViolationRow{
				FixedVersions:             []string{"1.1.0", "1.1.4"},
				ImpactedDependencyVersion: "1.1.5",
				ImpactedDependencyName:    packageName,
				ImpactPaths:               [][]formats.ComponentRow{{}, {}},
			}, expected: map[string]*utils.FixVersionInfo{packageName: {FixVersion: "1.1.4", DirectDependency: true}},
			description: "Suggest smallest downgrade",
		},
	}
	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			fixVersionsMap := map[string]*utils.FixVersionInfo{}
			err := testScan.addVulnerabilityToFixVersionsMap(test.vulnerability, fixVersionsMap)
			assert.NoError(t, err)
			if len(fixVersionsMap) != 0 {
				assert.Equal(t, *test.expected[packageName], *fixVersionsMap[packageName])
			}
		})
	}

}

func verifyTechnologyNaming(t *testing.T, scanResponse []services.ScanResponse, expectedType coreutils.Technology) {
	for _, resp := range scanResponse {
		for _, vulnerability := range resp.Vulnerabilities {
			assert.Equal(t, expectedType.ToString(), vulnerability.Technology)
		}
	}
}
