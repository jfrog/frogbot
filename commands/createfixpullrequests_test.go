package commands

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"

	testdatautils "github.com/jfrog/build-info-go/build/testdata"
	"github.com/jfrog/frogbot/commands/utils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-client-go/xray/services"
	"github.com/stretchr/testify/assert"
)

type FixPackagesTestFunc func(test packageFixTest) CreateFixPullRequestsCmd

type packageFixTest struct {
	technology           coreutils.Technology
	impactedPackaged     string
	fixVersion           string
	packageDescriptor    string
	fixPackageVersionCmd FixPackagesTestFunc
}

var packageFixTests = []packageFixTest{
	{technology: coreutils.Maven, impactedPackaged: "junit", fixVersion: "4.11", packageDescriptor: "pom.xml", fixPackageVersionCmd: getMavenFixPackageVersionFunc()},
	{technology: coreutils.Npm, impactedPackaged: "minimatch", fixVersion: "3.0.2", packageDescriptor: "package.json", fixPackageVersionCmd: getGenericFixPackageVersionFunc()},
	{technology: coreutils.Go, impactedPackaged: "github.com/google/uuid", fixVersion: "1.3.0", packageDescriptor: "go.mod", fixPackageVersionCmd: getGenericFixPackageVersionFunc()},
	{technology: coreutils.Yarn, impactedPackaged: "minimist", fixVersion: "1.2.6", packageDescriptor: "package.json", fixPackageVersionCmd: getGenericFixPackageVersionFunc()},
	{technology: coreutils.Pipenv, impactedPackaged: "pyjwt", fixVersion: "2.4.0", packageDescriptor: "Pipfile", fixPackageVersionCmd: getGenericFixPackageVersionFunc()},
	{technology: coreutils.Poetry, impactedPackaged: "pyjwt", fixVersion: "2.4.0", packageDescriptor: "pyproject.toml", fixPackageVersionCmd: getGenericFixPackageVersionFunc()},
	{technology: coreutils.Pip, impactedPackaged: "pyjwt", fixVersion: "2.4.0", packageDescriptor: "requirements.txt", fixPackageVersionCmd: getGenericFixPackageVersionFunc()},
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
	{"prance", "prance>=0.9.0"},
	{"prompt-toolkit", "prompt-toolkit~=1.0.15"},
	{"pyinotify", "pyinotify>0.9.6"},
	{"pyjwt", "PyJWT>1.7.1"},
	{"urllib3", "urllib3 > 1.1.9, < 1.5.*"},
}

var packageTypes = []coreutils.Technology{
	coreutils.Go,
	coreutils.Maven,
	coreutils.Npm,
	coreutils.Yarn,
	coreutils.Pip,
	coreutils.Pipenv,
	coreutils.Poetry,
}

func getGenericFixPackageVersionFunc() FixPackagesTestFunc {
	return func(test packageFixTest) CreateFixPullRequestsCmd {
		return CreateFixPullRequestsCmd{}
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
	for _, test := range packageFixTests {
		// Create temp technology project
		projectPath := filepath.Join(testdataDir, test.technology.ToString())
		tmpProjectPath, cleanup := testdatautils.CreateTestProject(t, projectPath)
		defer cleanup()
		assert.NoError(t, os.Chdir(tmpProjectPath))

		t.Run(test.technology.ToString(), func(t *testing.T) {
			cfg := test.fixPackageVersionCmd(test)
			// Fix impacted package for each technology
			assert.NoError(t, cfg.updatePackageToFixedVersion(test.technology, test.impactedPackaged, test.fixVersion, test.packageDescriptor, tmpProjectPath))
			file, err := os.ReadFile(test.packageDescriptor)
			assert.NoError(t, err)
			assert.Contains(t, string(file), test.fixVersion)
		})
	}
	assert.NoError(t, os.Chdir(currentDir))
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
		re := regexp.MustCompile(pythonPackageRegexPrefix + pack.packageName + pythonPackageRegexSuffix)
		found := re.FindString(requirementsFile)
		assert.Equal(t, pack.expectedRequirement, found)
	}
}

func TestPackageTypeFromScan(t *testing.T) {
	environmentVars, restoreEnv := verifyEnv(t)
	defer restoreEnv()
	var testScan CreateFixPullRequestsCmd
	params := utils.Params{
		Scan: utils.Scan{Projects: []utils.Project{{}}},
	}
	var frogbotParams = utils.FrogbotRepoConfig{
		Server: environmentVars,
		Params: params,
	}
	for _, pkgType := range packageTypes {
		// Create temp technology project
		projectPath := filepath.Join("testdata", "projects", pkgType.ToString())
		t.Run(pkgType.ToString(), func(t *testing.T) {
			frogbotParams.Projects[0].WorkingDirs = []string{projectPath}
			scanResponse, _, err := testScan.scan(frogbotParams.Projects[0], &frogbotParams.Server, services.XrayGraphScanParams{}, false, projectPath)
			assert.NoError(t, err)
			verifyTechnologyNaming(t, scanResponse, pkgType)
		})
	}
}

func TestGetMinimalFixVersion(t *testing.T) {
	impactedVersionPackage := "1.6.2"
	fixVersions := []string{"1.5.3", "1.6.1", "1.6.22", "1.7.0"}
	assert.Equal(t, "1.6.22", getMinimalFixVersion(impactedVersionPackage, fixVersions))
	impactedVersionPackageGo := "v" + impactedVersionPackage
	assert.Equal(t, "1.6.22", getMinimalFixVersion(impactedVersionPackageGo, fixVersions))
	impactedVersionPackage = "1.7.1"
	assert.Equal(t, "", getMinimalFixVersion(impactedVersionPackage, fixVersions))
}

func verifyTechnologyNaming(t *testing.T, scanResponse []services.ScanResponse, expectedType coreutils.Technology) {
	for _, resp := range scanResponse {
		for _, vulnerability := range resp.Vulnerabilities {
			assert.Equal(t, expectedType.ToString(), vulnerability.Technology)
		}
	}
}

func TestFormatGoVersion(t *testing.T) {
	formatGoCases := []struct {
		description     string
		impactedPackage string
		fixVersion      string
		expected        string
	}{
		{
			impactedPackage: "github.com/go-git/go-git",
			fixVersion:      "5.5.2",
			expected:        "github.com/go-git/go-git/v5",
			description:     "Validate adding /v5 to impacted package name",
		},
		{
			impactedPackage: "github.com/go-git/go-git",
			fixVersion:      "4.1.1",
			expected:        "github.com/go-git/go-git/v4",
			description:     "Validate adding /v4 to impacted package name",
		},
		{
			impactedPackage: "github.com/go-git/go-git",
			fixVersion:      "1.0.0",
			expected:        "github.com/go-git/go-git",
			description:     "Validate no string has been added",
		},
		{
			impactedPackage: "gopkg.in/ini",
			fixVersion:      "1.67.0",
			expected:        "gopkg.in/ini.v1",
			description:     "gopkg different separator",
		},
		{
			impactedPackage: "gopkg.in/ini",
			fixVersion:      "2.1.0",
			expected:        "gopkg.in/ini.v2",
			description:     "gopkg different separator",
		},
	}

	for _, tt := range formatGoCases {
		t.Run(tt.description, func(t *testing.T) {
			result, err := handleGoPackageSemanticVersionSuffix(tt.impactedPackage, tt.fixVersion)
			assert.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}
