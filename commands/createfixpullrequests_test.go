package commands

import (
	testdatautils "github.com/jfrog/build-info-go/build/testdata"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/stretchr/testify/assert"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

type FixPackagesTestFunc func(test packageFixTest) error

type packageFixTest struct {
	commandArgs       []string
	technology        string
	impactedPackaged  string
	fixVersion        string
	operator          string
	packageDescriptor string
	fixPackageVersion func(test packageFixTest) error
}

var packageFixTests = []packageFixTest{
	{commandArgs: []string{"install"}, technology: coreutils.Npm, impactedPackaged: "minimatch", fixVersion: "3.0.2", operator: "@", packageDescriptor: "package.json", fixPackageVersion: getGenericFixPackageVersionFunc()},
	{commandArgs: []string{"get"}, technology: coreutils.Go, impactedPackaged: "github.com/sassoftware/go-rpmutils", fixVersion: "0.1.1", operator: "@v", packageDescriptor: "go.mod", fixPackageVersion: getGenericFixPackageVersionFunc()},
	{commandArgs: []string{"up"}, technology: strings.ToLower(coreutils.Yarn), impactedPackaged: "minimist", fixVersion: "1.2.6", operator: "@", packageDescriptor: "package.json", fixPackageVersion: getGenericFixPackageVersionFunc()},
	{commandArgs: []string{"install"}, technology: coreutils.Pipenv, impactedPackaged: "pyjwt", fixVersion: "2.4.0", operator: "==", packageDescriptor: "Pipfile", fixPackageVersion: getGenericFixPackageVersionFunc()},
	{technology: coreutils.Maven, impactedPackaged: "junit", fixVersion: "4.11", packageDescriptor: "pom.xml", fixPackageVersion: getMavenFixPackageVersionFunc()},
	{technology: coreutils.Pip, impactedPackaged: "pyjwt", fixVersion: "2.4.0", packageDescriptor: "requirements.txt", fixPackageVersion: getPipFixPackageVersionFunc()},
	{technology: coreutils.Pip, impactedPackaged: "pyjwt", fixVersion: "2.4.0", packageDescriptor: "setup.py", fixPackageVersion: getPipFixPackageVersionFunc()},
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

func getGenericFixPackageVersionFunc() FixPackagesTestFunc {
	return func(test packageFixTest) error {
		return fixPackageVersionGeneric(test.commandArgs, test.technology, test.impactedPackaged, test.fixVersion, test.operator)
	}
}

func getMavenFixPackageVersionFunc() FixPackagesTestFunc {
	return func(test packageFixTest) error {
		mavenDepToPropertyMap := map[string][]string{
			test.impactedPackaged: {"junit:junit", "3.8.1"},
		}
		cfp := CreateFixPullRequestsCmd{
			mavenDepToPropertyMap: mavenDepToPropertyMap,
		}
		return fixPackageVersionMaven(&cfp, test.impactedPackaged, test.fixVersion)
	}
}

func getPipFixPackageVersionFunc() FixPackagesTestFunc {
	return func(test packageFixTest) error {
		return fixPackageVersionPip(test.impactedPackaged, test.fixVersion, test.packageDescriptor)
	}
}

func TestFixPackageVersion(t *testing.T) {
	testdataDir, err := filepath.Abs(filepath.Join("testdata/projects"))
	assert.NoError(t, err)
	for _, test := range packageFixTests {
		// Create temp technology project
		projectPath := filepath.Join(testdataDir, test.technology)
		tmpProjectPath, cleanup := testdatautils.CreateTestProject(t, projectPath)
		defer cleanup()
		assert.NoError(t, os.Chdir(tmpProjectPath))
		t.Run(test.technology, func(t *testing.T) {
			// Fix impacted package for each technology
			assert.NoError(t, test.fixPackageVersion(test))
			file, err := os.ReadFile(test.packageDescriptor)
			assert.NoError(t, err)
			assert.Contains(t, string(file), test.fixVersion)
		})
	}
}

///      1.0         --> 1.0 ≤ x
///      (,1.0]      --> x ≤ 1.0
///      (,1.0)      --> x < 1.0
///      [1.0]       --> x == 1.0
///      (1.0,)      --> 1.0 < x
///      (1.0, 2.0)   --> 1.0 < x < 2.0
///      [1.0, 2.0]   --> 1.0 ≤ x ≤ 2.0
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
