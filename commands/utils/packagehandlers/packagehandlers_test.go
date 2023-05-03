package packagehandlers

import (
	testdatautils "github.com/jfrog/build-info-go/build/testdata"
	"github.com/jfrog/frogbot/commands/utils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/stretchr/testify/assert"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

type dependencyFixTest struct {
	fixVersionInfo *utils.FixDetails
	supportedFix   bool
}

type pythonIndirectDependencies struct {
	dependencyFixTest
	requirementsPath string
}

const requirementsFile = "oslo.config>=1.12.1,<1.13\noslo.utils<5.0,>=4.0.0\nparamiko==2.7.2\npasslib<=1.7.4\nprance>=0.9.0\nprompt-toolkit~=1.0.15\npyinotify>0.9.6\nPyJWT>1.7.1\nurllib3 > 1.1.9, < 1.5.*"

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

// Go handles direct and indirect the same, so we can have one test function
func TestGoPackageHandler_UpdateImpactedPackage(t *testing.T) {
	testdataDir := getTestDataDir(t, false)
	pgk := GoPackageHandler{}
	testcases := []dependencyFixTest{
		{
			fixVersionInfo: &utils.FixDetails{
				FixVersion:         "0.0.0-20201216223049-8b5274cf687f",
				PackageType:        coreutils.Go,
				DirectDependency:   false,
				ImpactedDependency: "golang.org/x/crypto",
			}, supportedFix: true,
		},
		{
			fixVersionInfo: &utils.FixDetails{
				FixVersion:         "1.7.7",
				PackageType:        coreutils.Go,
				DirectDependency:   true,
				ImpactedDependency: "github.com/gin-gonic/gin",
			}, supportedFix: true,
		},
		{
			fixVersionInfo: &utils.FixDetails{
				FixVersion:         "1.3.0",
				PackageType:        coreutils.Go,
				DirectDependency:   true,
				ImpactedDependency: "github.com/google/uuid",
			}, supportedFix: true,
		},
	}
	for _, test := range testcases {
		t.Run(test.fixVersionInfo.ImpactedDependency, func(t *testing.T) {
			cleanup := createTempDirAndChDir(t, testdataDir, coreutils.Go)
			defer cleanup()
			supportedFix, err := pgk.UpdateDependency(test.fixVersionInfo)
			assert.NoError(t, err)
			assert.Equal(t, test.supportedFix, supportedFix)
			assertFixVersionInPackageDescriptor(t, test, "go.mod")
			assert.NoError(t, os.Chdir(testdataDir))
		})
	}
}

// Maven
func TestMavenPackageHandler_updateIndirectDependency(t *testing.T) {
	testDataDir := getTestDataDir(t, false)
	mvn := MavenPackageHandler{mavenDepToPropertyMap: map[string][]string{"junit": {"junit:junit", "3.8.1"}}}
	tests := []dependencyFixTest{
		{fixVersionInfo: &utils.FixDetails{
			FixVersion:         "4.11",
			PackageType:        "maven",
			ImpactedDependency: "junit",
			DirectDependency:   false}, supportedFix: false},
	}
	for _, test := range tests {
		t.Run(test.fixVersionInfo.ImpactedDependency, func(t *testing.T) {
			cleanup := createTempDirAndChDir(t, testDataDir, coreutils.Maven)
			defer cleanup()
			supportedFix, err := mvn.UpdateDependency(test.fixVersionInfo)
			assert.NoError(t, err)
			assert.Equal(t, test.supportedFix, supportedFix)
			assert.NoError(t, os.Chdir(testDataDir))
		})
	}
}
func TestMavenPackageHandler_updateDirectDependency(t *testing.T) {
	testDataDir := getTestDataDir(t, true)
	mavenDepToPropertyMap := map[string][]string{
		"junit": {"junit:junit", "3.8.1"},
	}
	mvn := &MavenPackageHandler{mavenDepToPropertyMap: mavenDepToPropertyMap}
	tests := []dependencyFixTest{
		{fixVersionInfo: &utils.FixDetails{
			FixVersion:         "4.11",
			PackageType:        coreutils.Maven,
			ImpactedDependency: "junit",
			DirectDependency:   true}, supportedFix: true},
	}
	cleanup := createTempDirAndChDir(t, testDataDir, coreutils.Maven)
	defer cleanup()
	for _, test := range tests {
		t.Run(test.fixVersionInfo.ImpactedDependency, func(t *testing.T) {
			supportedFix, err := mvn.UpdateDependency(test.fixVersionInfo)
			assert.NoError(t, err)
			assert.Equal(t, test.supportedFix, supportedFix)
			assertFixVersionInPackageDescriptor(t, test, "pom.xml")
			assert.NoError(t, os.Chdir(testDataDir))
		})
	}
}

// Python, includes pip,pipenv, poetry
func TestPythonPackageHandler_updateIndirectDependency(t *testing.T) {
	testDataDir := getTestDataDir(t, false)
	testcases := []pythonIndirectDependencies{
		{
			dependencyFixTest: dependencyFixTest{
				fixVersionInfo: &utils.FixDetails{
					FixVersion:         "1.25.9",
					PackageType:        coreutils.Pip,
					ImpactedDependency: "urllib3",
					DirectDependency:   false}, supportedFix: false},
			requirementsPath: "requirements.txt",
		}, {
			dependencyFixTest: dependencyFixTest{
				fixVersionInfo: &utils.FixDetails{
					FixVersion:         "1.25.9",
					PackageType:        coreutils.Poetry,
					ImpactedDependency: "urllib3",
					DirectDependency:   false}, supportedFix: false},
			requirementsPath: "pyproejct.toml",
		}, {
			dependencyFixTest: dependencyFixTest{
				fixVersionInfo: &utils.FixDetails{
					FixVersion:         "1.25.9",
					PackageType:        coreutils.Pipenv,
					ImpactedDependency: "urllib3",
					DirectDependency:   false}, supportedFix: false},
			requirementsPath: "Pipfile",
		},
	}
	for _, test := range testcases {
		t.Run(test.fixVersionInfo.ImpactedDependency, func(t *testing.T) {
			packageHandler, err := GetCompatiblePackageHandler(test.fixVersionInfo, &utils.ScanDetails{
				Project: utils.Project{PipRequirementsFile: test.requirementsPath}}, nil)
			assert.NoError(t, err)
			cleanup := createTempDirAndChDir(t, testDataDir, test.fixVersionInfo.PackageType)
			defer cleanup()
			supportedFix, err := packageHandler.UpdateDependency(test.fixVersionInfo)
			assert.NoError(t, err)
			assert.Equal(t, test.supportedFix, supportedFix)
			assert.NoError(t, os.Chdir(testDataDir))
		})
	}
}
func TestPythonPackageHandler_updateDirectDependency(t *testing.T) {
	testDataDir := getTestDataDir(t, true)
	testcases := []pythonIndirectDependencies{
		{dependencyFixTest: dependencyFixTest{fixVersionInfo: &utils.FixDetails{
			FixVersion: "2.4.0", PackageType: coreutils.Pip, ImpactedDependency: "pyjwt", DirectDependency: true}, supportedFix: true}, requirementsPath: "requirements.txt"},
		{dependencyFixTest: dependencyFixTest{fixVersionInfo: &utils.FixDetails{
			FixVersion: "2.4.0", PackageType: coreutils.Pip, ImpactedDependency: "Pyjwt", DirectDependency: true}, supportedFix: true}, requirementsPath: "requirements.txt"},
		{dependencyFixTest: dependencyFixTest{fixVersionInfo: &utils.FixDetails{
			FixVersion: "2.4.0", PackageType: coreutils.Pip, ImpactedDependency: "pyjwt", DirectDependency: true}, supportedFix: true}, requirementsPath: "setup.py"},
		{dependencyFixTest: dependencyFixTest{fixVersionInfo: &utils.FixDetails{
			FixVersion: "23.1", PackageType: coreutils.Pip, ImpactedDependency: "pip", DirectDependency: true}, supportedFix: false}, requirementsPath: "setup.py"},
		{dependencyFixTest: dependencyFixTest{fixVersionInfo: &utils.FixDetails{
			FixVersion: "2.3.0", PackageType: coreutils.Pip, ImpactedDependency: "wheel", DirectDependency: true}, supportedFix: false}, requirementsPath: "setup.py"},
		{dependencyFixTest: dependencyFixTest{fixVersionInfo: &utils.FixDetails{
			FixVersion: "66.6.6", PackageType: coreutils.Pip, ImpactedDependency: "setuptools", DirectDependency: true}, supportedFix: false}, requirementsPath: "setup.py"},
		{dependencyFixTest: dependencyFixTest{fixVersionInfo: &utils.FixDetails{
			FixVersion: "2.4.0", PackageType: coreutils.Poetry, ImpactedDependency: "pyjwt", DirectDependency: true}, supportedFix: true}, requirementsPath: "pyproject.toml"},
		{dependencyFixTest: dependencyFixTest{fixVersionInfo: &utils.FixDetails{
			FixVersion: "2.4.0", PackageType: coreutils.Poetry, ImpactedDependency: "pyjwt", DirectDependency: true}, supportedFix: true}, requirementsPath: "pyproject.toml"},
	}
	for _, test := range testcases {
		t.Run(test.fixVersionInfo.ImpactedDependency, func(t *testing.T) {
			packageHandler, err := GetCompatiblePackageHandler(test.fixVersionInfo, &utils.ScanDetails{
				Project: utils.Project{PipRequirementsFile: test.requirementsPath}}, nil)
			assert.NoError(t, err)
			cleanup := createTempDirAndChDir(t, testDataDir, test.fixVersionInfo.PackageType)
			defer cleanup()
			supportedFix, err := packageHandler.UpdateDependency(test.fixVersionInfo)
			if test.supportedFix {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
				assertFixVersionInPackageDescriptor(t, test.dependencyFixTest, test.requirementsPath)
			}
			assert.Equal(t, test.supportedFix, supportedFix)
			assert.NoError(t, os.Chdir(testDataDir))
		})
	}
}
func TestPipPackageRegex(t *testing.T) {
	for _, pack := range pipPackagesRegexTests {
		re := regexp.MustCompile(PythonPackageRegexPrefix + "(" + pack.packageName + "|" + strings.ToLower(pack.packageName) + ")" + PythonPackageRegexSuffix)
		found := re.FindString(requirementsFile)
		assert.Equal(t, pack.expectedRequirement, strings.ToLower(found))
	}
}

// Npm

// Yarn

// Utils functions
func TestFixVersionInfo_UpdateFixVersion(t *testing.T) {
	type testCase struct {
		fixVersionInfo utils.FixDetails
		newFixVersion  string
		expectedOutput string
	}
	testCases := []testCase{
		{fixVersionInfo: utils.FixDetails{FixVersion: "1.2.3", PackageType: "pkg", DirectDependency: true}, newFixVersion: "1.2.4", expectedOutput: "1.2.4"},
		{fixVersionInfo: utils.FixDetails{FixVersion: "1.2.3", PackageType: "pkg", DirectDependency: true}, newFixVersion: "1.0.4", expectedOutput: "1.2.3"},
	}
	for _, tc := range testCases {
		t.Run(tc.expectedOutput, func(t *testing.T) {
			tc.fixVersionInfo.UpdateFixVersionIfMax(tc.newFixVersion)
			assert.Equal(t, tc.expectedOutput, tc.fixVersionInfo.FixVersion)
		})
	}
}

func getTestDataDir(t *testing.T, directDependency bool) string {
	var projectDir string
	if directDependency {
		projectDir = "projects"
	} else {
		projectDir = "indirect-projects"
	}
	testdataDir, err := filepath.Abs(filepath.Join("..", "..", "testdata/"+projectDir))
	assert.NoError(t, err)
	return testdataDir
}

func createTempDirAndChDir(t *testing.T, testdataDir string, tech coreutils.Technology) func() {
	// Create temp technology project
	projectPath := filepath.Join(testdataDir, tech.ToString())
	tmpProjectPath, cleanup := testdatautils.CreateTestProject(t, projectPath)
	assert.NoError(t, os.Chdir(tmpProjectPath))
	return cleanup
}

func assertFixVersionInPackageDescriptor(t *testing.T, test dependencyFixTest, packageDescriptor string) {
	file, err := os.ReadFile(packageDescriptor)
	assert.NoError(t, err)
	if !test.supportedFix {
		assert.NotContains(t, string(file), test.fixVersionInfo)
	} else {
		assert.Contains(t, string(file), test.fixVersionInfo.FixVersion)
		// Verify that case-sensitive packages in python are lowered
		assert.Contains(t, string(file), strings.ToLower(test.fixVersionInfo.ImpactedDependency))
	}
}
