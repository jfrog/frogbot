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
	fixSupported   bool
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

func TestGoPackageHandler_UpdateDependency(t *testing.T) {
	goPackageHandler := GoPackageHandler{}
	testcases := []dependencyFixTest{
		{
			fixVersionInfo: &utils.FixDetails{
				FixVersion:         "0.0.0-20201216223049-8b5274cf687f",
				PackageType:        coreutils.Go,
				DirectDependency:   false,
				ImpactedDependency: "golang.org/x/crypto",
			}, fixSupported: true,
		},
		{
			fixVersionInfo: &utils.FixDetails{
				FixVersion:         "1.7.7",
				PackageType:        coreutils.Go,
				DirectDependency:   true,
				ImpactedDependency: "github.com/gin-gonic/gin",
			}, fixSupported: true,
		},
		{
			fixVersionInfo: &utils.FixDetails{
				FixVersion:         "1.3.0",
				PackageType:        coreutils.Go,
				DirectDependency:   true,
				ImpactedDependency: "github.com/google/uuid",
			}, fixSupported: true,
		},
	}
	for _, test := range testcases {
		t.Run(test.fixVersionInfo.ImpactedDependency, func(t *testing.T) {
			testDataDir := getTestDataDir(t, test.fixVersionInfo.DirectDependency)
			cleanup := createTempDirAndChDir(t, testDataDir, coreutils.Go)
			err := goPackageHandler.UpdateDependency(test.fixVersionInfo)
			if !test.fixSupported {
				assert.Error(t, err, "Expected error to occur")
				assert.IsType(t, &utils.ErrUnsupportedFix{}, err, "Expected unsupported fix error")
			} else {
				assert.NoError(t, err)
				assertFixVersionInPackageDescriptor(t, test, "go.mod")
			}
			assert.NoError(t, os.Chdir(testDataDir))
			cleanup()
		})
	}
}

// Maven
func TestMavenPackageHandler_UpdateDependency(t *testing.T) {
	mavenPackageHandler := MavenPackageHandler{mavenDepToPropertyMap: map[string][]string{"junit": {"junit:junit", "3.8.1"}}}
	tests := []dependencyFixTest{
		{fixVersionInfo: &utils.FixDetails{
			FixVersion:         "4.11",
			PackageType:        "maven",
			ImpactedDependency: "junit",
			DirectDependency:   false}, fixSupported: false},
		{fixVersionInfo: &utils.FixDetails{
			FixVersion:         "4.11",
			PackageType:        coreutils.Maven,
			ImpactedDependency: "junit",
			DirectDependency:   true}, fixSupported: true},
	}
	for _, test := range tests {
		t.Run(test.fixVersionInfo.ImpactedDependency, func(t *testing.T) {
			testDataDir := getTestDataDir(t, test.fixVersionInfo.DirectDependency)
			cleanup := createTempDirAndChDir(t, testDataDir, coreutils.Maven)
			err := mavenPackageHandler.UpdateDependency(test.fixVersionInfo)
			if !test.fixSupported {
				assert.Error(t, err, "Expected error to occur")
				assert.IsType(t, &utils.ErrUnsupportedFix{}, err, "Expected unsupported fix error")
			} else {
				assert.NoError(t, err)
			}
			assert.NoError(t, os.Chdir(testDataDir))
			cleanup()
		})
	}
}

// Python, includes pip,pipenv, poetry
func TestPythonPackageHandler_updateIndirectDependency(t *testing.T) {
	testcases := []pythonIndirectDependencies{
		{dependencyFixTest: dependencyFixTest{fixVersionInfo: &utils.FixDetails{
			FixVersion: "1.25.9", PackageType: coreutils.Pip, ImpactedDependency: "urllib3", DirectDependency: false}, fixSupported: false}, requirementsPath: "requirements.txt"},
		{dependencyFixTest: dependencyFixTest{fixVersionInfo: &utils.FixDetails{
			FixVersion: "1.25.9", PackageType: coreutils.Poetry, ImpactedDependency: "urllib3", DirectDependency: false}, fixSupported: false}, requirementsPath: "pyproejct.toml"},
		{dependencyFixTest: dependencyFixTest{fixVersionInfo: &utils.FixDetails{
			FixVersion: "1.25.9", PackageType: coreutils.Pipenv, ImpactedDependency: "urllib3", DirectDependency: false}, fixSupported: false}, requirementsPath: "Pipfile"},
		{dependencyFixTest: dependencyFixTest{fixVersionInfo: &utils.FixDetails{
			FixVersion: "2.4.0", PackageType: coreutils.Pip, ImpactedDependency: "pyjwt", DirectDependency: true}, fixSupported: true}, requirementsPath: "requirements.txt"},
		{dependencyFixTest: dependencyFixTest{fixVersionInfo: &utils.FixDetails{
			FixVersion: "2.4.0", PackageType: coreutils.Pip, ImpactedDependency: "Pyjwt", DirectDependency: true}, fixSupported: true}, requirementsPath: "requirements.txt"},
		{dependencyFixTest: dependencyFixTest{fixVersionInfo: &utils.FixDetails{
			FixVersion: "2.4.0", PackageType: coreutils.Pip, ImpactedDependency: "pyjwt", DirectDependency: true}, fixSupported: true}, requirementsPath: "setup.py"},
		{dependencyFixTest: dependencyFixTest{fixVersionInfo: &utils.FixDetails{
			FixVersion: "2.4.0", PackageType: coreutils.Poetry, ImpactedDependency: "pyjwt", DirectDependency: true}, fixSupported: true}, requirementsPath: "pyproject.toml"},
		{dependencyFixTest: dependencyFixTest{fixVersionInfo: &utils.FixDetails{
			FixVersion: "2.4.0", PackageType: coreutils.Poetry, ImpactedDependency: "pyjwt", DirectDependency: true}, fixSupported: true}, requirementsPath: "pyproject.toml"},
	}
	for _, test := range testcases {
		t.Run(test.fixVersionInfo.ImpactedDependency, func(t *testing.T) {
			testDataDir := getTestDataDir(t, test.fixVersionInfo.DirectDependency)
			pythonPackageHandler, err := GetCompatiblePackageHandler(test.fixVersionInfo, &utils.ScanDetails{
				Project: &utils.Project{PipRequirementsFile: test.requirementsPath}}, nil)
			assert.NoError(t, err)
			cleanup := createTempDirAndChDir(t, testDataDir, test.fixVersionInfo.PackageType)
			err = pythonPackageHandler.UpdateDependency(test.fixVersionInfo)
			if !test.fixSupported {
				assert.Error(t, err, "Expected error to occur")
				assert.IsType(t, &utils.ErrUnsupportedFix{}, err, "Expected unsupported fix error")
			} else {
				assert.NoError(t, err)
			}
			assert.NoError(t, os.Chdir(testDataDir))
			cleanup()
		})
	}
}

func TestPipPackageRegex(t *testing.T) {
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
	for _, pack := range pipPackagesRegexTests {
		re := regexp.MustCompile(PythonPackageRegexPrefix + "(" + pack.packageName + "|" + strings.ToLower(pack.packageName) + ")" + PythonPackageRegexSuffix)
		found := re.FindString(requirementsFile)
		assert.Equal(t, pack.expectedRequirement, strings.ToLower(found))
	}
}

// Npm
func TestNpmPackageHandler_UpdateDependency(t *testing.T) {
	npmPackageHandler := &NpmPackageHandler{}
	testcases := []dependencyFixTest{
		{
			fixVersionInfo: &utils.FixDetails{
				FixVersion:           "0.8.4",
				PackageType:          coreutils.Npm,
				DirectDependency:     false,
				ImpactedDependency:   "mpath",
				DirectDependencyName: "mongoose",
			}, fixSupported: true,
		},
		{
			fixVersionInfo: &utils.FixDetails{
				FixVersion:         "3.0.2",
				PackageType:        coreutils.Npm,
				DirectDependency:   true,
				ImpactedDependency: "minimatch",
			}, fixSupported: true,
		},
	}
	for _, test := range testcases {
		t.Run(test.fixVersionInfo.ImpactedDependency, func(t *testing.T) {
			testDataDir := getTestDataDir(t, test.fixVersionInfo.DirectDependency)
			cleanup := createTempDirAndChDir(t, testDataDir, coreutils.Npm)
			err := npmPackageHandler.UpdateDependency(test.fixVersionInfo)
			if !test.fixSupported {
				assert.Error(t, err, "Expected error to occur")
				assert.IsType(t, &utils.ErrUnsupportedFix{}, err, "Expected unsupported fix error")
			} else {
				assert.NoError(t, err)
			}
			assert.NoError(t, os.Chdir(testDataDir))
			cleanup()
		})
	}
}

// Yarn
func TestYarnPackageHandler_updateIndirectDependency(t *testing.T) {
	yarnPackageHandler := &YarnPackageHandler{}
	testcases := []dependencyFixTest{
		{
			fixVersionInfo: &utils.FixDetails{
				FixVersion:         "1.2.6",
				PackageType:        coreutils.Yarn,
				DirectDependency:   false,
				ImpactedDependency: "minimist",
			}, fixSupported: false,
		},
	}
	for _, test := range testcases {
		t.Run(test.fixVersionInfo.ImpactedDependency, func(t *testing.T) {
			testDataDir := getTestDataDir(t, test.fixVersionInfo.DirectDependency)
			cleanup := createTempDirAndChDir(t, testDataDir, coreutils.Yarn)
			err := yarnPackageHandler.UpdateDependency(test.fixVersionInfo)
			if !test.fixSupported {
				assert.Error(t, err, "Expected error to occur")
				assert.IsType(t, &utils.ErrUnsupportedFix{}, err, "Expected unsupported fix error")
			} else {
				assert.NoError(t, err)
			}
			assert.NoError(t, os.Chdir(testDataDir))
			cleanup()
		})
	}
}

func TestYarnPackageHandler_updateDirectDependency(t *testing.T) {
	yarnPackageHandler := &YarnPackageHandler{}
	testcases := []dependencyFixTest{
		{
			fixVersionInfo: &utils.FixDetails{
				FixVersion:         "1.2.6",
				PackageType:        coreutils.Yarn,
				DirectDependency:   true,
				ImpactedDependency: "minimist",
			}, fixSupported: true,
		},
	}
	for _, test := range testcases {
		t.Run(test.fixVersionInfo.ImpactedDependency, func(t *testing.T) {
			testDataDir := getTestDataDir(t, test.fixVersionInfo.DirectDependency)
			cleanup := createTempDirAndChDir(t, testDataDir, coreutils.Yarn)
			err := yarnPackageHandler.updateDirectDependency(test.fixVersionInfo)
			if !test.fixSupported {
				assert.Error(t, err, "Expected error to occur")
				assert.IsType(t, &utils.ErrUnsupportedFix{}, err, "Expected unsupported fix error")
			} else {
				assert.NoError(t, err)
			}
			assertFixVersionInPackageDescriptor(t, test, "package.json")
			assert.NoError(t, os.Chdir(testDataDir))
			cleanup()
		})
	}
}

// Utils functions
func TestFixVersionInfo_UpdateFixVersionIfMax(t *testing.T) {
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
func TestNpmPackageHandler_passesConstraint(t *testing.T) {
	type testCase struct {
		constraintVersion string
		candidateVersion  string
		expected          bool
	}
	testCases := []testCase{
		{constraintVersion: "^1.2.2", candidateVersion: "1.2.3", expected: true},
		{constraintVersion: ">0.7.0", candidateVersion: "0.8.4", expected: true},
		{constraintVersion: "^1.2.2", candidateVersion: "1.2.1", expected: false},
		{constraintVersion: "~1.2.2", candidateVersion: "2.2.3", expected: false},
		{constraintVersion: "~1.2.2", candidateVersion: "1.3.0", expected: false},
		{constraintVersion: "1.x", candidateVersion: "1.2.3", expected: true},
		{constraintVersion: "1.x", candidateVersion: "2.2.3", expected: false},
		{constraintVersion: "~1.3.7", candidateVersion: "1.3.8", expected: true},
	}
	for _, tc := range testCases {
		t.Run(tc.constraintVersion, func(t *testing.T) {
			ok, _, err := passesConstraint(tc.constraintVersion, tc.candidateVersion)
			assert.NoError(t, err)
			assert.Equal(t, tc.expected, ok)
		})
	}
}
func TestNpmPackageHandler_ExtractOriginalConstraint(t *testing.T) {
	type testCase struct {
		constraintVersion string
		constraintString  string
	}
	testCases := []testCase{
		{constraintVersion: "^1.2.2", constraintString: "^"},
		{constraintVersion: "^1.2.2", constraintString: "^"},
		{constraintVersion: "~1.2.2", constraintString: "~"},
		{constraintVersion: "~1.2.2", constraintString: "~"},
		{constraintVersion: ">=1.3.7", constraintString: ">="},
		{constraintVersion: "<=1.3.7", constraintString: "<="},
		{constraintVersion: "<1.3.7", constraintString: "<"},
		{constraintVersion: "1.3.7", constraintString: ""},
		{constraintVersion: "", constraintString: ""},
	}
	for _, tc := range testCases {
		t.Run(tc.constraintVersion, func(t *testing.T) {
			constraintString := extractOriginalConstraint(tc.constraintVersion)
			assert.Equal(t, tc.constraintString, constraintString)
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
	if !test.fixSupported {
		assert.NotContains(t, string(file), test.fixVersionInfo)
	} else {
		assert.Contains(t, string(file), test.fixVersionInfo.FixVersion)
		// Verify that case-sensitive packages in python are lowered
		assert.Contains(t, string(file), strings.ToLower(test.fixVersionInfo.ImpactedDependency))
	}
}
