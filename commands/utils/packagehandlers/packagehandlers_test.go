package packagehandlers

import (
	testdatautils "github.com/jfrog/build-info-go/build/testdata"
	"github.com/jfrog/frogbot/commands/utils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/stretchr/testify/assert"
	"os"
	"path/filepath"
	"testing"
)

type indirectDependencyFixTest struct {
	impactedPackage string
	fixVersionInfo  *utils.FixVersionInfo
	shouldFix       bool
}

type pythonIndirectDependencies struct {
	indirectDependencyFixTest
	requirementsPath     string
	pythonPackageManager coreutils.Technology
}

func TestFixVersionInfo_UpdateFixVersion(t *testing.T) {
	type testCase struct {
		fixVersionInfo utils.FixVersionInfo
		newFixVersion  string
		expectedOutput string
	}
	testCases := []testCase{
		{fixVersionInfo: utils.FixVersionInfo{FixVersion: "1.2.3", PackageType: "pkg", DirectDependency: true}, newFixVersion: "1.2.4", expectedOutput: "1.2.4"},
		{fixVersionInfo: utils.FixVersionInfo{FixVersion: "1.2.3", PackageType: "pkg", DirectDependency: true}, newFixVersion: "1.0.4", expectedOutput: "1.2.3"},
	}
	for _, tc := range testCases {
		t.Run(tc.expectedOutput, func(t *testing.T) {
			tc.fixVersionInfo.UpdateFixVersionIfMax(tc.newFixVersion)
			assert.Equal(t, tc.expectedOutput, tc.fixVersionInfo.FixVersion)
		})
	}
}

func TestGoPackageHandler_UpdateImpactedPackage(t *testing.T) {
	testdataDir := getTestDataDir(t)
	pgk := GoPackageHandler{}
	testcases := []indirectDependencyFixTest{
		{impactedPackage: "golang.org/x/crypto",
			fixVersionInfo: &utils.FixVersionInfo{
				FixVersion:       "0.0.0-20201216223049-8b5274cf687f",
				PackageType:      "go",
				DirectDependency: false,
			}, shouldFix: true,
		},
		{impactedPackage: "github.com/gin-gonic/gin",
			fixVersionInfo: &utils.FixVersionInfo{
				FixVersion:       "1.7.7",
				PackageType:      "go",
				DirectDependency: true,
			}, shouldFix: true,
		},
	}
	for _, test := range testcases {
		t.Run(test.impactedPackage, func(t *testing.T) {
			cleanup := createTempDirAndChDir(t, testdataDir, coreutils.Go)
			defer cleanup()
			shouldFix, err := pgk.UpdateImpactedPackage(test.impactedPackage, test.fixVersionInfo)
			assert.NoError(t, err)
			assert.Equal(t, test.shouldFix, shouldFix)
			assert.NoError(t, os.Chdir(testdataDir))
		})
	}
}

// Until implemented, Test we are not attempting to fix indirect dependencies in maven
func TestMavenPackageHandler_UpdateImpactedPackage(t *testing.T) {
	testDataDir := getTestDataDir(t)
	mvn := MavenPackageHandler{
		mavenDepToPropertyMap: map[string][]string{
			"junit": {"junit:junit", "3.8.1"},
		},
	}
	test := indirectDependencyFixTest{
		impactedPackage: "junit",
		fixVersionInfo: &utils.FixVersionInfo{
			FixVersion:       "4.11",
			PackageType:      "maven",
			DirectDependency: false,
		},
		shouldFix: false,
	}
	cleanup := createTempDirAndChDir(t, testDataDir, coreutils.Maven)
	defer cleanup()
	shouldFix, err := mvn.UpdateImpactedPackage(test.impactedPackage, test.fixVersionInfo)
	assert.NoError(t, err)
	assert.Equal(t, test.shouldFix, shouldFix)
	assert.NoError(t, os.Chdir(testDataDir))
}

// Until implemented, Test we are not attempting to fix indirect dependencies in python
func TestPythonPackageHandler_UpdateImpactedPackage(t *testing.T) {
	testDataDir := getTestDataDir(t)
	testcases := []pythonIndirectDependencies{
		{
			indirectDependencyFixTest: indirectDependencyFixTest{impactedPackage: "urllib3",
				fixVersionInfo: &utils.FixVersionInfo{
					FixVersion:       "1.25.9",
					PackageType:      "pip",
					DirectDependency: false}, shouldFix: false},
			requirementsPath:     "requirements.txt",
			pythonPackageManager: "pip",
		}, {
			indirectDependencyFixTest: indirectDependencyFixTest{impactedPackage: "urllib3",
				fixVersionInfo: &utils.FixVersionInfo{
					FixVersion:       "1.25.9",
					PackageType:      "poetry",
					DirectDependency: false}, shouldFix: false},
			requirementsPath:     "pyproejct.toml",
			pythonPackageManager: "poetry",
		}, {
			indirectDependencyFixTest: indirectDependencyFixTest{impactedPackage: "urllib3",
				fixVersionInfo: &utils.FixVersionInfo{
					FixVersion:       "1.25.9",
					PackageType:      "pipenv",
					DirectDependency: false}, shouldFix: false},
			requirementsPath:     "Pipfile",
			pythonPackageManager: "pipenv",
		},
	}
	for _, test := range testcases {
		t.Run(test.pythonPackageManager.ToString(), func(t *testing.T) {
			packageHandler := GetCompatiblePackageHandler(test.fixVersionInfo, &utils.ScanDetails{
				Project: utils.Project{PipRequirementsFile: test.requirementsPath}}, nil)
			cleanup := createTempDirAndChDir(t, testDataDir, test.fixVersionInfo.PackageType)
			defer cleanup()
			shouldFix, err := packageHandler.UpdateImpactedPackage(test.impactedPackage, test.fixVersionInfo)
			assert.NoError(t, err)
			assert.Equal(t, test.shouldFix, shouldFix)
			assert.NoError(t, os.Chdir(testDataDir))
		})
	}
}

func getTestDataDir(t *testing.T) string {
	testdataDir, err := filepath.Abs(filepath.Join("..", "..", "testdata/indirect-projects"))
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
