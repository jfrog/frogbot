package utils

import (
	"github.com/stretchr/testify/assert"
	"path/filepath"
	"testing"
)

func TestCreateResultsContext(t *testing.T) {
	testCases := []struct {
		name                   string
		httpCloneUrl           string
		watches                []string
		jfrogProjectKey        string
		includeVulnerabilities bool
		includeLicenses        bool
	}{
		{
			name:                   "Violations and Vulnerabilities",
			httpCloneUrl:           "http://localhost:8080/my-user/my-project.git",
			watches:                []string{"watch-1", "watch-2"},
			jfrogProjectKey:        "project",
			includeVulnerabilities: true,
			includeLicenses:        true,
		},
		{
			name:                   "Violations - Project key",
			httpCloneUrl:           "",
			watches:                nil,
			jfrogProjectKey:        "project",
			includeVulnerabilities: false,
			includeLicenses:        true,
		},
		{
			name:                   "Violations - Watches",
			httpCloneUrl:           "",
			watches:                []string{"watch-1", "watch-2"},
			jfrogProjectKey:        "",
			includeVulnerabilities: false,
			includeLicenses:        false,
		},
		{
			name:                   "Violations - GitInfoContext",
			httpCloneUrl:           "http://localhost:8080/my-user/my-project.git",
			watches:                nil,
			jfrogProjectKey:        "",
			includeVulnerabilities: false,
			includeLicenses:        false,
		},
		{
			name:                   "Vulnerabilities",
			httpCloneUrl:           "",
			watches:                nil,
			jfrogProjectKey:        "",
			includeVulnerabilities: true,
			includeLicenses:        true,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			scanDetails := &ScanDetails{}
			scanDetails.SetResultsContext(testCase.httpCloneUrl, testCase.watches, testCase.jfrogProjectKey, testCase.includeVulnerabilities, testCase.includeLicenses)
			assert.Equal(t, testCase.httpCloneUrl, scanDetails.XscGitInfoContext.GitRepoHttpsCloneUrl)
			assert.Equal(t, testCase.watches, scanDetails.Watches)
			assert.Equal(t, testCase.jfrogProjectKey, scanDetails.ProjectKey)
			assert.Equal(t, testCase.includeVulnerabilities, scanDetails.IncludeVulnerabilities)
			assert.Equal(t, testCase.includeLicenses, scanDetails.IncludeLicenses)
		})
	}
}

func TestGetFullPathWorkingDirs(t *testing.T) {
	sampleProject := Project{
		WorkingDirs: []string{filepath.Join("a", "b"), filepath.Join("a", "b", "c"), ".", filepath.Join("c", "d", "e", "f")},
	}
	baseWd := "tempDir"
	fullPathWds := GetFullPathWorkingDirs(sampleProject.WorkingDirs, baseWd)
	expectedWds := []string{filepath.Join("tempDir", "a", "b"), filepath.Join("tempDir", "a", "b", "c"), "tempDir", filepath.Join("tempDir", "c", "d", "e", "f")}
	for _, expectedWd := range expectedWds {
		assert.Contains(t, fullPathWds, expectedWd)
	}
}
