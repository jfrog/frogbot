package packagehandlers

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jfrog/frogbot/v2/utils"
	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/stretchr/testify/assert"
)

func TestNpmGetVulnerabilityRegexCompiler(t *testing.T) {
	testcases := []struct {
		name        string
		packageName string
		version     string
		testContent string
		shouldMatch bool
	}{
		{
			name:        "exact version match",
			packageName: "minimist",
			version:     "1.2.5",
			testContent: `"minimist": "1.2.5"`,
			shouldMatch: true,
		},
		{
			name:        "version with caret prefix",
			packageName: "lodash",
			version:     "4.17.0",
			testContent: `"lodash": "^4.17.0"`,
			shouldMatch: true,
		},
		{
			name:        "version with tilde prefix",
			packageName: "express",
			version:     "4.18.0",
			testContent: `"express": "~4.18.0"`,
			shouldMatch: true,
		},
		{
			name:        "scoped package",
			packageName: "@types/node",
			version:     "18.0.0",
			testContent: `"@types/node": "18.0.0"`,
			shouldMatch: true,
		},
		{
			name:        "version mismatch",
			packageName: "minimist",
			version:     "1.2.5",
			testContent: `"minimist": "1.2.6"`,
			shouldMatch: false,
		},
		{
			name:        "package name mismatch",
			packageName: "minimist",
			version:     "1.2.5",
			testContent: `"minimatch": "1.2.5"`,
			shouldMatch: false,
		},
		{
			name:        "case insensitive package name",
			packageName: "Minimist",
			version:     "1.2.5",
			testContent: `"minimist": "1.2.5"`,
			shouldMatch: true,
		},
		{
			name:        "version with plus sign (build metadata)",
			packageName: "somepackage",
			version:     "1.0.0+build.123",
			testContent: `"somepackage": "1.0.0+build.123"`,
			shouldMatch: true,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			regex := GetVulnerabilityRegexCompiler(tc.packageName, tc.version, npmDependencyRegexpPattern)
			matches := regex.MatchString(strings.ToLower(tc.testContent))
			assert.Equal(t, tc.shouldMatch, matches, "Pattern: %s, Content: %s", regex.String(), tc.testContent)
		})
	}
}

func TestUpdateVersionInDescriptor(t *testing.T) {
	npm := &NpmPackageHandler{}

	testcases := []struct {
		name            string
		originalContent string
		packageName     string
		newVersion      string
		expectedContent string
		expectError     bool
	}{
		{
			name:            "update exact version",
			originalContent: `{"dependencies": {"minimist": "1.2.5"}}`,
			packageName:     "minimist",
			newVersion:      "1.2.6",
			expectedContent: `{"dependencies": {"minimist": "1.2.6"}}`,
			expectError:     false,
		},
		{
			name:            "update version with caret prefix - removes prefix",
			originalContent: `{"dependencies": {"lodash": "^4.17.0"}}`,
			packageName:     "lodash",
			newVersion:      "4.17.21",
			expectedContent: `{"dependencies": {"lodash": "4.17.21"}}`,
			expectError:     false,
		},
		{
			name:            "update version with tilde prefix - removes prefix",
			originalContent: `{"dependencies": {"express": "~4.18.0"}}`,
			packageName:     "express",
			newVersion:      "4.18.2",
			expectedContent: `{"dependencies": {"express": "4.18.2"}}`,
			expectError:     false,
		},
		{
			name:            "update scoped package",
			originalContent: `{"dependencies": {"@types/node": "18.0.0"}}`,
			packageName:     "@types/node",
			newVersion:      "18.11.0",
			expectedContent: `{"dependencies": {"@types/node": "18.11.0"}}`,
			expectError:     false,
		},
		{
			name:            "package not found",
			originalContent: `{"dependencies": {"lodash": "4.17.0"}}`,
			packageName:     "minimist",
			newVersion:      "1.2.6",
			expectedContent: "",
			expectError:     true,
		},
		{
			name: "preserve formatting with spaces",
			originalContent: `{
  "dependencies": {
    "minimist": "1.2.5"
  }
}`,
			packageName: "minimist",
			newVersion:  "1.2.6",
			expectedContent: `{
  "dependencies": {
    "minimist": "1.2.6"
  }
}`,
			expectError: false,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := npm.updateVersionInDescriptor([]byte(tc.originalContent), tc.packageName, tc.newVersion)

			if tc.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedContent, string(result))
			}
		})
	}
}

func TestBuildIsolatedEnv(t *testing.T) {
	npm := &NpmPackageHandler{}
	env := npm.buildIsolatedEnv()

	// Convert to map for easier checking
	envMap := make(map[string]string)
	for _, e := range env {
		parts := strings.SplitN(e, "=", 2)
		if len(parts) == 2 {
			envMap[parts[0]] = parts[1]
		}
	}

	// Verify all required env vars are set
	assert.Equal(t, "true", envMap[configIgnoreScriptsEnv])
	assert.Equal(t, "false", envMap[configAuditEnv])
	assert.Equal(t, "false", envMap[configFundEnv])
	assert.Equal(t, "error", envMap[configLevelEnv])
	assert.Equal(t, "true", envMap[ciEnv])
	assert.Equal(t, "1", envMap[noUpdateNotifierEnv])
}

func TestNpmGetDescriptorPathsFromVulnerability(t *testing.T) {
	npm := &NpmPackageHandler{}
	tmpDir, err := os.MkdirTemp("", "npm-descriptor-test-")
	assert.NoError(t, err)
	defer func() {
		assert.NoError(t, fileutils.RemoveTempDir(tmpDir))
	}()

	// Create a package.json in the temp directory
	packageJsonPath := filepath.Join(tmpDir, "package.json")
	assert.NoError(t, os.WriteFile(packageJsonPath, []byte(`{"name": "test"}`), 0644))

	// Create nested directory with package.json
	nestedDir := filepath.Join(tmpDir, "apps", "frontend")
	assert.NoError(t, os.MkdirAll(nestedDir, 0755))
	nestedPackageJsonPath := filepath.Join(nestedDir, "package.json")
	assert.NoError(t, os.WriteFile(nestedPackageJsonPath, []byte(`{"name": "frontend"}`), 0644))

	testcases := []struct {
		name          string
		vulnDetails   *utils.VulnerabilityDetails
		expectedPaths []string
		expectError   bool
		errorContains string
	}{
		{
			name: "derives package.json from package-lock.json path",
			vulnDetails: &utils.VulnerabilityDetails{
				VulnerabilityOrViolationRow: formats.VulnerabilityOrViolationRow{
					ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
						ImpactedDependencyName: "minimist",
						Components: []formats.ComponentRow{
							{Name: "minimist", Version: "1.2.5", Location: &formats.Location{File: filepath.Join(tmpDir, "package-lock.json")}},
						},
					},
				},
			},
			expectedPaths: []string{packageJsonPath},
			expectError:   false,
		},
		{
			name: "derives package.json from nested directory",
			vulnDetails: &utils.VulnerabilityDetails{
				VulnerabilityOrViolationRow: formats.VulnerabilityOrViolationRow{
					ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
						ImpactedDependencyName: "minimist",
						Components: []formats.ComponentRow{
							{Name: "minimist", Version: "1.2.5", Location: &formats.Location{File: filepath.Join(nestedDir, "package-lock.json")}},
						},
					},
				},
			},
			expectedPaths: []string{nestedPackageJsonPath},
			expectError:   false,
		},
		{
			name: "error when no location evidence found",
			vulnDetails: &utils.VulnerabilityDetails{
				VulnerabilityOrViolationRow: formats.VulnerabilityOrViolationRow{
					ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
						ImpactedDependencyName: "minimist",
						Components:             []formats.ComponentRow{},
					},
				},
			},
			expectedPaths: nil,
			expectError:   true,
			errorContains: "no location evidence was found",
		},
		{
			name: "error when descriptor file does not exist",
			vulnDetails: &utils.VulnerabilityDetails{
				VulnerabilityOrViolationRow: formats.VulnerabilityOrViolationRow{
					ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
						ImpactedDependencyName: "minimist",
						Components: []formats.ComponentRow{
							{Name: "minimist", Version: "1.2.5", Location: &formats.Location{File: "/nonexistent/path/package-lock.json"}},
						},
					},
				},
			},
			expectedPaths: nil,
			expectError:   true,
			errorContains: "not found for lock file",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := npm.getDescriptorsToFixFromVulnerability(tc.vulnDetails)
			if tc.expectError {
				assert.Error(t, err)
				if tc.errorContains != "" {
					assert.Contains(t, err.Error(), tc.errorContains)
				}
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.ElementsMatch(t, tc.expectedPaths, result)
			}
		})
	}
}
