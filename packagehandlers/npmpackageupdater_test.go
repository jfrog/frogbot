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

func TestGetFixedDescriptor(t *testing.T) {
	npm := &NpmPackageUpdater{}

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
			name:            "update in devDependencies",
			originalContent: `{"devDependencies": {"minimist": "1.2.5"}}`,
			packageName:     "minimist",
			newVersion:      "1.2.6",
			expectedContent: `{"devDependencies": {"minimist": "1.2.6"}}`,
			expectError:     false,
		},
		{
			name:            "update in optionalDependencies",
			originalContent: `{"optionalDependencies": {"minimist": "1.2.5"}}`,
			packageName:     "minimist",
			newVersion:      "1.2.6",
			expectedContent: `{"optionalDependencies": {"minimist": "1.2.6"}}`,
			expectError:     false,
		},
		{
			name:            "update in overrides section",
			originalContent: `{"dependencies": {"express": "4.18.0"}, "overrides": {"minimist": "1.2.5"}}`,
			packageName:     "minimist",
			newVersion:      "1.2.6",
			expectedContent: `{"dependencies": {"express": "4.18.0"}, "overrides": {"minimist": "1.2.6"}}`,
			expectError:     false,
		},
		{
			name:            "update in both dependencies and overrides",
			originalContent: `{"dependencies": {"minimist": "1.2.5"}, "overrides": {"minimist": "1.2.5"}}`,
			packageName:     "minimist",
			newVersion:      "1.2.6",
			expectedContent: `{"dependencies": {"minimist": "1.2.6"}, "overrides": {"minimist": "1.2.6"}}`,
			expectError:     false,
		},
		{
			name:            "skip peerDependencies section - package only in peerDependencies",
			originalContent: `{"dependencies": {"express": "4.18.0"}, "peerDependencies": {"minimist": "1.2.5"}}`,
			packageName:     "minimist",
			newVersion:      "1.2.6",
			expectedContent: "",
			expectError:     true,
		},
		{
			name:            "skip peerDependencies section - package in both dependencies and peerDependencies",
			originalContent: `{"dependencies": {"minimist": "1.2.5"}, "peerDependencies": {"minimist": "1.2.5"}}`,
			packageName:     "minimist",
			newVersion:      "1.2.6",
			expectedContent: `{"dependencies": {"minimist": "1.2.6"}, "peerDependencies": {"minimist": "1.2.5"}}`,
			expectError:     false,
		},
		{
			name:            "update in multiple allowed sections",
			originalContent: `{"dependencies": {"minimist": "1.2.5"}, "devDependencies": {"minimist": "1.2.5"}}`,
			packageName:     "minimist",
			newVersion:      "1.2.6",
			expectedContent: `{"dependencies": {"minimist": "1.2.6"}, "devDependencies": {"minimist": "1.2.6"}}`,
			expectError:     false,
		},
		{
			name:            "package name with dot",
			originalContent: `{"dependencies": {"vue.config": "1.0.0"}}`,
			packageName:     "vue.config",
			newVersion:      "2.0.0",
			expectedContent: `{"dependencies": {"vue.config": "2.0.0"}}`,
			expectError:     false,
		},
		{
			name:            "no dependency sections",
			originalContent: `{"name": "test", "version": "1.0.0"}`,
			packageName:     "minimist",
			newVersion:      "1.2.6",
			expectedContent: "",
			expectError:     true,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := npm.getFixedDescriptor([]byte(tc.originalContent), tc.packageName, tc.newVersion, "package.json")

			if tc.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedContent, string(result))
			}
		})
	}
}

func TestEscapeJsonPathKey(t *testing.T) {
	testcases := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "simple package name",
			input:    "lodash",
			expected: "lodash",
		},
		{
			name:     "scoped package",
			input:    "@types/node",
			expected: "@types/node",
		},
		{
			name:     "package with dot",
			input:    "vue.config",
			expected: "vue\\.config",
		},
		{
			name:     "package with multiple dots",
			input:    "some.package.name",
			expected: "some\\.package\\.name",
		},
		{
			name:     "package with asterisk",
			input:    "package*name",
			expected: "package\\*name",
		},
		{
			name:     "package with question mark",
			input:    "package?name",
			expected: "package\\?name",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			result := escapeJsonPathKey(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestBuildIsolatedEnv(t *testing.T) {
	testcases := []struct {
		name         string
		predefineEnv bool
	}{
		{
			name:         "sets required env vars",
			predefineEnv: false,
		},
		{
			name:         "overrides conflicting user env vars",
			predefineEnv: true,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.predefineEnv {
				originalCI := os.Getenv(ciEnv)
				defer func() {
					assert.NoError(t, os.Setenv(ciEnv, originalCI))
				}()
				assert.NoError(t, os.Setenv(ciEnv, "false"))
			}

			npm := &NpmPackageUpdater{}
			env := npm.buildIsolatedEnv()

			envMap := make(map[string]string)
			envCount := make(map[string]int)
			for _, e := range env {
				parts := strings.SplitN(e, "=", 2)
				if len(parts) == 2 {
					envMap[parts[0]] = parts[1]
					envCount[parts[0]]++
				}
			}

			assert.Equal(t, "true", envMap[configIgnoreScriptsEnv])
			assert.Equal(t, "false", envMap[configAuditEnv])
			assert.Equal(t, "false", envMap[configFundEnv])
			assert.Equal(t, "error", envMap[configLevelEnv])
			assert.Equal(t, "true", envMap[ciEnv])

			if tc.predefineEnv {
				assert.Equal(t, 1, envCount[ciEnv], "CI should appear exactly once")
			}
		})
	}
}

func TestGetDescriptorsToFixFromVulnerability(t *testing.T) {
	npm := &NpmPackageUpdater{}
	tmpDir, err := os.MkdirTemp("", "npm-descriptor-test-")
	assert.NoError(t, err)
	defer func() {
		assert.NoError(t, fileutils.RemoveTempDir(tmpDir))
	}()

	packageJsonPath := filepath.Join(tmpDir, "package.json")
	assert.NoError(t, os.WriteFile(packageJsonPath, []byte(`{"name": "test"}`), 0644))

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
