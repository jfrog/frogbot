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

func TestNpmBuildPackageRegex(t *testing.T) {
	testcases := []struct {
		name        string
		packageName string
		testContent string
		shouldMatch bool
	}{
		{
			name:        "matches package with exact version format",
			packageName: "minimist",
			testContent: `"minimist": "1.2.5"`,
			shouldMatch: true,
		},
		{
			name:        "matches package with caret version format",
			packageName: "lodash",
			testContent: `"lodash": "^4.17.0"`,
			shouldMatch: true,
		},
		{
			name:        "matches package with tilde version format",
			packageName: "express",
			testContent: `"express": "~4.18.0"`,
			shouldMatch: true,
		},
		{
			name:        "matches scoped package",
			packageName: "@types/node",
			testContent: `"@types/node": "18.0.0"`,
			shouldMatch: true,
		},
		{
			name:        "matches package regardless of version value",
			packageName: "minimist",
			testContent: `"minimist": "1.2.6"`,
			shouldMatch: true,
		},
		{
			name:        "does not match similar package name",
			packageName: "minimist",
			testContent: `"minimatch": "1.2.5"`,
			shouldMatch: false,
		},
		{
			name:        "matches package case insensitively",
			packageName: "Minimist",
			testContent: `"minimist": "1.2.5"`,
			shouldMatch: true,
		},
		{
			name:        "matches package with build metadata in version",
			packageName: "somepackage",
			testContent: `"somepackage": "1.0.0+build.123"`,
			shouldMatch: true,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			regex := BuildPackageRegex(tc.packageName, npmDependencyRegexpPattern)
			matches := regex.MatchString(strings.ToLower(tc.testContent))
			assert.Equal(t, tc.shouldMatch, matches, "Pattern: %s, Content: %s", regex.String(), tc.testContent)
		})
	}
}

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

func TestBuildIsolatedEnv(t *testing.T) {
	npm := &NpmPackageUpdater{}
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
	npm := &NpmPackageUpdater{}
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

func TestFindAllowedSectionRanges(t *testing.T) {
	npm := &NpmPackageUpdater{}

	testcases := []struct {
		name           string
		content        string
		expectedRanges int
	}{
		{
			name: "single dependencies section",
			content: `{
  "name": "test",
  "dependencies": {
    "lodash": "4.17.21"
  }
}`,
			expectedRanges: 1,
		},
		{
			name: "multiple allowed sections",
			content: `{
  "name": "test",
  "dependencies": {
    "lodash": "4.17.21"
  },
  "devDependencies": {
    "jest": "29.0.0"
  },
  "optionalDependencies": {
    "fsevents": "2.3.2"
  }
}`,
			expectedRanges: 3,
		},
		{
			name: "all allowed sections including overrides",
			content: `{
  "dependencies": { "a": "1.0.0" },
  "devDependencies": { "b": "1.0.0" },
  "optionalDependencies": { "c": "1.0.0" },
  "overrides": { "d": "1.0.0" }
}`,
			expectedRanges: 4,
		},
		{
			name: "ignored sections only - peerDependencies",
			content: `{
  "name": "test",
  "peerDependencies": {
    "react": "^18.0.0"
  }
}`,
			expectedRanges: 0,
		},
		{
			name: "mixed allowed and ignored sections",
			content: `{
  "dependencies": {
    "lodash": "4.17.21"
  },
  "peerDependencies": {
    "react": "^18.0.0"
  },
  "devDependencies": {
    "jest": "29.0.0"
  }
}`,
			expectedRanges: 2,
		},
		{
			name:           "no sections at all",
			content:        `{"name": "test", "version": "1.0.0"}`,
			expectedRanges: 0,
		},
		{
			name: "nested braces within section",
			content: `{
  "dependencies": {
    "webpack": "5.0.0",
    "config": {
      "nested": "value"
    }
  }
}`,
			expectedRanges: 1,
		},
		{
			name: "section with string containing braces",
			content: `{
  "dependencies": {
    "lodash": "4.17.21"
  },
  "scripts": {
    "test": "echo \"{test}\""
  }
}`,
			expectedRanges: 1,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			ranges := npm.findAllowedSectionRanges([]byte(tc.content))
			assert.Len(t, ranges, tc.expectedRanges)

			for _, r := range ranges {
				assert.True(t, r.start >= 0, "start should be non-negative")
				assert.True(t, r.end > r.start, "end should be greater than start")
				assert.Equal(t, byte('{'), tc.content[r.start], "range should start with opening brace")
				assert.Equal(t, byte('}'), tc.content[r.end], "range should end with closing brace")
			}
		})
	}
}
