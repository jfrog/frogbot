package packageupdaters

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	biutils "github.com/jfrog/build-info-go/utils"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
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

func TestNpmCollectVulnerabilityDescriptorPaths_filtersCoordinateEvidence(t *testing.T) {
	t.Parallel()
	npm := &NpmPackageUpdater{}
	vuln := createVulnerabilityDetails(techutils.Npm, "lodash", "4.17.19", "4.17.21", true,
		"lodash@4.17.19/package.json", "minimist@1.2.5/package.json", "package.json")
	paths := npm.CollectVulnerabilityDescriptorPaths(vuln, []string{nodePackageJSONFileName}, []string{nodeModulesDirName})
	assert.ElementsMatch(t, []string{"package.json"}, paths)
}

func skipUnlessNpmRunnable(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("requires npm and network for lockfile regeneration")
	}
	if _, err := exec.LookPath("npm"); err != nil {
		t.Skip("npm not on PATH:", err)
	}
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH:", err)
	}
	if err := exec.Command("npm", "--version").Run(); err != nil {
		t.Skip("npm not runnable:", err)
	}
}

func TestNpmUpdateDependency_directFix_filtersCoordinateEvidence(t *testing.T) {
	skipUnlessNpmRunnable(t)

	testRootDir, err := os.Getwd()
	assert.NoError(t, err)

	tmpDir, err := os.MkdirTemp("", "")
	defer func() {
		assert.NoError(t, fileutils.RemoveTempDir(tmpDir))
	}()
	assert.NoError(t, err)
	assert.NoError(t, biutils.CopyDir(filepath.Join("..", "testdata", "projects", "npm"), tmpDir, true, nil))
	initTestGitRepo(t, tmpDir, "package.json", "package-lock.json")

	assert.NoError(t, os.Chdir(tmpDir))
	defer func() {
		assert.NoError(t, os.Chdir(testRootDir))
	}()

	vuln := createVulnerabilityDetails(techutils.Npm, "minimist", "1.2.5", "1.2.6", true,
		"minimist@1.2.5/package.json", "lodash@4.17.19/package.json", "package.json")

	npm := &NpmPackageUpdater{}
	assert.NoError(t, npm.UpdateDependency(vuln))

	manifest, err := os.ReadFile("package.json")
	assert.NoError(t, err)
	assert.Contains(t, string(manifest), "\"minimist\": \"1.2.6\"")
	assert.NotContains(t, string(manifest), "\"minimist\": \"1.2.5\"")
}
