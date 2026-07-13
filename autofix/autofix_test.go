package autofix

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jfrog/jfrog-cli-security/utils/techutils"
)

func TestValidateInputs(t *testing.T) {
	tests := []struct {
		name            string
		componentName   string
		affectedVersion string
		fixVersion      string
		expectError     bool
		errorContains   []string
		errorMissing    []string
	}{
		{
			name:            "all present",
			componentName:   "com.example:lib",
			affectedVersion: "1.0.0",
			fixVersion:      "1.0.1",
		},
		{
			name:          "missing all",
			expectError:   true,
			errorContains: []string{componentNameEnv, affectedVersionEnv, fixVersionEnv},
		},
		{
			name:            "missing fix version only",
			componentName:   "com.example:lib",
			affectedVersion: "1.0.0",
			expectError:     true,
			errorContains:   []string{fixVersionEnv},
			errorMissing:    []string{componentNameEnv},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateInputs(tc.componentName, tc.affectedVersion, tc.fixVersion)
			if tc.expectError {
				require.Error(t, err)
				for _, s := range tc.errorContains {
					assert.Contains(t, err.Error(), s)
				}
				for _, s := range tc.errorMissing {
					assert.NotContains(t, err.Error(), s)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestGenerateAutoFixBranchName(t *testing.T) {
	tests := []struct {
		name          string
		componentName string
		fixVersion    string
		notContains   []string
		maxLen        int
	}{
		{
			name:          "basic — colon replaced",
			componentName: "com.example:lib",
			fixVersion:    "1.0.1",
			notContains:   []string{":"},
		},
		{
			name:          "special chars sanitized",
			componentName: "@scope/pkg",
			fixVersion:    "2.0.0",
			notContains:   []string{"@", "/scope/"},
		},
		{
			name:          "long name truncated",
			componentName: strings.Repeat("a", 300),
			fixVersion:    "1.0.0",
			maxLen:        255,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			name := generateAutoFixBranchName(tc.componentName, tc.fixVersion)
			assert.True(t, strings.HasPrefix(name, autoFixBranchPrefix+"/"))
			for _, s := range tc.notContains {
				assert.NotContains(t, name, s)
			}
			if tc.maxLen > 0 {
				assert.LessOrEqual(t, len(name), tc.maxLen)
			}
		})
	}
}

func TestBuildPRBody(t *testing.T) {
	tests := []struct {
		name        string
		commitHash  string
		contains    []string
		notContains []string
	}{
		{
			name:        "no commit hash",
			contains:    []string{"com.example:lib", "1.0.0", "1.0.1"},
			notContains: []string{"Scanned commit"},
		},
		{
			name:       "with commit hash",
			commitHash: "abc123",
			contains:   []string{"abc123", "Scanned commit"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.commitHash != "" {
				t.Setenv(commitHashEnv, tc.commitHash)
			} else {
				t.Setenv(commitHashEnv, "")
			}
			body := buildPRBody("com.example:lib", "1.0.0", "1.0.1")
			for _, s := range tc.contains {
				assert.Contains(t, body, s)
			}
			for _, s := range tc.notContains {
				assert.NotContains(t, body, s)
			}
		})
	}
}

func TestNewUpdater(t *testing.T) {
	tests := []struct {
		name        string
		tech        techutils.Technology
		expectError bool
	}{
		{name: "maven", tech: techutils.Maven},
		{name: "npm", tech: techutils.Npm},
		{name: "pnpm", tech: techutils.Pnpm},
		{name: "go", tech: techutils.Go},
		{name: "pip", tech: techutils.Pip},
		{name: "unsupported yarn", tech: techutils.Yarn, expectError: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			updater, err := newUpdater(tc.tech)
			if tc.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "unsupported technology")
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, updater)
			}
		})
	}
}

func TestBuildFixDetails(t *testing.T) {
	paths := []string{"pom.xml", "module/pom.xml"}
	details := buildFixDetails("com.example:lib", "1.0.0", "1.0.1", techutils.Maven, paths)

	assert.Equal(t, "com.example:lib", details.ImpactedDependencyName)
	assert.Equal(t, "1.0.0", details.ImpactedDependencyVersion)
	assert.Equal(t, "1.0.1", details.SuggestedFixedVersion)
	assert.True(t, details.IsDirectDependency)
	assert.Equal(t, techutils.Maven, details.Technology)
	require.Len(t, details.Components, 1)
	require.Len(t, details.Components[0].Evidences, 2)
	assert.Equal(t, "pom.xml", details.Components[0].Evidences[0].File)
	assert.Equal(t, "module/pom.xml", details.Components[0].Evidences[1].File)
}
