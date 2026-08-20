package autopr

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jfrog/frogbot/v3/utils"
	securitypkgupdaters "github.com/jfrog/jfrog-cli-security/remediation/sca/packageupdaters"
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

func TestBuildPRBody(t *testing.T) {
	tests := []struct {
		name        string
		commitHash  string
		contains    []string
		notContains []string
	}{
		{
			name:     "no commit hash",
			contains: []string{"com.example:lib", "1.0.0", "Frogbot"},
		},
		{
			name:       "with commit hash",
			commitHash: "abc123",
			contains:   []string{"abc123"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.commitHash != "" {
				t.Setenv(commitHashEnv, tc.commitHash)
			} else {
				t.Setenv(commitHashEnv, "")
			}
			body := buildPRBody(utils.Repository{}, "com.example:lib", "1.0.0", "1.0.1", techutils.Maven, []string{"pom.xml"})
			for _, s := range tc.contains {
				assert.Contains(t, body, s)
			}
			for _, s := range tc.notContains {
				assert.NotContains(t, body, s)
			}
		})
	}
}

// TestRunUpdater_UnsupportedTech ensures runUpdater surfaces a clear error for technologies
// GetCompatiblePackageUpdater does not recognize (Yarn is not in the compatible set).
func TestRunUpdater_UnsupportedTech(t *testing.T) {
	err := runUpdater("some-pkg", "1.0.0", "1.0.1", techutils.Yarn, true, []string{"package.json"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported technology")
}

// TestGetCompatiblePackageUpdater_SupportedSet documents the technologies routed through the
// shared factory. Docker must be included so auto-pr can fix container images.
func TestGetCompatiblePackageUpdater_SupportedSet(t *testing.T) {
	techs := []techutils.Technology{
		techutils.Maven,
		techutils.Npm,
		techutils.Pnpm,
		techutils.Go,
		techutils.Pip,
		techutils.Docker,
	}
	for _, tech := range techs {
		t.Run(tech.String(), func(t *testing.T) {
			updater, supported := securitypkgupdaters.GetCompatiblePackageUpdater(&securitypkgupdaters.FixDetails{Technology: tech})
			require.True(t, supported)
			require.NotNil(t, updater)
		})
	}
}

func TestBuildFixDetails(t *testing.T) {
	paths := []string{"pom.xml", "module/pom.xml"}
	details := buildFixDetails("com.example:lib", "1.0.0", "1.0.1", techutils.Maven, true, paths)

	assert.Equal(t, "com.example:lib", details.ImpactedDependencyName)
	assert.Equal(t, "1.0.0", details.ImpactedDependencyVersion)
	assert.Equal(t, "1.0.1", details.SuggestedFixedVersion)
	assert.True(t, details.IsDirectDependency)
	assert.Equal(t, techutils.Maven, details.Technology)
	require.Len(t, details.Components, 1)
	require.Len(t, details.Components[0].Evidences, 2)
	assert.Equal(t, "pom.xml", details.Components[0].Evidences[0].File)
	assert.Equal(t, "module/pom.xml", details.Components[0].Evidences[1].File)

	transitive := buildFixDetails("com.example:lib", "1.0.0", "1.0.1", techutils.Maven, false, paths)
	assert.False(t, transitive.IsDirectDependency)
}
