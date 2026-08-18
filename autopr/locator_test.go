package autopr

import (
	"testing"

	cyclonedx "github.com/CycloneDX/cyclonedx-go"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func makeComponent(purl string, locations ...string) cyclonedx.Component {
	c := cyclonedx.Component{PackageURL: purl}
	if len(locations) > 0 {
		occurrences := make([]cyclonedx.EvidenceOccurrence, len(locations))
		for i, loc := range locations {
			occurrences[i] = cyclonedx.EvidenceOccurrence{Location: loc}
		}
		c.Evidence = &cyclonedx.Evidence{Occurrences: &occurrences}
	}
	return c
}

func TestExtractDescriptorPaths(t *testing.T) {
	tests := []struct {
		name            string
		sbom            *cyclonedx.BOM
		componentName   string
		affectedVersion string
		expectedPaths   []string
		expectedTech    techutils.Technology
		expectError     bool
	}{
		{
			name: "maven match",
			sbom: &cyclonedx.BOM{Components: &[]cyclonedx.Component{
				makeComponent("pkg:maven/com.example/lib@1.0.0", "pom.xml"),
				makeComponent("pkg:maven/com.example/other@2.0.0", "other/pom.xml"),
			}},
			componentName:   "com.example/lib",
			affectedVersion: "1.0.0",
			expectedPaths:   []string{"pom.xml"},
			expectedTech:    techutils.Maven,
		},
		{
			name: "npm match",
			sbom: &cyclonedx.BOM{Components: &[]cyclonedx.Component{
				makeComponent("pkg:npm/lodash@4.17.20", "package.json"),
			}},
			componentName:   "lodash",
			affectedVersion: "4.17.20",
			expectedPaths:   []string{"package.json"},
			expectedTech:    techutils.Npm,
		},
		{
			name: "component not found",
			sbom: &cyclonedx.BOM{Components: &[]cyclonedx.Component{
				makeComponent("pkg:maven/com.example/lib@1.0.0", "pom.xml"),
			}},
			componentName:   "com.example/other",
			affectedVersion: "1.0.0",
			expectedPaths:   nil,
			expectedTech:    techutils.NoTech,
		},
		{
			name: "wrong version",
			sbom: &cyclonedx.BOM{Components: &[]cyclonedx.Component{
				makeComponent("pkg:maven/com.example/lib@1.0.0", "pom.xml"),
			}},
			componentName:   "com.example/lib",
			affectedVersion: "2.0.0",
			expectedPaths:   nil,
			expectedTech:    techutils.NoTech,
		},
		{
			name:          "nil SBOM returns error",
			sbom:          nil,
			componentName: "lib",
			expectError:   true,
		},
		{
			name: "duplicate locations deduplicated",
			sbom: &cyclonedx.BOM{Components: &[]cyclonedx.Component{
				makeComponent("pkg:maven/com.example/lib@1.0.0", "pom.xml", "pom.xml"),
			}},
			componentName:   "com.example/lib",
			affectedVersion: "1.0.0",
			expectedPaths:   []string{"pom.xml"},
			expectedTech:    techutils.Maven,
		},
		{
			name: "match with no evidence — tech detected, paths empty",
			sbom: &cyclonedx.BOM{Components: &[]cyclonedx.Component{
				{PackageURL: "pkg:maven/com.example/lib@1.0.0"},
			}},
			componentName:   "com.example/lib",
			affectedVersion: "1.0.0",
			expectedPaths:   nil,
			expectedTech:    techutils.Maven,
		},
		{
			name: "maven colon vs slash",
			sbom: &cyclonedx.BOM{Components: &[]cyclonedx.Component{
				makeComponent("pkg:maven/com.example/lib@1.0.0", "pom.xml"),
			}},
			componentName:   "com.example:lib",
			affectedVersion: "1.0.0",
			expectedPaths:   []string{"pom.xml"},
			expectedTech:    techutils.Maven,
		},
		{
			name: "pip name normalization",
			sbom: &cyclonedx.BOM{Components: &[]cyclonedx.Component{
				makeComponent("pkg:pypi/Py_JWT@2.0.0", "requirements.txt"),
			}},
			componentName:   "py.jwt",
			affectedVersion: "2.0.0",
			expectedPaths:   []string{"requirements.txt"},
			expectedTech:    techutils.Pip,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			paths, tech, err := extractDescriptorPaths(tc.sbom, tc.componentName, tc.affectedVersion)
			if tc.expectError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.expectedTech, tech)
			assert.Equal(t, tc.expectedPaths, paths)
		})
	}
}

func TestComponentNamesMatch(t *testing.T) {
	assert.True(t, componentNamesMatch("com.example:lib", "com.example/lib"))
	assert.True(t, componentNamesMatch("Py_JWT", "py.jwt"))
	assert.False(t, componentNamesMatch("lodash", "underscore"))
}
