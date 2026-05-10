package gitlabreport

import (
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGitlabReachabilityRankForRow(t *testing.T) {
	t.Run("not scanned omits property", func(t *testing.T) {
		v := formats.VulnerabilityOrViolationRow{
			ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
				ImpactedDependencyName: "lib", ImpactedDependencyVersion: "1.0.0",
			},
			Cves: []formats.CveRow{{Id: "CVE-2024-1"}},
		}
		r, ok := gitlabReachabilityRankForRow(&v)
		assert.False(t, ok)
		assert.Equal(t, reachNone, r)
	})
	t.Run("applicable is in_use", func(t *testing.T) {
		v := formats.VulnerabilityOrViolationRow{
			ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
				ImpactedDependencyName: "lib", ImpactedDependencyVersion: "1.0.0",
			},
			Cves: []formats.CveRow{{
				Id:            "CVE-2024-1",
				Applicability: &formats.Applicability{Status: jasutils.Applicable.String()},
			}},
		}
		r, ok := gitlabReachabilityRankForRow(&v)
		require.True(t, ok)
		assert.Equal(t, reachInUse, r)
	})
	t.Run("not applicable is not_found", func(t *testing.T) {
		v := formats.VulnerabilityOrViolationRow{
			ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
				ImpactedDependencyName: "lib", ImpactedDependencyVersion: "1.0.0",
			},
			Cves: []formats.CveRow{{
				Id:            "CVE-2024-1",
				Applicability: &formats.Applicability{Status: jasutils.NotApplicable.String()},
			}},
		}
		r, ok := gitlabReachabilityRankForRow(&v)
		require.True(t, ok)
		assert.Equal(t, reachNotFound, r)
	})
}

func TestEnrichCycloneDXBOMForGitLabReachability_nilSafe(t *testing.T) {
	EnrichCycloneDXBOMForGitLabReachability(nil, nil)
	bom := &cyclonedx.BOM{}
	EnrichCycloneDXBOMForGitLabReachability(bom, nil)
	assert.Nil(t, bom.Metadata)
}

func TestWalkComponentTree_setsGitLabPropertiesAndTrimsPurlQuery(t *testing.T) {
	depInfo := map[string]*depReachInfo{
		dependencyReachabilityKey("minimist", "1.2.5"): {
			rank:      reachInUse,
			inputFile: "node_modules/minimist/package.json",
		},
	}
	c := &cyclonedx.Component{
		Type:       cyclonedx.ComponentTypeLibrary,
		Name:       "minimist",
		Version:    "1.2.5",
		PackageURL: "pkg:npm/minimist@1.2.5?foo=bar",
	}

	walkComponentTree(c, depInfo)

	assert.Equal(t, "pkg:npm/minimist@1.2.5", c.PackageURL, "query params should be stripped for stable matching")
	require.NotNil(t, c.Properties)
	props := map[string]string{}
	for _, p := range *c.Properties {
		props[p.Name] = p.Value
	}
	assert.Equal(t, "node_modules/minimist/package.json", props[gitlabDependencyScanningInputFilePath])
	assert.Equal(t, gitlabReachabilityInUse, props[gitlabDependencyScanningReachability])
}

func TestWalkComponentTree_usesGroupPrefixedNameMatch(t *testing.T) {
	depInfo := map[string]*depReachInfo{
		dependencyReachabilityKey("com.thoughtworks.xstream:xstream", "1.4.5"): {
			rank:      reachNotFound,
			inputFile: "pom.xml",
		},
	}
	c := &cyclonedx.Component{
		Type:    cyclonedx.ComponentTypeLibrary,
		Group:   "com.thoughtworks.xstream",
		Name:    "xstream",
		Version: "1.4.5",
	}

	walkComponentTree(c, depInfo)

	require.NotNil(t, c.Properties)
	props := map[string]string{}
	for _, p := range *c.Properties {
		props[p.Name] = p.Value
	}
	assert.Equal(t, "pom.xml", props[gitlabDependencyScanningInputFilePath])
	assert.Equal(t, gitlabReachabilityNotFound, props[gitlabDependencyScanningReachability])
}
