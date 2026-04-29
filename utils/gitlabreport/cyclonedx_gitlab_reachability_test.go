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
