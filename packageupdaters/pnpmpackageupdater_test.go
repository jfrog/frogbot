package packageupdaters

import (
	"testing"

	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/stretchr/testify/assert"
)

func TestEvidencePathLooksLikeNpmPackageCoordinate(t *testing.T) {
	t.Parallel()
	tests := []struct {
		path     string
		wantTrue bool
	}{
		{"lodash@4.17.19/package.json", true},
		{"axios@0.21.1/package.json", true},
		{"nested/pkg@1.0.0-rc.1/sub/package.json", true},
		{"package.json", false},
		{"apps/web/package.json", false},
		{"node_modules/@types/node/package.json", false},
		{"node_modules/@scope/pkg/package.json", false},
		{"@types/node/package.json", false},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.wantTrue, evidencePathLooksLikeNpmPackageCoordinate(tt.path), tt.path)
		})
	}
}

func TestPnpmFilterCoordinateStyleDescriptorPaths(t *testing.T) {
	t.Parallel()
	in := []string{
		"lodash@4.17.19/package.json",
		"axios@0.21.1/package.json",
		"package.json",
		"apps/web/package.json",
		"node_modules/@types/node/package.json",
	}
	want := []string{"package.json", "apps/web/package.json", "node_modules/@types/node/package.json"}
	assert.ElementsMatch(t, want, pnpmFilterCoordinateStyleDescriptorPaths(in))
}

func TestPnpmCollectLeavesNpmParityThenPnpmFilterDropsCoordinates(t *testing.T) {
	t.Parallel()
	pnpm := &PnpmPackageUpdater{}
	vuln := createVulnerabilityDetails(techutils.Pnpm, "lodash", "4.17.19", "4.17.21", true,
		"lodash@4.17.19/package.json", "axios@0.21.1/package.json", "package.json")
	raw := pnpm.CollectVulnerabilityDescriptorPaths(vuln, []string{nodePackageJSONFileName}, []string{nodeModulesDirName})
	assert.ElementsMatch(t, []string{"lodash@4.17.19/package.json", "axios@0.21.1/package.json", "package.json"}, raw)
	assert.ElementsMatch(t, []string{"package.json"}, pnpmFilterCoordinateStyleDescriptorPaths(raw))
}
