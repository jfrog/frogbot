package packageupdaters

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	biutils "github.com/jfrog/build-info-go/utils"
	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/stretchr/testify/assert"

	"github.com/jfrog/frogbot/v2/utils"
)

func skipUnlessPnpmRunnable(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("requires runnable pnpm (often needs network for Corepack)")
	}
	if _, err := exec.LookPath("pnpm"); err != nil {
		t.Skip("pnpm not on PATH:", err)
	}
	cmd := exec.Command("pnpm", "--version")
	cmd.Env = envWithCorepackIntegrityWorkaround(os.Environ())
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("pnpm not runnable (install/Corepack/network): %v\n%s", err, string(out))
	}
}

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

func TestPnpmFixVulnerabilityIfExists(t *testing.T) {
	skipUnlessPnpmRunnable(t)

	testRootDir, err := os.Getwd()
	assert.NoError(t, err)

	tmpDir, err := os.MkdirTemp("", "")
	defer func() {
		assert.NoError(t, fileutils.RemoveTempDir(tmpDir))
	}()
	assert.NoError(t, err)
	assert.NoError(t, biutils.CopyDir(filepath.Join("..", "testdata", "projects", "npm"), tmpDir, true, nil))
	assert.NoError(t, os.Chdir(tmpDir))
	defer func() {
		assert.NoError(t, os.Chdir(testRootDir))
	}()

	vulnerabilityDetails := &utils.VulnerabilityDetails{
		SuggestedFixedVersion:       "1.2.6",
		IsDirectDependency:          true,
		VulnerabilityOrViolationRow: formats.VulnerabilityOrViolationRow{Technology: techutils.Pnpm, ImpactedDependencyDetails: formats.ImpactedDependencyDetails{ImpactedDependencyName: "minimist", ImpactedDependencyVersion: "1.2.5"}},
	}
	pnpm := &PnpmPackageUpdater{}

	descriptorFiles, err := pnpm.GetAllDescriptorFilesFullPaths([]string{pnpmDescriptorFileSuffix})
	assert.NoError(t, err)
	descriptorFileToTest := descriptorFiles[0]

	vulnRegexpCompiler := BuildPackageWithVersionRegex(vulnerabilityDetails.ImpactedDependencyName, vulnerabilityDetails.ImpactedDependencyVersion, pnpmDependencyRegexpPattern)
	var isFileChanged bool
	isFileChanged, err = pnpm.fixVulnerabilityIfExists(vulnerabilityDetails, descriptorFileToTest, tmpDir, vulnRegexpCompiler)
	assert.NoError(t, err)
	assert.True(t, isFileChanged)

	var fixedFileContent []byte
	fixedFileContent, err = os.ReadFile(descriptorFileToTest)
	fixedFileContentString := string(fixedFileContent)

	assert.NoError(t, err)
	assert.NotContains(t, fixedFileContentString, "\"minimist\": \"1.2.5\"")
	assert.Contains(t, fixedFileContentString, "\"minimist\": \"1.2.6\"")

	nodeModulesExist, err := fileutils.IsDirExists(filepath.Join(tmpDir, "node_modules"), false)
	assert.NoError(t, err)
	assert.False(t, nodeModulesExist)
}
