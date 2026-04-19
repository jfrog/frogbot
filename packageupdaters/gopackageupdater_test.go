package packageupdaters

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBackupModuleFiles(t *testing.T) {
	testcases := []struct {
		name          string
		goModContent  []byte
		goSumContent  []byte
		modifiedGoMod []byte
		modifiedGoSum []byte
	}{
		{
			name:          "backup and restore after files were modified",
			goModContent:  []byte("module example.com/test\n\ngo 1.21\n\nrequire github.com/some/pkg v1.0.0\n"),
			goSumContent:  []byte("github.com/some/pkg v1.0.0 h1:abc123=\ngithub.com/some/pkg v1.0.0/go.mod h1:def456=\n"),
			modifiedGoMod: []byte("module example.com/test\n\ngo 1.21\n\nrequire github.com/some/pkg v2.0.0\n"),
			modifiedGoSum: []byte("github.com/some/pkg v2.0.0 h1:xyz789=\n"),
		},
		{
			name:         "backup preserves empty go.sum",
			goModContent: []byte("module example.com/test\n\ngo 1.21\n"),
			goSumContent: []byte(""),
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			goModPath := filepath.Join(tmpDir, goModFileName)
			goSumPath := filepath.Join(tmpDir, goSumFileName)
			assert.NoError(t, os.WriteFile(goModPath, tc.goModContent, 0644))
			assert.NoError(t, os.WriteFile(goSumPath, tc.goSumContent, 0644))

			gpu := &GoPackageUpdater{}
			backup, err := gpu.backupModuleFiles(goModPath)
			assert.NoError(t, err)
			assert.Equal(t, tc.goModContent, backup.goModContent)
			assert.Equal(t, tc.goSumContent, backup.goSumContent)
			assert.Equal(t, goModPath, backup.goModPath)
			assert.Equal(t, goSumPath, backup.goSumPath)

			if tc.modifiedGoMod != nil {
				assert.NoError(t, os.WriteFile(goModPath, tc.modifiedGoMod, 0644))
				assert.NoError(t, os.WriteFile(goSumPath, tc.modifiedGoSum, 0644))

				assert.NoError(t, gpu.restoreModuleFiles(backup))

				restoredGoMod, err := os.ReadFile(goModPath)
				assert.NoError(t, err)
				assert.Equal(t, tc.goModContent, restoredGoMod)

				restoredGoSum, err := os.ReadFile(goSumPath)
				assert.NoError(t, err)
				assert.Equal(t, tc.goSumContent, restoredGoSum)
			}
		})
	}
}

func TestHasVendorDirectory(t *testing.T) {
	testcases := []struct {
		name           string
		setupVendor    bool
		expectedResult bool
	}{
		{
			name:           "vendor directory with modules.txt",
			setupVendor:    true,
			expectedResult: true,
		},
		{
			name:           "no vendor directory",
			setupVendor:    false,
			expectedResult: false,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			tmpDir := t.TempDir()

			if tc.setupVendor {
				vendorDir := filepath.Join(tmpDir, goVendorDirName)
				assert.NoError(t, os.MkdirAll(vendorDir, 0755))
				assert.NoError(t, os.WriteFile(filepath.Join(vendorDir, "modules.txt"), []byte("# vendor modules\n"), 0644))
			}

			gpu := &GoPackageUpdater{}
			assert.Equal(t, tc.expectedResult, gpu.hasVendorDirectory(tmpDir))
		})
	}
}
