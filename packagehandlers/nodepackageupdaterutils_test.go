package packagehandlers

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/stretchr/testify/assert"
)

func TestGetPackageJsonPathsFromLockfilePaths(t *testing.T) {
	testcases := []struct {
		name          string
		lockfilePaths []string
		expectedPaths []string
		expectError   bool
	}{
		{
			name:          "single lockfile in root",
			lockfilePaths: []string{"package-lock.json"},
			expectedPaths: []string{"package.json"},
			expectError:   false,
		},
		{
			name:          "single lockfile in subdirectory",
			lockfilePaths: []string{"frontend/package-lock.json"},
			expectedPaths: []string{"frontend/package.json"},
			expectError:   false,
		},
		{
			name:          "multiple lockfiles in different directories",
			lockfilePaths: []string{"app1/package-lock.json", "app2/package-lock.json"},
			expectedPaths: []string{"app1/package.json", "app2/package.json"},
			expectError:   false,
		},
		{
			name:          "empty input",
			lockfilePaths: []string{},
			expectedPaths: nil,
			expectError:   false,
		},
		{
			name:          "descriptor file doesn't exist",
			lockfilePaths: []string{"nonexistent/package-lock.json"},
			expectError:   true,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			tmpDir, err := os.MkdirTemp("", "lockfile-paths-test-")
			assert.NoError(t, err)
			defer func() {
				assert.NoError(t, fileutils.RemoveTempDir(tmpDir))
			}()

			originalWd, err := os.Getwd()
			assert.NoError(t, err)
			defer func() {
				assert.NoError(t, os.Chdir(originalWd))
			}()

			assert.NoError(t, os.Chdir(tmpDir))

			if !tc.expectError {
				for _, expectedPath := range tc.expectedPaths {
					dir := filepath.Dir(expectedPath)
					if dir != "." {
						assert.NoError(t, os.MkdirAll(dir, 0755))
					}
					assert.NoError(t, os.WriteFile(expectedPath, []byte("{}"), 0644))
				}
			}

			result, err := GetPackageJsonPathsFromLockfilePaths(tc.lockfilePaths)

			if tc.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "descriptor file")
				assert.Contains(t, err.Error(), "not found")
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tc.expectedPaths, result)
		})
	}
}

func TestUpdatePackageInDescriptor(t *testing.T) {
	testcases := []struct {
		name                 string
		initialContent       string
		packageName          string
		newVersion           string
		allowedSections      []string
		expectError          bool
		expectedInContent    string
		notExpectedInContent string
	}{
		{
			name: "update package in dependencies",
			initialContent: `{
  "dependencies": {
    "lodash": "4.17.20"
  }
}`,
			packageName:          "lodash",
			newVersion:           "4.17.21",
			allowedSections:      []string{"dependencies"},
			expectError:          false,
			expectedInContent:    `"lodash": "4.17.21"`,
			notExpectedInContent: `"lodash": "4.17.20"`,
		},
		{
			name: "package not found",
			initialContent: `{
  "dependencies": {
    "axios": "0.21.4"
  }
}`,
			packageName:     "lodash",
			newVersion:      "4.17.21",
			allowedSections: []string{"dependencies"},
			expectError:     true,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			tmpDir, err := os.MkdirTemp("", "update-descriptor-test-")
			assert.NoError(t, err)
			defer func() {
				assert.NoError(t, fileutils.RemoveTempDir(tmpDir))
			}()

			descriptorPath := filepath.Join(tmpDir, "package.json")
			assert.NoError(t, os.WriteFile(descriptorPath, []byte(tc.initialContent), 0644))

			backupContent, err := UpdatePackageInDescriptor(tc.packageName, tc.newVersion, descriptorPath, tc.allowedSections)

			if tc.expectError {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, []byte(tc.initialContent), backupContent, "Backup should match original content")

			updatedContent, err := os.ReadFile(descriptorPath)
			assert.NoError(t, err)
			assert.Contains(t, string(updatedContent), tc.expectedInContent)
			if tc.notExpectedInContent != "" {
				assert.NotContains(t, string(updatedContent), tc.notExpectedInContent)
			}
		})
	}
}

func TestRegenerateLockfile_Success(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "regenerate-lockfile-test-")
	assert.NoError(t, err)
	defer func() {
		assert.NoError(t, fileutils.RemoveTempDir(tmpDir))
	}()

	originalWd, err := os.Getwd()
	assert.NoError(t, err)

	descriptorPath := filepath.Join(tmpDir, "package.json")
	descriptorContent := []byte(`{"name": "test", "dependencies": {"lodash": "4.17.21"}}`)
	assert.NoError(t, os.WriteFile(descriptorPath, descriptorContent, 0644))

	backupContent := []byte(`{"name": "test", "dependencies": {"lodash": "4.17.20"}}`)

	regenerateCalled := false
	mockRegenerate := func() error {
		regenerateCalled = true
		return nil
	}

	err = RegenerateLockfile("lodash", "4.17.21", descriptorPath, originalWd, backupContent, mockRegenerate)

	assert.NoError(t, err)
	assert.True(t, regenerateCalled, "Regenerate function should have been called")

	currentContent, err := os.ReadFile(descriptorPath)
	assert.NoError(t, err)
	assert.Equal(t, descriptorContent, currentContent, "Descriptor should remain updated on success")
}

func TestRegenerateLockfile_FailureWithRollback(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "regenerate-lockfile-rollback-test-")
	assert.NoError(t, err)
	defer func() {
		assert.NoError(t, fileutils.RemoveTempDir(tmpDir))
	}()

	originalWd, err := os.Getwd()
	assert.NoError(t, err)

	descriptorPath := filepath.Join(tmpDir, "package.json")
	updatedContent := []byte(`{"name": "test", "dependencies": {"lodash": "4.17.21"}}`)
	assert.NoError(t, os.WriteFile(descriptorPath, updatedContent, 0644))

	backupContent := []byte(`{"name": "test", "dependencies": {"lodash": "4.17.20"}}`)

	regenerateError := errors.New("npm install failed")
	mockRegenerate := func() error {
		return regenerateError
	}

	err = RegenerateLockfile("lodash", "4.17.21", descriptorPath, originalWd, backupContent, mockRegenerate)

	assert.Error(t, err)
	assert.Equal(t, regenerateError, err, "Original error should be returned")

	rolledBackContent, err := os.ReadFile(descriptorPath)
	assert.NoError(t, err)
	assert.Equal(t, backupContent, rolledBackContent, "Descriptor should be rolled back to original")
}

func TestRegenerateLockfile_RollbackFailure(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "regenerate-lockfile-rollback-fail-test-")
	assert.NoError(t, err)
	defer func() {
		assert.NoError(t, fileutils.RemoveTempDir(tmpDir))
	}()

	originalWd, err := os.Getwd()
	assert.NoError(t, err)

	descriptorPath := filepath.Join(tmpDir, "package.json")
	updatedContent := []byte(`{"name": "test", "dependencies": {"lodash": "4.17.21"}}`)
	assert.NoError(t, os.WriteFile(descriptorPath, updatedContent, 0644))

	backupContent := []byte(`{"name": "test", "dependencies": {"lodash": "4.17.20"}}`)

	regenerateError := errors.New("npm install failed")
	mockRegenerate := func() error {
		assert.NoError(t, os.Remove(descriptorPath))
		return regenerateError
	}

	err = RegenerateLockfile("lodash", "4.17.21", descriptorPath, originalWd, backupContent, mockRegenerate)

	assert.Error(t, err)
	assert.Equal(t, regenerateError, err, "Original regenerate error should be returned even if rollback fails")
}

func TestUpdatePackageAndRegenerateLock_Success(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "update-package-success-test-")
	assert.NoError(t, err)
	defer func() {
		assert.NoError(t, fileutils.RemoveTempDir(tmpDir))
	}()

	originalWd, err := os.Getwd()
	assert.NoError(t, err)
	defer func() {
		assert.NoError(t, os.Chdir(originalWd))
	}()

	assert.NoError(t, os.Chdir(tmpDir))

	descriptorPath := filepath.Join(tmpDir, "package.json")
	initialContent := `{"dependencies": {"lodash": "4.17.20"}}`
	assert.NoError(t, os.WriteFile(descriptorPath, []byte(initialContent), 0644))

	regenerateCalled := false
	mockRegenerate := func() error {
		regenerateCalled = true
		return nil
	}

	err = UpdatePackageAndRegenerateLock(
		"lodash",
		"4.17.20",
		"4.17.21",
		descriptorPath,
		originalWd,
		"package-lock.json",
		[]string{"dependencies"},
		mockRegenerate,
	)

	assert.NoError(t, err)

	updatedContent, err := os.ReadFile(descriptorPath)
	assert.NoError(t, err)
	assert.Contains(t, string(updatedContent), `"lodash": "4.17.21"`)

	// Regeneration happens when git check fails (defaults to true)
	// This is the correct behavior: better to regenerate when uncertain
	assert.True(t, regenerateCalled, "Regenerate should be called when git check is uncertain")
}

func TestUpdatePackageAndRegenerateLock_UpdateDescriptorFailure(t *testing.T) {
	originalWd, err := os.Getwd()
	assert.NoError(t, err)

	err = UpdatePackageAndRegenerateLock(
		"nonexistent",
		"1.0.0",
		"2.0.0",
		"/nonexistent/package.json",
		originalWd,
		"package-lock.json",
		[]string{"dependencies"},
		func() error { return nil },
	)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read file")
}

func TestGetPackageJsonPathsFromLockfilePaths_EdgeCases(t *testing.T) {
	testcases := []struct {
		name          string
		lockfilePaths []string
		expectedPaths []string
	}{
		{
			name:          "lockfile with . in directory name",
			lockfilePaths: []string{"app.v2/package-lock.json"},
			expectedPaths: []string{"app.v2/package.json"},
		},
		{
			name:          "lockfile name variations",
			lockfilePaths: []string{"package-lock.json", "yarn.lock", "pnpm-lock.yaml"},
			expectedPaths: []string{"package.json", "package.json", "package.json"},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			tmpDir, err := os.MkdirTemp("", "edge-cases-test-")
			assert.NoError(t, err)
			defer func() {
				assert.NoError(t, fileutils.RemoveTempDir(tmpDir))
			}()

			originalWd, err := os.Getwd()
			assert.NoError(t, err)
			defer func() {
				assert.NoError(t, os.Chdir(originalWd))
			}()

			assert.NoError(t, os.Chdir(tmpDir))

			for _, expectedPath := range tc.expectedPaths {
				dir := filepath.Dir(expectedPath)
				if dir != "." {
					assert.NoError(t, os.MkdirAll(dir, 0755))
				}
				assert.NoError(t, os.WriteFile(expectedPath, []byte("{}"), 0644))
			}

			result, err := GetPackageJsonPathsFromLockfilePaths(tc.lockfilePaths)
			assert.NoError(t, err)
			assert.Equal(t, tc.expectedPaths, result)
		})
	}
}
