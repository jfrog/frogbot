package utils

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// evalTempDir creates a temporary directory and resolves any symlinks in its path.
// Some platforms use symlinked temp directories (e.g., /var -> /private/var on macOS),
// which would cause path comparisons to fail without resolving first.
func evalTempDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	resolved, err := filepath.EvalSymlinks(dir)
	require.NoError(t, err)
	return resolved
}

func TestValidateFileWithinDir(t *testing.T) {
	tmpDir := evalTempDir(t)

	regularFile := filepath.Join(tmpDir, "requirements.txt")
	require.NoError(t, os.WriteFile(regularFile, []byte("requests==2.28.0"), 0600))

	resolvedPath, err := ValidateFileWithinDir(regularFile, tmpDir)
	assert.NoError(t, err)
	assert.Equal(t, regularFile, resolvedPath)
}

func TestValidateFileWithinDir_Subdirectory(t *testing.T) {
	tmpDir := evalTempDir(t)

	subDir := filepath.Join(tmpDir, "subdir")
	require.NoError(t, os.Mkdir(subDir, 0700))
	nestedFile := filepath.Join(subDir, "setup.py")
	require.NoError(t, os.WriteFile(nestedFile, []byte("setup()"), 0600))

	resolvedPath, err := ValidateFileWithinDir(nestedFile, tmpDir)
	assert.NoError(t, err)
	assert.Equal(t, nestedFile, resolvedPath)
}

func TestValidateFileWithinDir_SymlinkEscape(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Symlink tests are not supported on Windows")
	}

	tmpDir := evalTempDir(t)
	outsideDir := evalTempDir(t)

	outsideFile := filepath.Join(outsideDir, "secret.txt")
	require.NoError(t, os.WriteFile(outsideFile, []byte("sensitive data"), 0600))

	// Create a symlink inside the allowed dir that points outside
	symlinkPath := filepath.Join(tmpDir, "requirements.txt")
	require.NoError(t, os.Symlink(outsideFile, symlinkPath))

	_, err := ValidateFileWithinDir(symlinkPath, tmpDir)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "outside the allowed directory")
}

func TestValidateFileWithinDir_SymlinkWithinDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Symlink tests are not supported on Windows")
	}

	tmpDir := evalTempDir(t)

	realFile := filepath.Join(tmpDir, "real-requirements.txt")
	require.NoError(t, os.WriteFile(realFile, []byte("requests==2.28.0"), 0600))

	// A symlink that resolves to a file still inside the allowed dir should be accepted
	symlinkPath := filepath.Join(tmpDir, "requirements.txt")
	require.NoError(t, os.Symlink(realFile, symlinkPath))

	resolvedPath, err := ValidateFileWithinDir(symlinkPath, tmpDir)
	assert.NoError(t, err)
	assert.Equal(t, realFile, resolvedPath)
}

func TestValidateFileWithinDir_PathTraversal(t *testing.T) {
	tmpDir := evalTempDir(t)
	outsideDir := evalTempDir(t)

	outsideFile := filepath.Join(outsideDir, "secret.txt")
	require.NoError(t, os.WriteFile(outsideFile, []byte("sensitive data"), 0600))

	_, err := ValidateFileWithinDir(outsideFile, tmpDir)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "outside the allowed directory")
}

func TestValidateFileWithinDir_NonexistentFile(t *testing.T) {
	tmpDir := evalTempDir(t)

	_, err := ValidateFileWithinDir(filepath.Join(tmpDir, "nonexistent.txt"), tmpDir)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "couldn't resolve symlinks")
}

func TestValidateFileWithinDir_DirSymlinkEscape(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Symlink tests are not supported on Windows")
	}

	tmpDir := evalTempDir(t)
	outsideDir := evalTempDir(t)

	outsideFile := filepath.Join(outsideDir, "secret.txt")
	require.NoError(t, os.WriteFile(outsideFile, []byte("sensitive data"), 0600))

	// A symlinked directory pointing outside the workspace should be caught
	symlinkDir := filepath.Join(tmpDir, "linked-dir")
	require.NoError(t, os.Symlink(outsideDir, symlinkDir))

	_, err := ValidateFileWithinDir(filepath.Join(symlinkDir, "secret.txt"), tmpDir)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "outside the allowed directory")
}
