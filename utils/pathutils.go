package utils

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ValidateFileWithinDir receives a file path and an allowed directory, resolves any symlinks in both,
// and verifies the real (on-disk) target still resides under the allowed directory.
// Returns the resolved absolute path on success, or an error if the file escapes the allowed boundary.
func ValidateFileWithinDir(filePath, allowedDir string) (string, error) {
	absPath, err := filepath.Abs(filePath)
	if err != nil {
		return "", fmt.Errorf("couldn't get absolute path for '%s': %s", filePath, err.Error())
	}

	realPath, err := filepath.EvalSymlinks(absPath)
	if err != nil {
		return "", fmt.Errorf("couldn't resolve symlinks for '%s': %s", filePath, err.Error())
	}

	realAllowedDir, err := filepath.EvalSymlinks(allowedDir)
	if err != nil {
		return "", fmt.Errorf("couldn't resolve symlinks for allowed directory '%s': %s", allowedDir, err.Error())
	}

	cleanAllowedDir := filepath.Clean(realAllowedDir)
	realPath = filepath.Clean(realPath)

	// The resolved path must either equal the allowed directory itself, or sit underneath it.
	if realPath != cleanAllowedDir && !strings.HasPrefix(realPath, cleanAllowedDir+string(os.PathSeparator)) {
		return "", fmt.Errorf("file '%s' resolves to '%s' which is outside the allowed directory '%s'", filePath, realPath, allowedDir)
	}

	return realPath, nil
}
