package packagehandlers

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/jfrog/frogbot/v2/utils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

const (
	packageJsonFileName             = "package.json"
	dependenciesSectionName         = "dependencies"
	devDependenciesSectionName      = "devDependencies"
	optionalDependenciesSectionName = "optionalDependencies"
)

// TODO: this function is a workaround that handles the bug where only lock files are provided in vulnerability locations, instead of the descriptor files.
// TODO: After the bug is fixed we can simply call GetVulnerabilityLocations(vulnDetails, []string{packageJsonFileName}) and verify it exists (delete func & test)
func GetDescriptorsToFixFromVulnerability(vulnDetails *utils.VulnerabilityDetails, lockFileName string) ([]string, error) {
	lockFilePaths := GetVulnerabilityLocations(vulnDetails, []string{lockFileName})
	if len(lockFilePaths) == 0 {
		return nil, fmt.Errorf("no location evidence was found for package %s", vulnDetails.ImpactedDependencyName)
	}

	return getPackageJsonPathsFromLockfilePaths(lockFilePaths)
}

func UpdatePackageAndRegenerateLock(packageName, oldVersion, newVersion, descriptorPath, originalWd, lockFileName string, allowedSections []string, regenerateLockfileFn func() error) error {
	backupContent, err := updatePackageInDescriptor(packageName, newVersion, descriptorPath, allowedSections)
	if err != nil {
		return err
	}

	lockFileTracked, checkErr := utils.IsFileTrackedByGit(lockFileName, originalWd)
	if checkErr != nil {
		log.Debug(fmt.Sprintf("Failed to check if lock file is tracked in git: %s. Proceeding with lock file regeneration.", checkErr.Error()))
		lockFileTracked = true
	}

	if !lockFileTracked {
		log.Debug(fmt.Sprintf("Lock file '%s' does not exist in remote, skipping lock file regeneration", lockFileName))
		log.Debug(fmt.Sprintf("Successfully updated '%s' from version '%s' to '%s' in descriptor '%s' without regenerating lock file", packageName, oldVersion, newVersion, descriptorPath))
		return nil
	}

	if err = regenerateLockfile(packageName, newVersion, descriptorPath, originalWd, backupContent, regenerateLockfileFn); err != nil {
		return err
	}

	log.Debug(fmt.Sprintf("Successfully updated '%s' from version '%s' to '%s' in descriptor '%s'", packageName, oldVersion, newVersion, descriptorPath))
	return nil
}

// ==================== Internal Helper Functions ====================

func getPackageJsonPathsFromLockfilePaths(lockFilePaths []string) ([]string, error) {
	var descriptorPaths []string
	for _, lockFilePath := range lockFilePaths {
		descriptorPath := filepath.Join(filepath.Dir(lockFilePath), packageJsonFileName)
		fileExists, err := fileutils.IsFileExists(descriptorPath, false)
		if err != nil {
			return nil, err
		}
		if !fileExists {
			return nil, fmt.Errorf("descriptor file '%s' not found for lock file '%s'", descriptorPath, lockFilePath)
		}
		descriptorPaths = append(descriptorPaths, descriptorPath)
	}
	return descriptorPaths, nil
}

func updatePackageInDescriptor(packageName, newVersion, descriptorPath string, allowedSections []string) ([]byte, error) {
	descriptorContent, err := os.ReadFile(descriptorPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file '%s': %w", descriptorPath, err)
	}

	backupContent := make([]byte, len(descriptorContent))
	copy(backupContent, descriptorContent)

	updatedContent, err := updatePackageJsonDependency(descriptorContent, packageName, newVersion, allowedSections, descriptorPath)
	if err != nil {
		return nil, fmt.Errorf("failed to update version in descriptor: %w", err)
	}

	if err = os.WriteFile(descriptorPath, updatedContent, 0644); err != nil {
		return nil, fmt.Errorf("failed to write updated descriptor '%s': %w", descriptorPath, err)
	}
	return backupContent, nil
}

func regenerateLockfile(packageName, newVersion, descriptorPath, originalWd string, backupContent []byte, regenerateLockfileFn func() error) (err error) {
	descriptorDir := filepath.Dir(descriptorPath)
	if err = os.Chdir(descriptorDir); err != nil {
		return fmt.Errorf("failed to change directory to '%s': %w", descriptorDir, err)
	}
	defer func() {
		if chErr := os.Chdir(originalWd); chErr != nil {
			err = errors.Join(err, fmt.Errorf("failed to return to original directory: %w", chErr))
		}
	}()

	if err = regenerateLockfileFn(); err != nil {
		log.Warn(fmt.Sprintf("Failed to regenerate lock file after updating '%s' to version '%s': %s. Rolling back...", packageName, newVersion, err.Error()))
		if rollbackErr := os.WriteFile(descriptorPath, backupContent, 0644); rollbackErr != nil {
			return fmt.Errorf("failed to rollback descriptor after lock file regeneration failure: %w (original error: %v)", rollbackErr, err)
		}
		return err
	}
	return nil
}

func updatePackageJsonDependency(content []byte, packageName, newVersion string, allowedSections []string, descriptorPath string) ([]byte, error) {
	updated := false
	escapedName := escapeJsonPathKey(packageName)

	for _, section := range allowedSections {
		path := section + "." + escapedName
		if gjson.GetBytes(content, path).Exists() {
			var err error
			content, err = sjson.SetBytes(content, path, newVersion)
			if err != nil {
				return nil, fmt.Errorf("failed to set version for '%s' in section '%s': %w", packageName, section, err)
			}
			updated = true
		}
	}

	if !updated {
		return nil, fmt.Errorf("package '%s' not found in allowed sections [%s] in '%s'", packageName, strings.Join(allowedSections, ", "), descriptorPath)
	}
	return content, nil
}

func escapeJsonPathKey(key string) string {
	r := strings.NewReplacer(".", "\\.", "*", "\\*", "?", "\\?")
	return r.Replace(key)
}
