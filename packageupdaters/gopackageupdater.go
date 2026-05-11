package packageupdaters

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/jfrog/frogbot/v2/utils"
	"github.com/jfrog/jfrog-client-go/utils/log"
)

const (
	goFlagModEditEnv      = "GOFLAGS=-mod=mod"
	goWorkOffEnv          = "GOWORK=off"
	goModFileName         = "go.mod"
	goSumFileName         = "go.sum"
	goVendorDirName       = "vendor"
	goTidyContinueOnError = "-e"
)

type GoPackageUpdater struct{}

type goModuleBackup struct {
	goModPath    string
	goModContent []byte
	goSumPath    string
	goSumContent []byte
}

func (gpu *GoPackageUpdater) UpdateDependency(vulnDetails *utils.VulnerabilityDetails) error {
	descriptorPaths := GetVulnerabilityLocations(vulnDetails, []string{goModFileName}, []string{goVendorDirName})
	if len(descriptorPaths) == 0 {
		return fmt.Errorf("no descriptor evidence was found for package %s", vulnDetails.ImpactedDependencyName)
	}

	originalWd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get current working directory: %w", err)
	}

	env := gpu.buildGoCommandEnv()

	var failingDescriptors []string
	for _, descriptorPath := range descriptorPaths {
		if fixErr := gpu.fixVulnerabilityAndTidy(vulnDetails, descriptorPath, originalWd, env); fixErr != nil {
			failedFixErrorMsg := fmt.Errorf("failed to fix '%s' in descriptor '%s': %w", vulnDetails.ImpactedDependencyName, descriptorPath, fixErr)
			log.Warn(failedFixErrorMsg.Error())
			err = errors.Join(err, failedFixErrorMsg)
			failingDescriptors = append(failingDescriptors, descriptorPath)
		}
	}
	if err != nil {
		return fmt.Errorf("encountered errors while fixing '%s' vulnerability in descriptors [%s]: %w", vulnDetails.ImpactedDependencyName, strings.Join(failingDescriptors, ", "), err)
	}

	return nil
}

func (gpu *GoPackageUpdater) fixVulnerabilityAndTidy(vulnDetails *utils.VulnerabilityDetails, descriptorPath, originalWd string, env []string) (err error) {
	backup, backupErr := gpu.backupModuleFiles(descriptorPath)
	if backupErr != nil {
		return backupErr
	}

	descriptorDir := filepath.Dir(descriptorPath)
	if err = os.Chdir(descriptorDir); err != nil {
		return fmt.Errorf("failed to change directory to '%s': %w", descriptorDir, err)
	}
	defer func() {
		if chErr := os.Chdir(originalWd); chErr != nil {
			err = errors.Join(err, fmt.Errorf("failed to return to original directory: %w", chErr))
		}
	}()

	if err = gpu.updateDependency(vulnDetails, env); err != nil {
		log.Warn(fmt.Sprintf("Failed to update '%s' to version '%s': %s. Rolling back...", vulnDetails.ImpactedDependencyName, vulnDetails.SuggestedFixedVersion, err.Error()))
		if rollbackErr := gpu.restoreModuleFiles(backup); rollbackErr != nil {
			return fmt.Errorf("failed to rollback module files after go get failure: %w (original error: %v)", rollbackErr, err)
		}
		return err
	}

	lockFileTracked, checkErr := utils.IsFileTrackedByGit(backup.goSumPath, originalWd)
	if checkErr != nil {
		log.Debug(fmt.Sprintf("Failed to check if lock file is tracked in git: %s. Proceeding with lock file regeneration.", checkErr.Error()))
		lockFileTracked = true
	}

	if !lockFileTracked {
		log.Debug(fmt.Sprintf("Lock file '%s' is not tracked in git, skipping lock file regeneration", backup.goSumPath))
		return nil
	}

	if err = gpu.tidyLockFiles(descriptorDir, env); err != nil {
		log.Warn(fmt.Sprintf("Failed to tidy module files after updating '%s' to version '%s': %s. Rolling back...", vulnDetails.ImpactedDependencyName, vulnDetails.SuggestedFixedVersion, err.Error()))
		if rollbackErr := gpu.restoreModuleFiles(backup); rollbackErr != nil {
			return fmt.Errorf("failed to rollback module files after tidy failure: %w (original error: %v)", rollbackErr, err)
		}
		return err
	}

	log.Debug(fmt.Sprintf("Successfully updated '%s' from version '%s' to '%s' in descriptor '%s'", vulnDetails.ImpactedDependencyName, vulnDetails.ImpactedDependencyVersion, vulnDetails.SuggestedFixedVersion, descriptorPath))
	return nil
}

func (gpu *GoPackageUpdater) buildGoCommandEnv() []string {
	return append(os.Environ(), goFlagModEditEnv, goWorkOffEnv)
}

func (gpu *GoPackageUpdater) backupModuleFiles(goModPath string) (*goModuleBackup, error) {
	//#nosec G304 -- go.mod path from scan workflow.
	goModContent, err := os.ReadFile(goModPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read '%s': %w", goModPath, err)
	}

	// We assume go.sum resides under the same directory as go.mod
	descriptorDir := filepath.Dir(goModPath)
	goSumPath := filepath.Join(descriptorDir, goSumFileName)
	//#nosec G304 -- go.sum adjacent to go.mod from same scan workflow.
	goSumContent, err := os.ReadFile(goSumPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read '%s': %w", goSumPath, err)
	}

	backup := &goModuleBackup{
		goModPath:    goModPath,
		goModContent: make([]byte, len(goModContent)),
		goSumPath:    goSumPath,
		goSumContent: make([]byte, len(goSumContent)),
	}
	copy(backup.goModContent, goModContent)
	copy(backup.goSumContent, goSumContent)

	return backup, nil
}

func (gpu *GoPackageUpdater) restoreModuleFiles(backup *goModuleBackup) error {
	//#nosec G306 -- 0644 for checked-out module files in workspace.
	if err := os.WriteFile(backup.goModPath, backup.goModContent, 0644); err != nil {
		return fmt.Errorf("failed to restore '%s': %w", backup.goModPath, err)
	}
	//#nosec G306 -- 0644 for checked-out module files in workspace.
	if err := os.WriteFile(backup.goSumPath, backup.goSumContent, 0644); err != nil {
		return fmt.Errorf("failed to restore '%s': %w", backup.goSumPath, err)
	}
	log.Debug(fmt.Sprintf("Successfully rolled back '%s' and '%s' to original state", backup.goModPath, backup.goSumPath))
	return nil
}

func (gpu *GoPackageUpdater) updateDependency(vulnDetails *utils.VulnerabilityDetails, env []string) error {
	impactedPackage := strings.ToLower(vulnDetails.ImpactedDependencyName)
	fixedVersion := strings.TrimSpace(vulnDetails.SuggestedFixedVersion)

	if !strings.HasPrefix(fixedVersion, "v") {
		fixedVersion = "v" + fixedVersion
	}
	fixedPackage := strings.TrimSpace(impactedPackage) + "@" + fixedVersion

	//#nosec G204 -- runs only after user approval; arguments from vulnerability metadata.
	cmd := exec.Command("go", "get", fixedPackage)
	cmd.Env = env
	log.Debug(fmt.Sprintf("Running 'go get %s'", fixedPackage))

	output, err := cmd.CombinedOutput()
	if len(output) > 0 {
		log.Debug(fmt.Sprintf("go get output:\n%s", string(output)))
	}

	if err != nil {
		return fmt.Errorf("go get failed: %s\n%s", err.Error(), output)
	}
	return nil
}

func (gpu *GoPackageUpdater) tidyLockFiles(descriptorDir string, env []string) error {
	cmd := exec.Command("go", "mod", "tidy", goTidyContinueOnError)
	cmd.Env = env
	log.Debug("Running 'go mod tidy'")

	//#nosec G204 -- False positive - the subprocess only runs after the user's approval.
	output, err := cmd.CombinedOutput()
	if len(output) > 0 {
		log.Debug(fmt.Sprintf("go mod tidy output:\n%s", string(output)))
	}

	if err != nil {
		return fmt.Errorf("go mod tidy failed: %s\n%s", err.Error(), output)
	}

	if gpu.hasVendorDirectory(descriptorDir) {
		if err := gpu.updateVendor(env); err != nil {
			return err
		}
	}

	return nil
}

func (gpu *GoPackageUpdater) hasVendorDirectory(descriptorDir string) bool {
	vendorModulesPath := filepath.Join(descriptorDir, goVendorDirName, "modules.txt")
	if _, err := os.Stat(vendorModulesPath); err == nil {
		log.Debug(fmt.Sprintf("Detected vendor directory at: %s", vendorModulesPath))
		return true
	}
	return false
}

func (gpu *GoPackageUpdater) updateVendor(env []string) error {
	vendorCmd := exec.Command("go", "mod", "vendor")
	vendorCmd.Env = env
	log.Debug("Running 'go mod vendor' to update vendored dependencies")

	//#nosec G204 -- False positive - the subprocess only runs after the user's approval.
	vendorOutput, err := vendorCmd.CombinedOutput()
	if len(vendorOutput) > 0 {
		log.Debug(fmt.Sprintf("go mod vendor output:\n%s", string(vendorOutput)))
	}

	if err != nil {
		return fmt.Errorf("go mod vendor failed: %s\n%s", err.Error(), vendorOutput)
	}

	log.Debug("Successfully updated vendor directory")
	return nil
}
