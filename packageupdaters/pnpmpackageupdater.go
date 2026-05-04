package packageupdaters

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/log"

	"github.com/jfrog/frogbot/v2/utils"
)

const (
	pnpmDependencyRegexpPattern = "\\s*\"%s\"\\s*:\\s*\"[~|^]?%s\""
	pnpmDescriptorFileSuffix    = "package.json"
	nodeModulesPathPattern      = ".*node_modules.*"

	pnpmLockFileName         = "pnpm-lock.yaml"
	pnpmLockfileOnlyFlag     = "--lockfile-only"
	pnpmIgnoreScriptsFlag    = "--ignore-scripts"
	pnpmNoFrozenLockfileFlag = "--no-frozen-lockfile"
	pnpmFrozenLockfileEnv    = "PNPM_FROZEN_LOCKFILE"

	pnpmInstallTimeout = 15 * time.Minute
)

var pnpmInstallEnvVars = map[string]string{
	pnpmFrozenLockfileEnv: "false",
	configLevelEnv:        "error",
	ciEnv:                 "true",
	// Avoid Corepack signature verification failures when the bundled Corepack is older than registry keys.
	"COREPACK_INTEGRITY_KEYS": "0",
}

// PnpmPackageUpdater updates pnpm projects (package.json + pnpm-lock.yaml) and supports legacy test helpers.
type PnpmPackageUpdater struct {
	CommonPackageUpdater
}

func (pnpm *PnpmPackageUpdater) UpdateDependency(vulnDetails *utils.VulnerabilityDetails) error {
	if vulnDetails.IsDirectDependency {
		return pnpm.updateDirectDependency(vulnDetails)
	}
	return &utils.ErrUnsupportedFix{
		PackageName:  vulnDetails.ImpactedDependencyName,
		FixedVersion: vulnDetails.SuggestedFixedVersion,
		ErrorType:    utils.IndirectDependencyFixNotSupported,
	}
}

func (pnpm *PnpmPackageUpdater) updateDirectDependency(vulnDetails *utils.VulnerabilityDetails) error {
	descriptorPaths := pnpm.CollectVulnerabilityDescriptorPaths(vulnDetails, []string{nodePackageJSONFileName}, []string{nodeModulesDirName})
	if len(descriptorPaths) == 0 {
		return fmt.Errorf("no descriptor evidence was found for package %s", vulnDetails.ImpactedDependencyName)
	}

	originalWd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get current working directory: %w", err)
	}

	var failingDescriptors []string
	for _, descriptorPath := range descriptorPaths {
		if fixErr := pnpm.fixVulnerabilityAndRegenerateLock(vulnDetails, descriptorPath, originalWd); fixErr != nil {
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

func (pnpm *PnpmPackageUpdater) fixVulnerabilityAndRegenerateLock(vulnDetails *utils.VulnerabilityDetails, descriptorPath string, originalWd string) error {
	backupContent, err := pnpm.UpdatePackageJSONDescriptor(descriptorPath, vulnDetails.ImpactedDependencyName, vulnDetails.SuggestedFixedVersion)
	if err != nil {
		return err
	}

	descriptorDir := filepath.Dir(descriptorPath)
	lockFilePath := filepath.Join(descriptorDir, pnpmLockFileName)

	lockFileTracked, checkErr := utils.IsFileTrackedByGit(lockFilePath, originalWd)
	if checkErr != nil {
		log.Debug(fmt.Sprintf("Failed to check if lock file is tracked in git: %s. Proceeding with lock file regeneration.", checkErr.Error()))
		lockFileTracked = true
	}

	if !lockFileTracked {
		log.Debug(fmt.Sprintf("Lock file '%s' is not tracked in git, skipping lock file regeneration", lockFilePath))
		return nil
	}

	if err = pnpm.regenerateLockfile(vulnDetails, descriptorPath, originalWd, backupContent); err != nil {
		return err
	}

	log.Debug(fmt.Sprintf("Successfully updated '%s' from version '%s' to '%s' in descriptor '%s'", vulnDetails.ImpactedDependencyName, vulnDetails.ImpactedDependencyVersion, vulnDetails.SuggestedFixedVersion, descriptorPath))
	return nil
}

func (pnpm *PnpmPackageUpdater) regenerateLockfile(vulnDetails *utils.VulnerabilityDetails, descriptorPath, originalWd string, backupContent []byte) (err error) {
	descriptorDir := filepath.Dir(descriptorPath)
	if err = os.Chdir(descriptorDir); err != nil {
		return fmt.Errorf("failed to change directory to '%s': %w", descriptorDir, err)
	}
	defer func() {
		if chErr := os.Chdir(originalWd); chErr != nil {
			err = errors.Join(err, fmt.Errorf("failed to return to original directory: %w", chErr))
		}
	}()

	if err = pnpm.runPnpmInstallLockOnly(); err != nil {
		log.Warn(fmt.Sprintf("Failed to regenerate lock file after updating '%s' to version '%s': %s. Rolling back...", vulnDetails.ImpactedDependencyName, vulnDetails.SuggestedFixedVersion, err.Error()))
		if rollbackErr := os.WriteFile(descriptorPath, backupContent, 0644); rollbackErr != nil {
			return fmt.Errorf("failed to rollback descriptor after lock file regeneration failure: %w (original error: %v)", rollbackErr, err)
		}
		return err
	}
	return nil
}

func (pnpm *PnpmPackageUpdater) runPnpmInstallLockOnly() error {
	args := []string{
		"install",
		pnpmLockfileOnlyFlag,
		pnpmIgnoreScriptsFlag,
		pnpmNoFrozenLockfileFlag,
	}
	fullCommand := "pnpm " + strings.Join(args, " ")
	log.Debug(fmt.Sprintf("Running '%s'", fullCommand))

	ctx, cancel := context.WithTimeout(context.Background(), pnpmInstallTimeout)
	defer cancel()

	//#nosec G204 -- False positive - the subprocess only runs after the user's approval
	cmd := exec.CommandContext(ctx, "pnpm", args...)
	cmd.Env = pnpm.buildPnpmInstallEnv()

	output, err := cmd.CombinedOutput()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return fmt.Errorf("pnpm install timed out after %v", pnpmInstallTimeout)
	}
	if err != nil {
		return fmt.Errorf("pnpm install failed: %w\nOutput: %s", err, string(output))
	}
	return nil
}

func (pnpm *PnpmPackageUpdater) buildPnpmInstallEnv() []string {
	var env []string
	for _, e := range os.Environ() {
		key := strings.SplitN(e, "=", 2)[0]
		if _, shouldOverride := pnpmInstallEnvVars[key]; !shouldOverride {
			env = append(env, e)
		}
	}
	for key, value := range pnpmInstallEnvVars {
		env = append(env, fmt.Sprintf("%s=%s", key, value))
	}
	return env
}

func (pnpm *PnpmPackageUpdater) fixVulnerabilityIfExists(vulnDetails *utils.VulnerabilityDetails, descriptorFilePath, originalWd string, vulnRegexpCompiler *regexp.Regexp) (isFileChanged bool, err error) {
	var descriptorFileData []byte
	descriptorFileData, err = os.ReadFile(descriptorFilePath)
	if err != nil {
		err = fmt.Errorf("failed to read file '%s': %s", descriptorFilePath, err.Error())
		return isFileChanged, err
	}

	if match := vulnRegexpCompiler.FindString(strings.ToLower(string(descriptorFileData))); match != "" {
		modulePath := path.Dir(descriptorFilePath)
		if err = os.Chdir(modulePath); err != nil {
			err = fmt.Errorf("failed to change directory to '%s': %s", modulePath, err.Error())
			return isFileChanged, err
		}
		defer func() {
			err = errors.Join(err, os.Chdir(originalWd))
		}()

		var nodeModulesDirExist bool
		if nodeModulesDirExist, err = fileutils.IsDirExists(filepath.Join(modulePath, "node_modules"), false); err != nil {
			return isFileChanged, err
		}

		if !nodeModulesDirExist {
			defer func() {
				err = errors.Join(err, fileutils.RemoveTempDir(filepath.Join(modulePath, "node_modules")))
			}()
		}

		if err = pnpm.CommonPackageUpdater.UpdateDependency(vulnDetails, vulnDetails.Technology.GetPackageInstallationCommand()); err != nil {
			return isFileChanged, fmt.Errorf("failed to update dependency '%s' from version '%s' to '%s': %s", vulnDetails.ImpactedDependencyName, vulnDetails.ImpactedDependencyVersion, vulnDetails.SuggestedFixedVersion, err.Error())
		}
		isFileChanged = true
	}
	return isFileChanged, err
}
