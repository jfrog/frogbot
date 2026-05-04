package packageupdaters

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/jfrog/jfrog-client-go/utils/log"

	"github.com/jfrog/frogbot/v2/utils"
)

const (
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

// pnpmFilterCoordinateStyleDescriptorPaths removes evidence paths that look like "pkg@version/package.json".
// Npm does not apply this filter at fix time; see evidencePathLooksLikeNpmPackageCoordinate in commonpackageupdater.go.
func pnpmFilterCoordinateStyleDescriptorPaths(paths []string) []string {
	if len(paths) == 0 {
		return paths
	}
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		if !evidencePathLooksLikeNpmPackageCoordinate(p) {
			out = append(out, p)
		}
	}
	return out
}

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
	descriptorPaths = pnpmFilterCoordinateStyleDescriptorPaths(descriptorPaths)
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
		//#nosec G306 -- 0644 is correct for a checked-out source file.
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
	cmd.Env = pnpm.buildEnvWithOverrides(pnpmInstallEnvVars)

	output, err := cmd.CombinedOutput()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return fmt.Errorf("pnpm install timed out after %v", pnpmInstallTimeout)
	}
	if err != nil {
		return fmt.Errorf("pnpm install failed: %w\nOutput: %s", err, string(output))
	}
	return nil
}
