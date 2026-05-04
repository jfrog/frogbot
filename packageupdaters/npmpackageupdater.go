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
	ciEnv                  = "CI"
	configIgnoreScriptsEnv = "NPM_CONFIG_IGNORE_SCRIPTS"
	configAuditEnv         = "NPM_CONFIG_AUDIT"
	configFundEnv          = "NPM_CONFIG_FUND"
	configLevelEnv         = "NPM_CONFIG_LOGLEVEL"

	npmPackageLockOnlyFlag = "--package-lock-only"
	npmIgnoreScriptsFlag   = "--ignore-scripts"
	npmNoAuditFlag         = "--no-audit"
	npmLegacyPeerDepsFlag  = "--legacy-peer-deps"
	npmNoFundFlag          = "--no-fund"

	npmLockFileName = "package-lock.json"

	npmInstallTimeout = 15 * time.Minute

	npmEreresolveErrorPrefix = "ERESOLVE"
)

var npmInstallEnvVars = map[string]string{
	configIgnoreScriptsEnv: "true",
	configAuditEnv:         "false",
	configFundEnv:          "false",
	configLevelEnv:         "error",
	ciEnv:                  "true",
}

type NpmPackageUpdater struct {
	CommonPackageUpdater
}

func (npm *NpmPackageUpdater) UpdateDependency(vulnDetails *utils.VulnerabilityDetails) error {
	if vulnDetails.IsDirectDependency {
		return npm.updateDirectDependency(vulnDetails)
	}
	return &utils.ErrUnsupportedFix{
		PackageName:  vulnDetails.ImpactedDependencyName,
		FixedVersion: vulnDetails.SuggestedFixedVersion,
		ErrorType:    utils.IndirectDependencyFixNotSupported,
	}
}

func (npm *NpmPackageUpdater) updateDirectDependency(vulnDetails *utils.VulnerabilityDetails) error {
	descriptorPaths := npm.CollectVulnerabilityDescriptorPaths(vulnDetails, []string{nodePackageJSONFileName}, []string{nodeModulesDirName})
	if len(descriptorPaths) == 0 {
		return fmt.Errorf("no descriptor evidence was found for package %s", vulnDetails.ImpactedDependencyName)
	}

	originalWd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get current working directory: %w", err)
	}

	var failingDescriptors []string
	for _, descriptorPath := range descriptorPaths {
		if fixErr := npm.fixVulnerabilityAndRegenerateLock(vulnDetails, descriptorPath, originalWd); fixErr != nil {
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

func (npm *NpmPackageUpdater) fixVulnerabilityAndRegenerateLock(vulnDetails *utils.VulnerabilityDetails, descriptorPath string, originalWd string) error {
	backupContent, err := npm.UpdatePackageJSONDescriptor(descriptorPath, vulnDetails.ImpactedDependencyName, vulnDetails.SuggestedFixedVersion)
	if err != nil {
		return err
	}

	descriptorDir := filepath.Dir(descriptorPath)
	lockFilePath := filepath.Join(descriptorDir, npmLockFileName)

	lockFileTracked, checkErr := utils.IsFileTrackedByGit(lockFilePath, originalWd)
	if checkErr != nil {
		log.Debug(fmt.Sprintf("Failed to check if lock file is tracked in git: %s. Proceeding with lock file regeneration.", checkErr.Error()))
		lockFileTracked = true
	}

	if !lockFileTracked {
		log.Debug(fmt.Sprintf("Lock file '%s' is not tracked in git, skipping lock file regeneration", lockFilePath))
		return nil
	}

	if err = npm.regenerateLockfile(vulnDetails, descriptorPath, originalWd, backupContent); err != nil {
		return err
	}

	log.Debug(fmt.Sprintf("Successfully updated '%s' from version '%s' to '%s' in descriptor '%s'", vulnDetails.ImpactedDependencyName, vulnDetails.ImpactedDependencyVersion, vulnDetails.SuggestedFixedVersion, descriptorPath))
	return nil
}

func (npm *NpmPackageUpdater) regenerateLockfile(vulnDetails *utils.VulnerabilityDetails, descriptorPath, originalWd string, backupContent []byte) (err error) {
	descriptorDir := filepath.Dir(descriptorPath)
	if err = os.Chdir(descriptorDir); err != nil {
		return fmt.Errorf("failed to change directory to '%s': %w", descriptorDir, err)
	}
	defer func() {
		if chErr := os.Chdir(originalWd); chErr != nil {
			err = errors.Join(err, fmt.Errorf("failed to return to original directory: %w", chErr))
		}
	}()

	if err = npm.regenerateLockFileWithRetry(); err != nil {
		log.Warn(fmt.Sprintf("Failed to regenerate lock file after updating '%s' to version '%s': %s. Rolling back...", vulnDetails.ImpactedDependencyName, vulnDetails.SuggestedFixedVersion, err.Error()))
		if rollbackErr := os.WriteFile(descriptorPath, backupContent, 0644); rollbackErr != nil {
			return fmt.Errorf("failed to rollback descriptor after lock file regeneration failure: %w (original error: %v)", rollbackErr, err)
		}
		return err
	}
	return nil
}

func (npm *NpmPackageUpdater) getFixedDescriptor(content []byte, packageName, newVersion, descriptorPath string) ([]byte, error) {
	return npm.GetFixedPackageJSONManifest(content, packageName, newVersion, descriptorPath)
}

func (npm *NpmPackageUpdater) regenerateLockFileWithRetry() error {
	err := npm.runNpmInstall(false)
	if err != nil {
		if strings.Contains(err.Error(), npmEreresolveErrorPrefix) {
			log.Debug(fmt.Sprintf("First npm install attempt failed due to peer dependency conflict. Retrying with %s...", npmLegacyPeerDepsFlag))
			if err = npm.runNpmInstall(true); err != nil {
				return fmt.Errorf("npm install failed after retry with %s: %w", npmLegacyPeerDepsFlag, err)
			}
			return nil
		}
		log.Debug(fmt.Sprintf("First npm install attempt failed: %s. Retrying...", err.Error()))
		if err = npm.runNpmInstall(false); err != nil {
			return fmt.Errorf("npm install failed after retry: %w", err)
		}
	}
	return nil
}

func (npm *NpmPackageUpdater) runNpmInstall(useLegacyPeerDeps bool) error {
	args := []string{
		"install",
		npmPackageLockOnlyFlag,
		npmIgnoreScriptsFlag,
		npmNoAuditFlag,
		npmNoFundFlag,
	}
	if useLegacyPeerDeps {
		args = append(args, npmLegacyPeerDepsFlag)
	}

	fullCommand := "npm " + strings.Join(args, " ")
	log.Debug(fmt.Sprintf("Running '%s'", fullCommand))

	ctx, cancel := context.WithTimeout(context.Background(), npmInstallTimeout)
	defer cancel()

	//#nosec G204 -- False positive - the subprocess only runs after the user's approval
	cmd := exec.CommandContext(ctx, "npm", args...)

	cmd.Env = npm.buildEnvWithOverrides(npmInstallEnvVars)
	output, err := cmd.CombinedOutput()

	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return fmt.Errorf("npm install timed out after %v", npmInstallTimeout)
	}

	if err != nil {
		return fmt.Errorf("npm install failed: %w\nOutput: %s", err, string(output))
	}

	return nil
}

func escapeJsonPathKey(key string) string {
	var c CommonPackageUpdater
	return c.EscapeJSONPathKey(key)
}
