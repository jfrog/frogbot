package packagehandlers

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/jfrog/frogbot/v2/utils"
	"github.com/jfrog/jfrog-client-go/utils/log"
)

const (
	npmPackageLockOnlyFlag = "--package-lock-only"
	npmIgnoreScriptsFlag   = "--ignore-scripts"
	npmNoAuditFlag         = "--no-audit"
	npmNoFundFlag          = "--no-fund"

	configIgnoreScriptsEnv = "NPM_CONFIG_IGNORE_SCRIPTS"
	configAuditEnv         = "NPM_CONFIG_AUDIT"
	configFundEnv          = "NPM_CONFIG_FUND"
	configLevelEnv         = "NPM_CONFIG_LOGLEVEL"
	ciEnv                  = "CI"

	npmLockFileName             = "package-lock.json"
	dependenciesSection         = "dependencies"
	devDependenciesSection      = "devDependencies"
	optionalDependenciesSection = "optionalDependencies"
	overridesSection            = "overrides"

	npmInstallTimeout = 15 * time.Minute
)

var npmAllowedSections = []string{dependenciesSection, devDependenciesSection, optionalDependenciesSection, overridesSection}

var npmInstallEnvVars = map[string]string{
	configIgnoreScriptsEnv: "true",
	configAuditEnv:         "false",
	configFundEnv:          "false",
	configLevelEnv:         "error",
	ciEnv:                  "true",
}

type NpmPackageUpdater struct {
	CommonPackageHandler
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
	descriptorPaths, err := GetDescriptorsToFixFromVulnerability(vulnDetails, npmLockFileName)
	if err != nil {
		return err
	}

	originalWd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get current working directory: %w", err)
	}

	var failingDescriptors []string
	for _, descriptorPath := range descriptorPaths {
		if fixErr := UpdatePackageAndRegenerateLock(
			vulnDetails.ImpactedDependencyName,
			vulnDetails.ImpactedDependencyVersion,
			vulnDetails.SuggestedFixedVersion,
			descriptorPath,
			originalWd,
			npmLockFileName,
			npmAllowedSections,
			npm.regenerateLockFileWithRetry,
		); fixErr != nil {
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

func (npm *NpmPackageUpdater) regenerateLockFileWithRetry() error {
	err := npm.runNpmInstall()
	if err != nil {
		log.Debug(fmt.Sprintf("First npm install attempt failed: %s. Retrying...", err.Error()))
		if err = npm.runNpmInstall(); err != nil {
			return fmt.Errorf("npm install failed after retry: %w", err)
		}
	}
	return nil
}

func (npm *NpmPackageUpdater) runNpmInstall() error {
	args := []string{
		"install",
		npmPackageLockOnlyFlag,
		npmIgnoreScriptsFlag,
		npmNoAuditFlag,
		npmNoFundFlag,
	}

	fullCommand := "npm " + strings.Join(args, " ")
	log.Debug(fmt.Sprintf("Running '%s'", fullCommand))

	ctx, cancel := context.WithTimeout(context.Background(), npmInstallTimeout)
	defer cancel()

	//#nosec G204 -- False positive - the subprocess only runs after the user's approval
	cmd := exec.CommandContext(ctx, "npm", args...)

	cmd.Env = buildIsolatedEnv(npmInstallEnvVars)
	output, err := cmd.CombinedOutput()

	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return fmt.Errorf("npm install timed out after %v", npmInstallTimeout)
	}

	if err != nil {
		return fmt.Errorf("npm install failed: %w\nOutput: %s", err, string(output))
	}

	return nil
}
