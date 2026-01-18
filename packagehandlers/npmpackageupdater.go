package packagehandlers

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/jfrog/frogbot/v2/utils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
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
	noUpdateNotifierEnv    = "NO_UPDATE_NOTIFIER"

	npmDescriptorFileName = "package.json"
	npmLockFileName       = "package-lock.json"
	npmInstallTimeout     = 15 * time.Minute

	/* TODO eran
	We need to fix this regexp and ease it to find package by only package name.
	we get from the lock as exact version (without ^ or ~) and the regexp won't match the descriptor.
	We also need to see what we do with override or peer dependencies that we doent need to fix at all
	GENERAL DECISION: we fix all occurrences we find
	*/
	npmDependencyRegexpPattern  = `\s*"%s"\s*:\s*"[~^]?%s"`
	npmDependencyReplacePattern = `(\s*"%s"\s*:\s*")[~^]?[^"]+(")`
)

var npmInstallEnvVars = map[string]string{
	configIgnoreScriptsEnv: "true",
	configAuditEnv:         "false",
	configFundEnv:          "false",
	configLevelEnv:         "error",
	ciEnv:                  "true",
	noUpdateNotifierEnv:    "1",
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
	descriptorPaths, err := npm.getDescriptorsToFixFromVulnerability(vulnDetails)
	if err != nil {
		return err
	}

	originalWd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get current working directory: %w", err)
	}

	vulnRegexp := GetVulnerabilityRegexCompiler(vulnDetails.ImpactedDependencyName, vulnDetails.ImpactedDependencyVersion, npmDependencyRegexpPattern)

	var failingDescriptors []string
	for _, descriptorPath := range descriptorPaths {
		if fixErr := npm.fixVulnerabilityAndRegenerateLockIfNeeded(vulnDetails, descriptorPath, originalWd, vulnRegexp); fixErr != nil {
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

// TODO: this function is a workaround that handles the bug where only lock files are provided in vulnerability locations, instead of the descriptor files.
// TODO: After the bug is fixed we can simply call GetVulnerabilityLocations(vulnDetails, []string{npmDescriptorFileName}) and verify it exists (delete func & test)
func (npm *NpmPackageUpdater) getDescriptorsToFixFromVulnerability(vulnDetails *utils.VulnerabilityDetails) ([]string, error) {
	lockFilePaths := GetVulnerabilityLocations(vulnDetails, []string{npmLockFileName})
	if len(lockFilePaths) == 0 {
		return nil, fmt.Errorf("no location evidence was found for package %s", vulnDetails.ImpactedDependencyName)
	}

	var descriptorPaths []string
	for _, lockFilePath := range lockFilePaths {
		// We currently assume the descriptor resides in the same directory as the lock file, and this is the only supported use case
		descriptorPath := filepath.Join(filepath.Dir(lockFilePath), npmDescriptorFileName)
		fileExists, err := fileutils.IsFileExists(descriptorPath, false)
		if err != nil {
			return nil, err
		}
		if !fileExists {
			return nil, fmt.Errorf("descriptor file '%s' not found for lock file '%s': %w", descriptorPath, lockFilePath, err)
		}
		descriptorPaths = append(descriptorPaths, descriptorPath)
	}
	return descriptorPaths, nil
}

func (npm *NpmPackageUpdater) fixVulnerabilityAndRegenerateLockIfNeeded(vulnDetails *utils.VulnerabilityDetails, descriptorPath string, originalWd string, vulnRegexp *regexp.Regexp) (err error) {
	descriptorContent, err := os.ReadFile(descriptorPath)
	if err != nil {
		return fmt.Errorf("failed to read file '%s': %w", descriptorPath, err)
	}

	if !vulnRegexp.MatchString(strings.ToLower(string(descriptorContent))) {
		return fmt.Errorf("dependency '%s' with version '%s' not found in descriptor '%s' despite lock file evidence", vulnDetails.ImpactedDependencyName, vulnDetails.ImpactedDependencyVersion, descriptorPath)
	}

	backupContent := descriptorContent
	updatedContent, err := npm.updateVersionInDescriptor(descriptorContent, vulnDetails.ImpactedDependencyName, vulnDetails.SuggestedFixedVersion)
	if err != nil {
		return fmt.Errorf("failed to update version in descriptor: %w", err)
	}

	if err = os.WriteFile(descriptorPath, updatedContent, 0644); err != nil {
		return fmt.Errorf("failed to write updated descriptor '%s': %w", descriptorPath, err)
	}

	// Change to the descriptor directory for the regeneration of the lock file
	descriptorDir := filepath.Dir(descriptorPath)
	if err = os.Chdir(descriptorDir); err != nil {
		return fmt.Errorf("failed to change directory to '%s': %w", descriptorDir, err)
	}
	defer func() {
		if chErr := os.Chdir(originalWd); chErr != nil {
			err = errors.Join(err, fmt.Errorf("failed to return to original directory: %w", chErr))
		}
	}()

	lockFileExistsInRemote, checkErr := utils.IsFileExistsInRemote(npmLockFileName, originalWd, "")
	if checkErr != nil {
		log.Debug(fmt.Sprintf("Failed to check if lock file exists in git: %s. Proceeding with lock file regeneration.", checkErr.Error()))
		lockFileExistsInRemote = true
	}

	if !lockFileExistsInRemote {
		log.Debug(fmt.Sprintf("Lock file '%s' does not exist in remote, skipping lock file regeneration", npmLockFileName))
		log.Debug(fmt.Sprintf("Successfully updated '%s' from version '%s' to '%s' in descriptor '%s' without regenerating lock file", vulnDetails.ImpactedDependencyName, vulnDetails.ImpactedDependencyVersion, vulnDetails.SuggestedFixedVersion, descriptorPath))
		return
	}

	if err = npm.regenerateLockFileWithRetry(); err != nil {
		log.Warn(fmt.Sprintf("Failed to regenerate lock file after updating '%s' to version '%s': %s. Rolling back...", vulnDetails.ImpactedDependencyName, vulnDetails.SuggestedFixedVersion, err.Error()))
		if rollbackErr := os.WriteFile(descriptorPath, backupContent, 0644); rollbackErr != nil {
			return fmt.Errorf("failed to rollback descriptor after lock file regeneration failure: %w (original error: %v)", rollbackErr, err)
		}
		return err
	}
	log.Debug(fmt.Sprintf("Successfully updated '%s' from version '%s' to '%s' in descriptor '%s'", vulnDetails.ImpactedDependencyName, vulnDetails.ImpactedDependencyVersion, vulnDetails.SuggestedFixedVersion, descriptorPath))
	return nil
}

func (npm *NpmPackageUpdater) updateVersionInDescriptor(content []byte, packageName, newVersion string) ([]byte, error) {
	escapedName := regexp.QuoteMeta(packageName)
	replacePattern := fmt.Sprintf(npmDependencyReplacePattern, escapedName)
	replaceRegex := regexp.MustCompile("(?i)" + replacePattern)

	replacement := fmt.Sprintf("${1}%s${2}", newVersion)
	updatedContent := replaceRegex.ReplaceAll(content, []byte(replacement))

	if string(content) == string(updatedContent) {
		return nil, fmt.Errorf("failed to find and replace version for package '%s'", packageName)
	}
	return updatedContent, nil
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

	cmd.Env = npm.buildIsolatedEnv()
	output, err := cmd.CombinedOutput()

	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return fmt.Errorf("npm install timed out after %v", npmInstallTimeout)
	}

	if err != nil {
		return fmt.Errorf("npm install failed: %w\nOutput: %s", err, string(output))
	}

	return nil
}

// Creates an environment slice with npm isolation variables that override user's .npmrc settings for specific options while allowing registry configuration to pass through
func (npm *NpmPackageUpdater) buildIsolatedEnv() []string {
	env := os.Environ()
	for key, value := range npmInstallEnvVars {
		env = append(env, fmt.Sprintf("%s=%s", key, value))
	}

	return env
}
