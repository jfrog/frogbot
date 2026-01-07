package packagehandlers

import (
	"context"
	"errors"
	"fmt"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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
	noUpdateNotifierEnv    = "NO_UPDATE_NOTIFIER"

	npmDescriptorFile = "package.json"
	npmInstallTimeout = 15 * time.Minute

	// Matches: "package-name": "version" with optional ^ or ~ prefix
	npmDependencyRegexpPattern = `\s*"%s"\s*:\s*"[~^]?%s"`
	// Regex pattern for replacement - captures the groups for reconstruction
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

type NpmPackageHandler struct {
	CommonPackageHandler
}

// TODO eran check manually connection to Artifactory with self defined .npmrc and that it is not being override by our env vars

func (npm *NpmPackageHandler) UpdateDependency(vulnDetails *utils.VulnerabilityDetails) error {
	if vulnDetails.IsDirectDependency {
		return npm.updateDirectDependency(vulnDetails)
	}
	return &utils.ErrUnsupportedFix{
		PackageName:  vulnDetails.ImpactedDependencyName,
		FixedVersion: vulnDetails.SuggestedFixedVersion,
		ErrorType:    utils.IndirectDependencyFixNotSupported,
	}
}

func (npm *NpmPackageHandler) updateDirectDependency(vulnDetails *utils.VulnerabilityDetails) error {
	/*
		// todo eran remove this assignment
		vulnDetails.ImpactPaths[0][1].Location = &formats.Location{
			File: "package-lock.json",
		}

	*/
	descriptorPaths, err := npm.getDescriptorsToFixFromVulnerability(vulnDetails)
	if err != nil {
		return err
	}

	originalWd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get current working directory: %w", err)
	}

	vulnRegexp := GetVulnerabilityRegexCompiler(vulnDetails.ImpactedDependencyName, vulnDetails.ImpactedDependencyVersion, npmDependencyRegexpPattern)

	for _, descriptorPath := range descriptorPaths {
		if fixErr := npm.fixVulnerabilityInDescriptor(vulnDetails, descriptorPath, originalWd, vulnRegexp); fixErr != nil {
			err = errors.Join(err, fixErr)
		}
	}
	if err != nil {
		return fmt.Errorf("failed to fix vulnerability in one of the following descriptors [%s]: %w", strings.Join(descriptorPaths, ", "), err)
	}

	return nil
}

// Returns all descriptors related to the vulnerability based on its lock file locations
func (npm *NpmPackageHandler) getDescriptorsToFixFromVulnerability(vulnDetails *utils.VulnerabilityDetails) ([]string, error) {
	lockFilePaths := GetVulnerabilityLocations(vulnDetails)
	if len(lockFilePaths) == 0 {
		return nil, fmt.Errorf("no location evidence was found for package %s", vulnDetails.ImpactedDependencyName)
	}

	var descriptorPaths []string
	for _, lockFilePath := range lockFilePaths {
		// We currently assume the descriptor resides in the same directory as the lock file, and this is the only supported use case
		descriptorPath := filepath.Join(filepath.Dir(lockFilePath), npmDescriptorFile)
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

func (npm *NpmPackageHandler) fixVulnerabilityInDescriptor(vulnDetails *utils.VulnerabilityDetails, descriptorPath string, originalWd string, vulnRegexp *regexp.Regexp) (err error) {
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

	if err = npm.regenerateLockFileWithRetry(); err != nil {
		log.Warn(fmt.Sprintf("Failed to regenerate lock file after updating '%s' to version '%s': %s. Rolling back...", vulnDetails.ImpactedDependencyName, vulnDetails.SuggestedFixedVersion, err.Error()))
		if rollbackErr := os.WriteFile(descriptorPath, backupContent, 0644); rollbackErr != nil {
			return fmt.Errorf("failed to rollback descriptor after lock file regeneration failure: %w (original error: %v)", rollbackErr, err)
		}
		return err
	}

	log.Debug(fmt.Sprintf("Successfully updated '%s' from version '%s' to '%s'", vulnDetails.ImpactedDependencyName, vulnDetails.ImpactedDependencyVersion, vulnDetails.SuggestedFixedVersion))
	return nil
}

func (npm *NpmPackageHandler) updateVersionInDescriptor(content []byte, packageName, newVersion string) ([]byte, error) {
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

func (npm *NpmPackageHandler) regenerateLockFileWithRetry() error {
	err := npm.runNpmInstall()
	if err == nil {
		return nil
	}

	log.Debug(fmt.Sprintf("First npm install attempt failed: %s. Retrying...", err.Error()))
	if err = npm.runNpmInstall(); err != nil {
		return fmt.Errorf("npm install failed after retry: %w", err)
	}
	return nil
}

func (npm *NpmPackageHandler) runNpmInstall() error {
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

	// TODO eran check manually that timeout is working by setting very low timeout
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return fmt.Errorf("npm install timed out after %v", npmInstallTimeout)
	}

	if err != nil {
		return fmt.Errorf("npm install failed: %w\nOutput: %s", err, string(output))
	}

	return nil
}

// Creates an environment slice with npm isolation variables that override user's .npmrc settings for specific options while allowing registry configuration to pass through
func (npm *NpmPackageHandler) buildIsolatedEnv() []string {
	env := os.Environ()
	for key, value := range npmInstallEnvVars {
		env = append(env, fmt.Sprintf("%s=%s", key, value))
	}

	return env
}
