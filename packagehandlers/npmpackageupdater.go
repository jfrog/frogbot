package packagehandlers

import (
	"bytes"
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

	npmDescriptorFileName       = "package.json"
	npmLockFileName             = "package-lock.json"
	dependenciesSection         = "dependencies"
	devDependenciesSection      = "devDependencies"
	optionalDependenciesSection = "optionalDependencies"
	overridesSection            = "overrides"

	npmInstallTimeout = 15 * time.Minute

	npmDependencyRegexpPattern  = `\s*"%s"\s*:\s*"[^"]+"`
	npmDependencyReplacePattern = `(\s*"%s"\s*:\s*")[^"]+(")`
)

var npmAllowedSections = []string{dependenciesSection, devDependenciesSection, optionalDependenciesSection, overridesSection}

var npmInstallEnvVars = map[string]string{
	configIgnoreScriptsEnv: "true",
	configAuditEnv:         "false",
	configFundEnv:          "false",
	configLevelEnv:         "error",
	ciEnv:                  "true",
	noUpdateNotifierEnv:    "1",
}

type byteRange struct {
	start int
	end   int
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

	vulnRegexp := BuildPackageRegex(vulnDetails.ImpactedDependencyName, npmDependencyRegexpPattern)

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
		return fmt.Errorf("dependency '%s' not found in descriptor '%s' despite lock file evidence", vulnDetails.ImpactedDependencyName, descriptorPath)
	}

	backupContent := make([]byte, len(descriptorContent))
	copy(backupContent, descriptorContent)
	updatedContent, err := npm.updateVersionInDescriptor(descriptorContent, vulnDetails.ImpactedDependencyName, vulnDetails.SuggestedFixedVersion, descriptorPath)
	if err != nil {
		return fmt.Errorf("failed to update version in descriptor: %w", err)
	}

	if err = os.WriteFile(descriptorPath, updatedContent, 0644); err != nil {
		return fmt.Errorf("failed to write updated descriptor '%s': %w", descriptorPath, err)
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

	lockFileExistsInRemote, checkErr := utils.IsFileExistsInRemote(npmLockFileName, originalWd, npm.baseBranch)
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

func (npm *NpmPackageUpdater) updateVersionInDescriptor(content []byte, packageName, newVersion, descriptorPath string) ([]byte, error) {
	sectionRanges := npm.findAllowedSectionRanges(content)
	if len(sectionRanges) == 0 {
		return nil, fmt.Errorf("no dependency sections found in descriptor")
	}

	escapedName := regexp.QuoteMeta(packageName)
	replacePattern := fmt.Sprintf(npmDependencyReplacePattern, escapedName)
	replaceRegex := regexp.MustCompile("(?i)" + replacePattern)

	validMatches := findValidMatches(replaceRegex, content, sectionRanges)
	if len(validMatches) == 0 {
		return nil, fmt.Errorf("package '%s' not found in allowed sections [%s] in '%s'", packageName, strings.Join(npmAllowedSections, ", "), descriptorPath)
	}

	return replaceVersionInMatches(content, validMatches, replaceRegex, newVersion), nil
}

func replaceVersionInMatches(content []byte, matches [][]int, replaceRegex *regexp.Regexp, newVersion string) []byte {
	replacement := []byte(fmt.Sprintf("${1}%s${2}", newVersion))
	for i := len(matches) - 1; i >= 0; i-- {
		match := matches[i]
		matchedText := content[match[0]:match[1]]
		replacedText := replaceRegex.ReplaceAll(matchedText, replacement)
		content = append(content[:match[0]], append(replacedText, content[match[1]:]...)...)
	}
	return content
}

func findValidMatches(replaceRegex *regexp.Regexp, content []byte, sectionRanges []byteRange) [][]int {
	matches := replaceRegex.FindAllIndex(content, -1)
	var validMatches [][]int
	for _, match := range matches {
		if isPositionInRanges(match[0], sectionRanges) {
			validMatches = append(validMatches, match)
		}
	}
	return validMatches
}

func (npm *NpmPackageUpdater) findAllowedSectionRanges(content []byte) []byteRange {
	var ranges []byteRange
	contentLower := bytes.ToLower(content)

	for _, sectionName := range npmAllowedSections {
		pattern := fmt.Sprintf(`"%s"\s*:\s*\{`, strings.ToLower(sectionName))
		regex := regexp.MustCompile(pattern)

		match := regex.FindIndex(contentLower)
		if match != nil {
			openBrace := bytes.IndexByte(content[match[0]:match[1]], '{') + match[0]
			closeBrace := npm.findMatchingBrace(content, openBrace)
			if closeBrace != -1 {
				ranges = append(ranges, byteRange{start: openBrace, end: closeBrace})
			}
		}
	}

	return ranges
}

func (npm *NpmPackageUpdater) findMatchingBrace(content []byte, openBracePos int) int {
	depth := 1
	inString := false

	for i := openBracePos + 1; i < len(content); i++ {
		c := content[i]

		if c == '"' && (i == 0 || content[i-1] != '\\') {
			inString = !inString
			continue
		}

		if !inString {
			switch c {
			case '{':
				depth++
			case '}':
				depth--
				if depth == 0 {
					return i
				}
			}
		}
	}

	return -1
}

func isPositionInRanges(pos int, ranges []byteRange) bool {
	for _, r := range ranges {
		if pos >= r.start && pos <= r.end {
			return true
		}
	}
	return false
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
