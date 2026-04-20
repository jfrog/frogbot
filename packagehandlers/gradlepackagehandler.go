package packagehandlers

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/jfrog/jfrog-cli-security/utils/techutils"

	"github.com/jfrog/frogbot/v2/utils"
)

const (
	groovyDescriptorFileSuffix    = "build.gradle"
	kotlinDescriptorFileSuffix    = "build.gradle.kts"
	apostrophes                   = "[\\\"|\\']"
	directMapRegexpEntry          = "\\s*%s\\s*[:|=]\\s*"
	directStringWithVersionFormat = "%s:%s:%s"
)

// Regexp pattern for "map" format dependencies
// Example: group: "junit", name: "junit", version: "1.0.0" | group = "junit", name = "junit", version = "1.0.0"
var directMapWithVersionRegexp = getMapRegexpEntry("group") + "," + getMapRegexpEntry("name") + "," + getMapRegexpEntry("version")

func getMapRegexpEntry(mapEntry string) string {
	return fmt.Sprintf(directMapRegexpEntry, mapEntry) + apostrophes + "%s" + apostrophes
}

type GradlePackageHandler struct {
	CommonPackageHandler
}

func (gph *GradlePackageHandler) UpdateDependency(vulnDetails *utils.VulnerabilityDetails) error {
	if vulnDetails.IsDirectDependency {
		return gph.updateDirectDependency(vulnDetails)
	}

	return &utils.ErrUnsupportedFix{
		PackageName:  vulnDetails.ImpactedDependencyName,
		FixedVersion: vulnDetails.SuggestedFixedVersion,
		ErrorType:    utils.IndirectDependencyFixNotSupported,
	}
}

func (gph *GradlePackageHandler) updateDirectDependency(vulnDetails *utils.VulnerabilityDetails) (err error) {
	if !isVersionSupportedForFix(vulnDetails.ImpactedDependencyVersion) {
		return &utils.ErrUnsupportedFix{
			PackageName:  vulnDetails.ImpactedDependencyName,
			FixedVersion: vulnDetails.SuggestedFixedVersion,
			ErrorType:    utils.UnsupportedForFixVulnerableVersion,
		}
	}

	// A gradle project may contain several descriptor files in several sub-modules. Each vulnerability may be found in each of the descriptor files.
	// Therefore we iterate over every descriptor file for each vulnerability and try to find and fix it.
	var descriptorFilesFullPaths []string
	descriptorFilesFullPaths, err = getAllGradleDescriptorFilesFullPaths()
	if err != nil {
		return
	}

	isAnyDescriptorFileChanged := false
	for _, descriptorFilePath := range descriptorFilesFullPaths {
		var isFileChanged bool
		isFileChanged, err = gph.fixVulnerabilityIfExists(descriptorFilePath, vulnDetails)
		if err != nil {
			return
		}
		// We use logical OR to save information over all descriptor files whether there is at least one file that has been changed
		isAnyDescriptorFileChanged = isAnyDescriptorFileChanged || isFileChanged
	}

	if !isAnyDescriptorFileChanged {
		err = fmt.Errorf("impacted package '%s' was not found or could not be fixed in all descriptor files", vulnDetails.ImpactedDependencyName)
	}
	return
}

// getAllGradleDescriptorFilesFullPaths lists build.gradle / build.gradle.kts files using the same
// discovery logic as the CLI (techutils.DetectTechnologiesDescriptors). patternsToExclude are passed
// as exclude path patterns to that API (first element used; if multiple are given they are combined with |).
func getAllGradleDescriptorFilesFullPaths(patternsToExclude ...string) (descriptorFilesFullPaths []string, err error) {
	excludePattern := joinExcludePatterns(patternsToExclude)
	detected, err := techutils.DetectTechnologiesDescriptors(".", true, []string{techutils.Gradle.String()}, map[techutils.Technology][]string{}, excludePattern)
	if err != nil {
		err = fmt.Errorf("failed to detect Gradle descriptors: %w", err)
		return
	}
	gradleDirs, ok := detected[techutils.Gradle]
	if !ok || len(gradleDirs) == 0 {
		return
	}
	seen := make(map[string]struct{})
	for _, paths := range gradleDirs {
		for _, p := range paths {
			if !isGradleBuildFilePath(p) {
				continue
			}
			var absFilePath string
			absFilePath, err = filepath.Abs(p)
			if err != nil {
				err = fmt.Errorf("couldn't retrieve absolute path for '%s': %w", p, err)
				return
			}
			if _, dup := seen[absFilePath]; dup {
				continue
			}
			seen[absFilePath] = struct{}{}
			descriptorFilesFullPaths = append(descriptorFilesFullPaths, absFilePath)
		}
	}
	return
}

func joinExcludePatterns(patterns []string) string {
	var nonEmpty []string
	for _, p := range patterns {
		p = strings.TrimSpace(p)
		if p != "" {
			nonEmpty = append(nonEmpty, p)
		}
	}
	if len(nonEmpty) == 0 {
		return ""
	}
	if len(nonEmpty) == 1 {
		return nonEmpty[0]
	}
	return strings.Join(nonEmpty, "|")
}

func isGradleBuildFilePath(p string) bool {
	return strings.HasSuffix(p, groovyDescriptorFileSuffix) || strings.HasSuffix(p, kotlinDescriptorFileSuffix)
}

// Checks if the impacted version is currently supported for fix
func isVersionSupportedForFix(impactedVersion string) bool {
	if strings.Contains(impactedVersion, "+") ||
		(strings.Contains(impactedVersion, "[") || strings.Contains(impactedVersion, "(")) ||
		strings.Contains(impactedVersion, "latest.release") {
		return false
	}
	return true
}

// Fixes all direct occurrences of the given vulnerability in the given descriptor file, if vulnerability occurs
func (gph *GradlePackageHandler) fixVulnerabilityIfExists(descriptorFilePath string, vulnDetails *utils.VulnerabilityDetails) (isFileChanged bool, err error) {
	byteFileContent, err := os.ReadFile(descriptorFilePath)
	if err != nil {
		err = fmt.Errorf("couldn't read file '%s': %s", descriptorFilePath, err.Error())
		return
	}
	fileContent := string(byteFileContent)
	originalFile := fileContent

	depGroup, depName, err := getVulnerabilityGroupAndName(vulnDetails.ImpactedDependencyName)
	if err != nil {
		return
	}

	// Fixing all vulnerable rows given in a string format. For Example: implementation "junit:junit:4.7"
	directStringVulnerableRow := fmt.Sprintf(directStringWithVersionFormat, depGroup, depName, vulnDetails.ImpactedDependencyVersion)
	directStringFixedRow := fmt.Sprintf(directStringWithVersionFormat, depGroup, depName, vulnDetails.SuggestedFixedVersion)
	fileContent = strings.ReplaceAll(fileContent, directStringVulnerableRow, directStringFixedRow)

	// We replace '.' characters to '\\.' since '.' in order to correctly capture '.' character using regexps
	regexpAdjustedDepGroup := strings.ReplaceAll(depGroup, ".", "\\.")
	regexpAdjustedDepName := strings.ReplaceAll(depName, ".", "\\.")
	regexpAdjustedImpactedVersion := strings.ReplaceAll(vulnDetails.ImpactedDependencyVersion, ".", "\\.")

	// Fixing all vulnerable rows given in a map format. For Example: implementation group: "junit", name: "junit", version: "4.7"
	mapRegexpForVulnerability := fmt.Sprintf(directMapWithVersionRegexp, regexpAdjustedDepGroup, regexpAdjustedDepName, regexpAdjustedImpactedVersion)
	regexpCompiler := regexp.MustCompile(mapRegexpForVulnerability)
	if rowsMatches := regexpCompiler.FindAllString(fileContent, -1); rowsMatches != nil {
		for _, entry := range rowsMatches {
			fixedRow := strings.Replace(entry, vulnDetails.ImpactedDependencyVersion, vulnDetails.SuggestedFixedVersion, 1)
			fileContent = strings.ReplaceAll(fileContent, entry, fixedRow)
		}
	}

	// If there is no changes in the file we finish dealing with the current descriptor file
	if fileContent == originalFile {
		return
	}
	isFileChanged = true

	err = writeUpdatedBuildFile(descriptorFilePath, fileContent)
	return
}

// Returns separated 'group' and 'name' for a given vulnerability name. In addition replaces every '.' char into '\\.' since the output will be used for a regexp
func getVulnerabilityGroupAndName(impactedDependencyName string) (depGroup string, depName string, err error) {
	seperatedImpactedDepName := strings.Split(impactedDependencyName, ":")
	if len(seperatedImpactedDepName) != 2 {
		err = fmt.Errorf("unable to parse impacted dependency name '%s'", impactedDependencyName)
		return
	}
	return seperatedImpactedDepName[0], seperatedImpactedDepName[1], err
}

// Writes the updated content of the descriptor's file into the file
func writeUpdatedBuildFile(filePath string, fileContent string) (err error) {
	cleanPath := filepath.Clean(filePath)
	fileInfo, err := os.Stat(cleanPath)
	if err != nil {
		err = fmt.Errorf("couldn't get file info for file '%s': %s", filePath, err.Error())
		return
	}

	err = os.WriteFile(filePath, []byte(fileContent), fileInfo.Mode()) // #nosec G703
	if err != nil {
		err = fmt.Errorf("couldn't write fixes to file '%s': %q", filePath, err)
	}
	return
}
