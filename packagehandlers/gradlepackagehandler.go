package packagehandlers

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

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

var gradleDescriptorsSuffixes = []string{groovyDescriptorFileSuffix, kotlinDescriptorFileSuffix}

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

func getAllGradleDescriptorFilesFullPaths(patternsToExclude ...string) (descriptorFilesFullPaths []string, err error) {
	var regexpPatternsCompilers []*regexp.Regexp
	for _, patternToExclude := range patternsToExclude {
		regexpPatternsCompilers = append(regexpPatternsCompilers, regexp.MustCompile(patternToExclude))
	}

	err = filepath.WalkDir(".", func(path string, d fs.DirEntry, innerErr error) error {
		if innerErr != nil {
			return fmt.Errorf("an error has occurred when attempting to access or traverse the file system: %w", innerErr)
		}

		if path == "." {
			return nil
		}

		for _, regexpCompiler := range regexpPatternsCompilers {
			if regexpCompiler.FindString(path) != "" {
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
		}

		var skipDirNamesWhenCollectingGradleDescriptors = map[string]struct{}{
			".git": {}, ".gradle": {}, "build": {}, "node_modules": {}, "out": {},
			".idea": {}, "dist": {}, "bin": {}, ".vscode": {},
		}

		if d.IsDir() {
			if _, skip := skipDirNamesWhenCollectingGradleDescriptors[filepath.Base(path)]; skip {
				return filepath.SkipDir
			}
			return nil
		}

		for _, suffix := range gradleDescriptorsSuffixes {
			if strings.HasSuffix(path, suffix) {
				absFilePath, absErr := filepath.Abs(path)
				if absErr != nil {
					return fmt.Errorf("couldn't retrieve file's absolute path for './%s': %w", path, absErr)
				}
				descriptorFilesFullPaths = append(descriptorFilesFullPaths, absFilePath)
			}
		}
		return nil
	})
	if err != nil {
		err = fmt.Errorf("failed to get Gradle descriptor files absolute paths: %w", err)
	}
	return
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
