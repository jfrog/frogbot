package packagehandlers

import (
	"fmt"
	"github.com/jfrog/frogbot/utils"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	groovyBuildFileSuffix         = "build.gradle"
	kotlinBuildFileSuffix         = "build.gradle.kts"
	apostrophes                   = "[\\\"|\\']"
	directMapRegexpEntry          = "\\s*%s\\s*[:|=]\\s*"
	directStringWithVersionFormat = "%s:%s:%s"
)

var regexpPatterns []string
var directMapWithVersionRegexp string

func init() {
	/*
		// Example: junit:junit:1.0.0
		regexpPatterns = append(regexpPatterns, directStringWithVersionFormat)

		groupEntry := getMapRegexpEntry("group")
		nameEntry := getMapRegexpEntry("name")
		versionEntry := getMapRegexpEntry("version")

		// Example: group: "junit", name: "junit", version: "1.0.0" | group = "junit", name = "junit", version = "1.0.0"
		directMapRegexpPattern := groupEntry + "," + nameEntry + "," + versionEntry
		regexpPatterns = append(regexpPatterns, directMapRegexpPattern)
	*/

	// Initializing a regexp pattern for map dependencies
	// Example: group: "junit", name: "junit", version: "1.0.0" | group = "junit", name = "junit", version = "1.0.0"
	groupEntry := getMapRegexpEntry("group")
	nameEntry := getMapRegexpEntry("name")
	versionEntry := getMapRegexpEntry("version")
	directMapWithVersionRegexp = groupEntry + "," + nameEntry + "," + versionEntry
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
	descriptorFilesPaths, err := getDescriptorFilesPaths()
	if err != nil {
		return
	}

	for _, descriptorFilePath := range descriptorFilesPaths {
		err = fixVulnerabilityIfExists(descriptorFilePath, vulnDetails)
		if err != nil {
			return
		}
	}

	return
}

// isVersionSupportedForFix checks if the impacted version is currently supported for fix
func isVersionSupportedForFix(impactedVersion string) bool {
	if strings.Contains(impactedVersion, "+") ||
		(strings.Contains(impactedVersion, "[") || strings.Contains(impactedVersion, "(")) ||
		strings.Contains(impactedVersion, "latest.release") {
		return false
	}
	return true
}

// getDescriptorFilesPaths collects all descriptor files absolute paths
func getDescriptorFilesPaths() (descriptorFilesPaths []string, err error) {
	err = filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("error has occured when trying to access or traverse the files system: %s", err.Error())
		}

		if d.Type().IsRegular() && (strings.HasSuffix(path, groovyBuildFileSuffix) || strings.HasSuffix(path, kotlinBuildFileSuffix)) {
			absFilePath, err := filepath.Abs(path)
			if err != nil {
				err = fmt.Errorf("couldn't retrieve file's absolute path for ./%s", path)
				return err
			}
			descriptorFilesPaths = append(descriptorFilesPaths, absFilePath)
		}
		return err
	})
	return
}

// fixVulnerabilityIfExists fixes all direct occurrences (string/map) of the given vulnerability in the given descriptor file if vulnerability occurs
func fixVulnerabilityIfExists(descriptorFilePath string, vulnDetails *utils.VulnerabilityDetails) (err error) {
	byteFileContent, err := os.ReadFile(descriptorFilePath)
	if err != nil {
		err = fmt.Errorf("couldn't read file '%s': %s", descriptorFilePath, err.Error())
		return
	}
	fileContent := string(byteFileContent)

	depGroup, depName, err := getVulnerabilityGroupAndName(vulnDetails.ImpactedDependencyName)
	if err != nil {
		return
	}
	// Fixing all vulnerable rows in string format
	directStringVulnerableRow := fmt.Sprintf(directStringWithVersionFormat, depGroup, depName, vulnDetails.ImpactedDependencyVersion)
	directStringFixedRow := fmt.Sprintf(directStringWithVersionFormat, depGroup, depName, vulnDetails.SuggestedFixedVersion)
	fileContent = strings.ReplaceAll(fileContent, directStringVulnerableRow, directStringFixedRow)

	// Fixing all vulnerable rows in a map format
	mapRegexpForVulnerability := fmt.Sprintf(directMapWithVersionRegexp, depGroup, depName, vulnDetails.ImpactedDependencyVersion)
	regexpCompiler := regexp.MustCompile(mapRegexpForVulnerability)
	if rowsMatches := regexpCompiler.FindAllString(fileContent, -1); rowsMatches != nil {
		for _, entry := range rowsMatches {
			fixedRow := strings.Replace(entry, vulnDetails.ImpactedDependencyVersion, vulnDetails.SuggestedFixedVersion, 1)
			fileContent = strings.ReplaceAll(fileContent, entry, fixedRow)
		}
	}

	/*
		vulnerabilityPatterns, err := getPatternCompilersForVulnerability(vulnDetails)
		if err != nil {
			return
		}

		for _, regexpCompiler := range vulnerabilityPatterns {
			if matches := regexpCompiler.FindAllString(fileContent, -1); matches != nil {
				uniqueMatches := datastructures.MakeSet[string]()
				for _, match := range matches {
					uniqueMatches.Add(strings.TrimSpace(match))
				}

				for _, entry := range uniqueMatches.ToSlice() {
					modifiedContent := strings.Replace(entry, vulnDetails.ImpactedDependencyVersion, vulnDetails.SuggestedFixedVersion, 1)
					fileContent = strings.ReplaceAll(fileContent, entry, modifiedContent)
				}
			}
		}

	*/

	err = writeUpdatedBuildFile(descriptorFilePath, fileContent)
	return
}

// getPatternCompilersForVulnerability creates all possible supported patterns for a vulnerability to appear in a descriptor file
func getPatternCompilersForVulnerability(vulnDetails *utils.VulnerabilityDetails) (patternsCompilers []*regexp.Regexp, err error) {
	depGroup, depName, err := getVulnerabilityGroupAndName(vulnDetails.ImpactedDependencyName)
	if err != nil {
		return
	}

	for _, pattern := range regexpPatterns {
		completedPattern := fmt.Sprintf(pattern, depGroup, depName, vulnDetails.ImpactedDependencyVersion)
		re := regexp.MustCompile(completedPattern)
		patternsCompilers = append(patternsCompilers, re)
	}
	return
}

// getVulnerabilityGroupAndName returns separated 'group' and 'name' for a given vulnerability name
func getVulnerabilityGroupAndName(impactedDependencyName string) (depGroup string, depName string, err error) {
	seperatedImpactedDepName := strings.Split(impactedDependencyName, ":")
	if len(seperatedImpactedDepName) != 2 {
		err = errorutils.CheckErrorf("unable to parse impacted dependency name '%s'", impactedDependencyName)
		return
	}
	return seperatedImpactedDepName[0], seperatedImpactedDepName[1], err
}

func getMapRegexpEntry(mapEntry string) string {
	return fmt.Sprintf(directMapRegexpEntry, mapEntry) + apostrophes + "%s" + apostrophes
}

// writeUpdatedBuildFile writes the updated content of the descriptor's file into the file
func writeUpdatedBuildFile(filePath string, fileContent string) (err error) {
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		err = fmt.Errorf("couldn't get file info for file '%s': %s", filePath, err.Error())
		return
	}
	filePerm := fileInfo.Mode()

	err = os.WriteFile(filePath, []byte(fileContent), filePerm)
	if err != nil {
		err = fmt.Errorf("couldn't write fixes to file '%s': %q", filePath, err)
	}
	return
}
