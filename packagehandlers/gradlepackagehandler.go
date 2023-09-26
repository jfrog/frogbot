package packagehandlers

import (
	"fmt"
	fileutils "github.com/jfrog/build-info-go/utils"
	"github.com/jfrog/frogbot/utils"
	"github.com/jfrog/gofrog/datastructures"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	groovyBuildFileSuffix                  = "build.gradle"
	kotlinBuildFileSuffix                  = "build.gradle.kts"
	apostrophes                            = "[\\\"|\\']"
	ORIGINAL_directMapWithVersionRegexp    = "group\\s?[:|=]\\s?" + apostrophes + "%s" + apostrophes + ", name\\s?[:|=]\\s?" + apostrophes + "%s" + apostrophes + ", version\\s?[:|=]\\s?" + apostrophes + "%s" + apostrophes
	directMapRegexpEntry                   = "\\s*%s\\s*[:|=]\\s*"
	regexpMapValueWithApostrophes          = apostrophes + "%s" + apostrophes
	ORIGINAL_directStringWithVersionRegexp = apostrophes + "%s:%s:%s" + ".*" + apostrophes
	directStringWithVersionRegexp          = "%s:%s:%s"
)

// var regexpPatterns = []string{directMapWithVersionRegexp, directStringWithVersionRegexp}
var regexpPatterns []string

func init() {
	// Example: <groupName>:<packageName>:<version>
	regexpPatterns = append(regexpPatterns, directStringWithVersionRegexp)

	groupEntry := getMapRegexpEntry("group")
	nameEntry := getMapRegexpEntry("name")
	versionEntry := getMapRegexpEntry("version")

	// Example: group: "<groupName>", name: "<packageName>", version: "<version>" | group = "<groupName>", name = "<packageName>", version = "<version>"
	directMapRegexpPattern := groupEntry + regexpMapValueWithApostrophes + "," + nameEntry + regexpMapValueWithApostrophes + "," + versionEntry + regexpMapValueWithApostrophes
	regexpPatterns = append(regexpPatterns, directMapRegexpPattern)
}

type GradlePackageHandler struct {
	CommonPackageHandler
}

func (gph *GradlePackageHandler) UpdateDependency(vulnDetails *utils.VulnerabilityDetails) error {
	fmt.Println("############### reached: " + vulnDetails.ImpactedDependencyName + ", version: " + vulnDetails.ImpactedDependencyVersion + " ###############")
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
	fmt.Println("############### pass block for: " + vulnDetails.ImpactedDependencyName + " ###############")

	// A gradle project may contain several descriptor files in several sub-modules. Each vulnerability may be found in each of the descriptor files.
	// Therefore we iterate over every descriptor file for each vulnerability and try to find and fix it.
	descriptorFilesPaths, err := getDescriptorFilesPaths()
	if err != nil {
		return
	}

	for _, descriptorFilePath := range descriptorFilesPaths {
		err = fixVulnerabilityInDescriptorFileIfExists2(descriptorFilePath, vulnDetails)
		if err != nil {
			return
		}
	}

	return
}

func isVersionSupportedForFix(impactedVersion string) bool {
	if strings.Contains(impactedVersion, "+") ||
		(strings.Contains(impactedVersion, "[") || strings.Contains(impactedVersion, "(")) ||
		strings.Contains(impactedVersion, "latest.release") {
		return false
	}
	return true
}

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

func fixVulnerabilityInDescriptorFileIfExists(descriptorFilePath string, vulnDetails *utils.VulnerabilityDetails) (err error) {
	patternsCompilers, err := getPatternCompilersForVulnerability(vulnDetails)
	if err != nil {
		return
	}

	fileContent, err := fileutils.ReadNLines(descriptorFilePath, math.MaxInt)
	if err != nil {
		err = fmt.Errorf("couldn't read file '%s': %s", descriptorFilePath, err.Error())
		return
	}

	for rowIdx, line := range fileContent {
		if isFixRequiredForLine(line, patternsCompilers) {
			fileContent[rowIdx] = getFixedLine(line, vulnDetails)
		}
	}

	err = writeUpdatedBuildFile(descriptorFilePath, fileContent)
	return
}

func fixVulnerabilityInDescriptorFileIfExists2(descriptorFilePath string, vulnDetails *utils.VulnerabilityDetails) (err error) {
	vulnerabilityPatterns, err := getPatternCompilersForVulnerability(vulnDetails)
	if err != nil {
		return
	}

	byteFileContent, err := os.ReadFile(descriptorFilePath)
	if err != nil {
		err = fmt.Errorf("couldn't read file '%s': %s", descriptorFilePath, err.Error())
		return
	}
	fileContent := string(byteFileContent)

	for _, regexpCompiler := range vulnerabilityPatterns {
		//if matches := regexpCompiler.FindAll(byteFileContent, -1); matches != nil {
		if matches := regexpCompiler.FindAllString(fileContent, -1); matches != nil {
			fmt.Println("############### found matching pattern for: " + vulnDetails.ImpactedDependencyName + " ###############")
			set := datastructures.MakeSet[string]()
			for _, match := range matches {
				//set.Add(strings.TrimSpace(string(match)))
				set.Add(strings.TrimSpace(match))
			}
			for _, entry := range set.ToSlice() {
				modifiedContent := strings.Replace(entry, vulnDetails.ImpactedDependencyVersion, vulnDetails.SuggestedFixedVersion, 1)
				fileContent = strings.ReplaceAll(fileContent, entry, modifiedContent)
			}
		}
	}

	byteFileContent = []byte(fileContent)
	err = writeUpdatedBuildFile2(descriptorFilePath, fileContent)
	return
}

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

func getVulnerabilityGroupAndName(impactedDependencyName string) (depGroup string, depName string, err error) {
	seperatedImpactedDepName := strings.Split(impactedDependencyName, ":")
	if len(seperatedImpactedDepName) != 2 {
		err = errorutils.CheckErrorf("unable to parse impacted dependency name '%s'", impactedDependencyName)
		return
	}
	return seperatedImpactedDepName[0], seperatedImpactedDepName[1], err
}

func getMapRegexpEntry(mapEntry string) string {
	return fmt.Sprintf(directMapRegexpEntry, mapEntry)
}

func isFixRequiredForLine(vulnerableRow string, patternsCompilers []*regexp.Regexp) bool {
	rowToCheck := strings.TrimSpace(vulnerableRow)
	for _, regexpCompiler := range patternsCompilers {
		if regexpCompiler.FindString(rowToCheck) != "" {
			return true
		}
	}

	return false
}

func getFixedLine(line string, vulnDetails *utils.VulnerabilityDetails) string {
	return strings.Replace(line, vulnDetails.ImpactedDependencyVersion, vulnDetails.SuggestedFixedVersion, 1)
}

func writeUpdatedBuildFile(filePath string, fileContent []string) (err error) {
	var bytesSlice []byte
	for _, row := range fileContent {
		bytesSlice = append(bytesSlice, []byte(row+"\n")...)
	}
	bytesSlice = bytesSlice[:len(bytesSlice)-1]

	fileInfo, err := os.Stat(filePath)
	if err != nil {
		err = fmt.Errorf("couldn't get file info for file '%s': %s", filePath, err.Error())
		return
	}
	filePerm := fileInfo.Mode()

	err = os.WriteFile(filePath, bytesSlice, filePerm)
	if err != nil {
		err = fmt.Errorf("couldn't write fixes to file '%s': %q", filePath, err)
	}
	return
}

func writeUpdatedBuildFile2(filePath string, fileContent string) (err error) {
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
