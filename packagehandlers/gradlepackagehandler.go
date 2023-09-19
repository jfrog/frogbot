package packagehandlers

import (
	"fmt"
	fileutils "github.com/jfrog/build-info-go/utils"
	"github.com/jfrog/frogbot/utils"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type UnsupportedForFixType string

const (
	groovyBuildFileSuffix                               = "build.gradle"
	kotlinBuildFileSuffix                               = "build.gradle.kts"
	unsupportedDynamicVersion     UnsupportedForFixType = "dynamic dependency version"
	unsupportedLatestVersion      UnsupportedForFixType = "latest release version"
	unsupportedRangeVersion       UnsupportedForFixType = "range version"
	apostrophes                                         = "[\\\"|\\']"
	directMapWithVersionRegexp                          = "group\\s?[:|=]\\s?" + apostrophes + "%s" + apostrophes + ", name\\s?[:|=]\\s?" + apostrophes + "%s" + apostrophes + ", version\\s?[:|=]\\s?" + apostrophes + "%s" + apostrophes
	directStringWithVersionRegexp                       = apostrophes + "%s:%s:%s" + ".*" + apostrophes
)

var regexpPatterns = []string{directMapWithVersionRegexp, directStringWithVersionRegexp}

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
	if unsupportedType := getUnsupportedForFixVersionType(vulnDetails.ImpactedDependencyVersion); unsupportedType != "" {
		log.Warn(fmt.Sprintf("frogbot currently doesn't support fixing %s: %s %s", unsupportedType, vulnDetails.ImpactedDependencyName, vulnDetails.ImpactedDependencyVersion))
		return &utils.ErrUnsupportedFix{
			PackageName:  vulnDetails.ImpactedDependencyName,
			FixedVersion: vulnDetails.SuggestedFixedVersion,
			ErrorType:    utils.UnsupportedForFixVulnerableVersion,
		}
	}

	buildFilesPaths, err := getBuildFilesPaths()
	if err != nil {
		return
	}

	for _, buildFilePath := range buildFilesPaths {
		err = fixBuildFile(buildFilePath, vulnDetails)
		if err != nil {
			return
		}
	}

	return
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

func getBuildFilesPaths() (buildFilesPaths []string, err error) {
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
			buildFilesPaths = append(buildFilesPaths, absFilePath)
		}
		return err
	})
	return
}

func fixBuildFile(buildFilePath string, vulnDetails *utils.VulnerabilityDetails) (err error) {
	patternsCompilers, err := getPatternCompilersForVulnerability(vulnDetails)
	if err != nil {
		return
	}

	fileContent, err := fileutils.ReadNLines(buildFilePath, math.MaxInt)
	if err != nil {
		err = fmt.Errorf("couldn't read file '%s': %s", buildFilePath, err.Error())
		return
	}

	for rowIdx, line := range fileContent {
		if isFixRequiredForLine(line, patternsCompilers) {
			fileContent[rowIdx] = getFixedLine(line, vulnDetails)
		}
	}

	err = writeUpdatedBuildFile(buildFilePath, fileContent)
	return
}

func getFixedLine(line string, vulnDetails *utils.VulnerabilityDetails) string {
	return strings.Replace(line, vulnDetails.ImpactedDependencyVersion, vulnDetails.SuggestedFixedVersion, 1)
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

func getUnsupportedForFixVersionType(impactedVersion string) UnsupportedForFixType {
	switch {
	case strings.Contains(impactedVersion, "+"):
		return unsupportedDynamicVersion
	case strings.Contains(impactedVersion, "[") || strings.Contains(impactedVersion, "("):
		// In case a version range will be supported- regexps need to be modified to identify '[' as a char
		return unsupportedRangeVersion
	case strings.Contains(impactedVersion, "latest.release"):
		return unsupportedLatestVersion // Bla
	}

	return ""
}
