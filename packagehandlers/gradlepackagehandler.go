package packagehandlers

import (
	"fmt"
	fileutils "github.com/jfrog/build-info-go/utils"
	"github.com/jfrog/frogbot/packagehandlers/resources"
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

const (
	groovyFileType                = "groovy" // todo delete
	kotlinFileType                = "kotlin" // todo delete
	groovyBuildFileSuffix         = "build.gradle"
	kotlinBuildFileSuffix         = "build.gradle.kts"
	unsupportedDynamicVersion     = "dynamic dependency version"
	unsupportedLatestVersion      = "latest release version"
	unsupportedRangeVersion       = "range version"
	apostrophes                   = "[\\\"|\\']"
	directMapWithVersionRegexp    = "group\\s?[:|=]\\s?" + apostrophes + "%s" + apostrophes + ", name\\s?[:|=]\\s?" + apostrophes + "%s" + apostrophes + ", version\\s?[:|=]\\s?" + apostrophes + "%s" + apostrophes
	directStringWithVersionRegexp = apostrophes + "%s:%s:%s" + ".*" + apostrophes
)

var regexpPatterns = []string{directMapWithVersionRegexp, directStringWithVersionRegexp}

type GradlePackageHandler struct {
	CommonPackageHandler
}

// todo delete
type buildFileData struct {
	fileType    string // Needed???
	fileContent []string
	filePath    string
	filePerm    os.FileMode
}

// todo delete
var fileExtensionToType = map[string]string{
	".gradle": groovyFileType,
	".kts":    kotlinFileType,
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
	//TODO check why latest.release enters here. fix it sooner in the chain - do not let it enter (if there is a specific build of vuln map for gradle- fix it there)
	if unsupportedType := getUnsupportedForFixVersionType(vulnDetails.ImpactedDependencyVersion); unsupportedType != "" {
		log.Warn(fmt.Sprintf("frogbot currently doesn't support fixing %s: %s %s", unsupportedType, vulnDetails.ImpactedDependencyName, vulnDetails.ImpactedDependencyVersion))
		return &utils.ErrUnsupportedFix{
			PackageName:  vulnDetails.ImpactedDependencyName,
			FixedVersion: vulnDetails.SuggestedFixedVersion,
			ErrorType:    utils.UnsupportedForFixVulnerableVersion,
		}
	}

	//collect all build files
	buildFilesPaths, err := getBuildFilesPaths()
	if err != nil {
		return
	}

	for _, buildFilePath := range buildFilesPaths {
		err = fixBuildFile2(buildFilePath, vulnDetails)
		if err != nil {
			return
		}
	}

	return //errors.New("stop")
}

/*
func writeUpdatedBuildFile(buildFile buildFileData) (err error) {
	// Todo fix the end of the file doesnt change with this flow
	var bytesSlice []byte
	for _, row := range buildFile.fileContent {
		bytesSlice = append(bytesSlice, []byte(row+"\n")...)
	}
	bytesSlice = bytesSlice[:len(bytesSlice)-1]
	err = os.WriteFile(buildFile.filePath, bytesSlice, buildFile.filePerm)
	if err != nil {
		err = fmt.Errorf("couldn't write fixes to file '%s': %q", buildFile.filePath, err)
	}
	return
}

*/

func writeUpdatedBuildFile2(filePath string, fileContent []string) (err error) {
	// Todo fix the end of the file doesnt change with this flow
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

/*
func readBuildFiles() (buildFiles []buildFileData, err error) {
	wd, err := os.Getwd()
	if err != nil {
		return
	}

	// TODO check if there a function that finds file given its path. after collecting all paths build the struct needed (separate those actions)
	err = filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("error has occured when trying to access or traverse the files system: %s", err.Error())
		}

		if d.Type().IsRegular() && (strings.HasSuffix(path, groovyBuildFileSuffix) || strings.HasSuffix(path, kotlinBuildFileSuffix)) {
			fullFilePath := filepath.Join(wd, path)

			// Read file's content
			fileContent, readErr := fileutils.ReadNLines(path, math.MaxInt)
			if readErr != nil {
				return readErr
			}

			// Get file permissions
			fileInfo, statErr := os.Stat(path)
			if statErr != nil {
				return statErr
			}

			filePerm := fileInfo.Mode()

			buildFiles = append(buildFiles, buildFileData{
				fileType:    fileExtensionToType[filepath.Ext(path)],
				fileContent: fileContent,
				filePath:    fullFilePath,
				filePerm:    filePerm,
			})
		}
		return err
	})
	return
}

*/

/*
// getVulnerableRowFixer returns a fixer object for each row type
func getVulnerableRowFixer(rowData resources.VulnRowData, rowNumberInFile int) (resources.VulnerableRowFixer, error) {
	fixer, err := resources.GetFixerByRowType(rowData, rowNumberInFile)
	if err != nil {
		return nil, fmt.Errorf("couldn't get row fixer for row '%s' (row number: %d, file: %s): %q", strings.TrimLeft(rowData.Content, " "), rowNumberInFile+1, rowData.Filepath, err)
	}
	return fixer, nil
}

*/

func fixBuildFile2(buildFilePath string, vulnDetails *utils.VulnerabilityDetails) (err error) {
	// todo fix this function to return a slice of compilers without names
	patternsCompilers, err := getPatternCompilersForVulnerability2(vulnDetails)
	if err != nil {
		return
	}

	// Read file's content
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

	err = writeUpdatedBuildFile2(buildFilePath, fileContent)
	return
}

func getFixedLine(line string, vulnDetails *utils.VulnerabilityDetails) string {
	return strings.Replace(line, vulnDetails.ImpactedDependencyVersion, vulnDetails.SuggestedFixedVersion, 1)
}

/*
func fixBuildFile(buildFileData buildFileData, vulnDetails *utils.VulnerabilityDetails) (err error) {
	patternsCompilers, err := getPatternCompilersForVulnerability(vulnDetails)
	if err != nil {
		return
	}

	for rowIdx, rowContent := range buildFileData.fileContent {
		vulnerableRowType := detectVulnerableRowType(rowContent, patternsCompilers)
		if vulnerableRowType != resources.UnknownRowType {
			rowData := resources.VulnRowData{
				Content:  rowContent,
				RowType:  vulnerableRowType,
				FileType: buildFileData.fileType,
				Filepath: buildFileData.filePath,
			}

			var fixer resources.VulnerableRowFixer
			fixer, err = getVulnerableRowFixer(rowData, rowIdx)
			if err != nil {
				return
			}
			buildFileData.fileContent[rowIdx] = fixer.GetVulnerableRowFix(vulnDetails)
		}

	}

	err = writeUpdatedBuildFile(buildFileData)
	return
}

*/

/*
// detectVulnerableRowType returns the row's type according to predefined patterns defined by RegexpNameToPattern in ./resources/gradlefixhelper.go
// if there is no match for some row with any known type, the row's type will be set to 'unknown'
func detectVulnerableRowType(vulnerableRow string, patternsCompilers map[resources.RowType][]*regexp.Regexp) resources.RowType {
	rowToCheck := strings.TrimSpace(vulnerableRow)
	for patternName, regexpCompilers := range patternsCompilers {
		for _, compiler := range regexpCompilers {
			if compiler.FindString(rowToCheck) != "" {
				return patternName
			}
		}
	}

	return resources.UnknownRowType
}

*/

func isFixRequiredForLine(vulnerableRow string, patternsCompilers []*regexp.Regexp) bool {
	rowToCheck := strings.TrimSpace(vulnerableRow)
	for _, regexpCompiler := range patternsCompilers {
		if regexpCompiler.FindString(rowToCheck) != "" {
			return true
		}
	}

	return false
}

func getPatternCompilersForVulnerability(vulnDetails *utils.VulnerabilityDetails) (patternsCompilers map[resources.RowType][]*regexp.Regexp, err error) {
	depGroup, depName, err := getVulnerabilityGroupAndName(vulnDetails.ImpactedDependencyName)
	if err != nil {
		return
	}

	patternsCompilers = make(map[resources.RowType][]*regexp.Regexp)
	for patternName, patterns := range resources.RegexpNameToPattern {
		for _, pattern := range patterns {
			completedPattern := fmt.Sprintf(pattern, depGroup, depName, vulnDetails.ImpactedDependencyVersion)
			re := regexp.MustCompile(completedPattern)
			patternsCompilers[patternName] = append(patternsCompilers[patternName], re)
		}
	}
	return
}

func getPatternCompilersForVulnerability2(vulnDetails *utils.VulnerabilityDetails) (patternsCompilers []*regexp.Regexp, err error) {
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

func getUnsupportedForFixVersionType(impactedVersion string) string {
	// TODO should fix those two or reject?
	// capture var version
	// capture property version - something that directs to take the value from properties.gradle (starts with $)

	switch {
	case strings.Contains(impactedVersion, "+"):
		return unsupportedDynamicVersion
	case strings.Contains(impactedVersion, "latest.release"):
		return unsupportedLatestVersion
	case strings.Contains(impactedVersion, "[") || strings.Contains(impactedVersion, "("):
		return unsupportedRangeVersion

	}
	return ""
}
