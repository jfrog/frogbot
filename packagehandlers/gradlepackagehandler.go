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
	groovyFileType            = "groovy" //TODO needed?
	kotlinFileType            = "kotlin" //TODO needed?
	groovyBuildFileSuffix     = "build.gradle"
	kotlinBuildFileSuffix     = "build.gradle.kts"
	unknownRowType            = "unknown"
	unsupportedDynamicVersion = "dynamic dependency version"
	unsupportedLatestVersion  = "latest release version"
	unsupportedRangeVersion   = "range version"
)

type GradlePackageHandler struct {
	CommonPackageHandler
}

type buildFileData struct {
	fileType    string      // TODO needed?
	fileContent []string    //needed
	filePath    string      //needed
	filePerm    os.FileMode //needed
}

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
	if unsupportedType, isUnsupported := isUnsupportedVulnVersion(vulnDetails.ImpactedDependencyVersion); isUnsupported {
		log.Warn(fmt.Sprintf("frogbot currently doesn't support fixing %s: %s %s", unsupportedType, vulnDetails.ImpactedDependencyName, vulnDetails.ImpactedDependencyVersion))
		return &utils.ErrUnsupportedFix{
			PackageName:  vulnDetails.ImpactedDependencyName,
			FixedVersion: vulnDetails.SuggestedFixedVersion,
			ErrorType:    utils.UnsupportedGradleDependencyVersion,
		}
	}
	// get all build files
	buildFiles, err := readBuildFiles()
	if err != nil {
		err = fmt.Errorf("error has occurred while getting project's build files: %s", err.Error())
		return
	}

	// fixing every build file separately
	for _, buildFile := range buildFiles {
		err = fixBuildFile(buildFile, vulnDetails)
		if err != nil {
			return
		}
	}
	return //errors.New("stop")
}

func writeUpdatedBuildFile(buildFile buildFileData) (err error) {
	// todo fix the end of the file doesnt change with this flow
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

func readBuildFiles() (buildFiles []buildFileData, err error) {
	wd, err := os.Getwd()
	if err != nil {
		return
	}

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

	if err != nil {
		return
	}

	if len(buildFiles) == 0 {
		err = errorutils.CheckErrorf("couldn't detect any build file in the project")
	}
	return
}

// getVulnerableRowFixer returns a fixer object for each row type
func getVulnerableRowFixer(rowData resources.VulnRowData, rowNumberInFile int) (resources.VulnerableRowFixer, error) {
	fixer, err := resources.GetFixerByRowType(rowData, rowNumberInFile)
	if err != nil {
		return nil, fmt.Errorf("couldn't get row fixer for row '%s' (row number: %d, file: %s): %q", strings.TrimLeft(rowData.Content, " "), rowNumberInFile+1, rowData.Filepath, err)
	}
	return fixer, nil
}

func fixBuildFile(buildFileData buildFileData, vulnDetails *utils.VulnerabilityDetails) (err error) {
	// TODO what should we do if the line doesn't contain any version?
	patternsCompilers, err := getPattenCompilersForVulnerability(vulnDetails)
	if err != nil {
		return
	}

	dependenciesScopeOpenCurlyParenthesis := 0
	insideDependenciesScope := false

	for rowIdx, rowContent := range buildFileData.fileContent {
		if isInsideDependenciesScope(rowContent, &insideDependenciesScope, &dependenciesScopeOpenCurlyParenthesis) {
			if vulnerableRowType := detectVulnerableRowType(rowContent, patternsCompilers); vulnerableRowType != unknownRowType {
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
	}

	err = writeUpdatedBuildFile(buildFileData)
	return
}

// isInsideDependenciesScope detects if we are inside a 'dependencies' scope and the given row need to be further checked for a possible fix
func isInsideDependenciesScope(rowContent string, insideDependenciesScope *bool, dependenciesScopeOpenCurlyParenthesis *int) bool {
	if strings.Contains(rowContent, "dependencies") {
		*insideDependenciesScope = true
	}
	if *insideDependenciesScope {
		if strings.Contains(rowContent, "{") {
			*dependenciesScopeOpenCurlyParenthesis += 1
		}
		if strings.Contains(rowContent, "}") {
			*dependenciesScopeOpenCurlyParenthesis -= 1
			if *dependenciesScopeOpenCurlyParenthesis == 0 {
				*insideDependenciesScope = false
			}
		}
	}
	return *insideDependenciesScope
}

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
	return unknownRowType
}

func getPattenCompilersForVulnerability(vulnDetails *utils.VulnerabilityDetails) (patternsCompilers map[resources.RowType][]*regexp.Regexp, err error) {
	seperatedImpactedDepName := strings.Split(vulnDetails.ImpactedDependencyName, ":")
	if len(seperatedImpactedDepName) != 2 {
		err = errorutils.CheckErrorf("unable to parse impacted dependency name '%s'", vulnDetails.ImpactedDependencyName)
		return
	}

	patternsCompilers = make(map[resources.RowType][]*regexp.Regexp)
	for patternName, patterns := range resources.RegexpNameToPattern {
		for _, pattern := range patterns {
			completedPattern := fmt.Sprintf(pattern, seperatedImpactedDepName[0], seperatedImpactedDepName[1], vulnDetails.ImpactedDependencyVersion)
			re := regexp.MustCompile(completedPattern)
			patternsCompilers[patternName] = append(patternsCompilers[patternName], re)
		}
	}
	return
}

func isUnsupportedVulnVersion(impactedVersion string) (string, bool) {
	// TODO should fix those two or reject?
	// capture var version
	// capture property version - something that directs to take the value from properties.gradle (starts with $)

	if strings.Contains(impactedVersion, "+") {
		return unsupportedDynamicVersion, true
	}
	if strings.Contains(impactedVersion, "latest.release") {
		return unsupportedLatestVersion, true
	}
	if strings.Contains(impactedVersion, "[") || strings.Contains(impactedVersion, "(") {
		return unsupportedRangeVersion, true
	}
	return "", false
}
