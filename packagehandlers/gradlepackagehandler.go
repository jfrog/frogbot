package packagehandlers

import (
	"fmt"
	fileutils "github.com/jfrog/build-info-go/utils"
	"github.com/jfrog/frogbot/packagehandlers/resources"
	"github.com/jfrog/frogbot/utils"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"
)

const (
	groovyFileType  = "groovy"
	kotlinFileType  = "kotlin"
	groovyBuildFile = "build.gradle"
	kotlinBuildFile = "build.gradle.kts"
	unknownRowType  = "unknown"
	mapLinePattern  = "[a-zA-Z]+\\s?group:\\s[\\\"|\\']%s[\\\"|\\'],\\s?name:\\s?[\\\"|\\']%s[\\\"|\\'].*"
)

type GradlePackageHandler struct {
	CommonPackageHandler
}

type buildFileData struct {
	fileName    string
	fileType    string
	fileContent []string
	filePath    string
}

var buildFileToType = map[string]string{
	"build.gradle":     groovyFileType,
	"build.gradle.kts": kotlinFileType,
}

var patternsCompilers map[string][]*regexp.Regexp

func init() {
	patternsCompilers = getAllPatternsCompilers()
}

func (gph *GradlePackageHandler) UpdateDependency(vulnDetails *utils.VulnerabilityDetails) error {
	// TODO check which kind of dependencies should be supported here in gradle (direct, with/without var, scripts?, plugins?, projects?)
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
	// get all build files
	buildFiles, err := readBuildFiles()
	if err != nil {
		err = fmt.Errorf("error occured while getting project's build files: %q", err)
	}

	// search for the vulnerability
	for _, buildFile := range buildFiles {
		//get vulnerable rows with data required for the fix
		//TODO check what to do if there are several rows with the same package, or in different build files ???
		vulnerableRows := getVulnerableRowsWithData(&buildFile, vulnDetails.ImpactedDependencyName)

		// get all fixers for the vulnerable rows
		var vulnRowsFixers map[int]resources.VulnerableRowFixer
		vulnRowsFixers, err = getVulnerableRowsFixers(vulnerableRows)
		if err != nil {
			return
		}

		// issue a fix for each row in the current build file
		for rowNumber, fixer := range vulnRowsFixers {
			rowFix := fixer.GetVulnerableRowFix(vulnDetails)
			buildFile.fileContent[rowNumber] = rowFix
		}

		err = writeUpdatedBuildFile(buildFile)
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
	err = os.WriteFile(buildFile.filePath, bytesSlice, 0644)
	if err != nil {
		err = fmt.Errorf("couldn't write fixes to file '%s': %q", buildFile.filePath, err)
	}
	return
}

func readBuildFiles() (buildFiles []buildFileData, err error) {
	dirContent, err := os.ReadDir(".")
	if err != nil {
		err = fmt.Errorf("couldn't read working directory: %q", err)
		return
	}
	wd, err := os.Getwd()
	if err != nil {
		return
	}

	//TODO check if this process is working for multi-dir and can detect build files not in main dir
	for _, dirEntry := range dirContent {
		fileName := dirEntry.Name()
		if fileName == groovyBuildFile || fileName == kotlinBuildFile {
			var fileContent []string
			fileContent, err = fileutils.ReadNLines(fileName, math.MaxInt)
			if err != nil {
				err = fmt.Errorf("couldn't read %s file: %q", fileName, err)
				return
			}
			buildFiles = append(buildFiles, buildFileData{
				fileName:    fileName,
				fileType:    buildFileToType[fileName],
				fileContent: fileContent,
				filePath:    filepath.Join(wd, fileName),
			})
		}
	}
	if len(buildFiles) == 0 {
		err = errorutils.CheckErrorf("couldn't detect any build file in the project")
	}
	return
}

func getVulnerableRowsWithData(buildFileData *buildFileData, impactedPackageName string) map[int]resources.VulnRowData {
	// TODO improve implementation (finding 'dependencies' in the file and look below it, counting { and } )
	// TODO what should we do if the line doesn't contain any version?
	idxToRowMap := make(map[int]resources.VulnRowData)

	for rowIdx, rowContent := range buildFileData.fileContent {
		if strings.Contains(rowContent, impactedPackageName) || (isMapFormat(rowContent) && mapLineContainsImpactedPackage(rowContent, impactedPackageName)) {
			idxToRowMap[rowIdx] = resources.VulnRowData{
				Content:         rowContent,
				RowType:         detectVulnerableRowType(rowContent),
				FileType:        buildFileData.fileType,
				Filepath:        buildFileData.filePath,
				LeftIndentation: getLeftWhitespaces(rowContent)}
		}
	}
	return idxToRowMap
}

// getVulnerableRowsFixers returns a slice of fixers, one for each of the vulnerable rows, according to the row type detected sooner
func getVulnerableRowsFixers(vulnerableRows map[int]resources.VulnRowData) (map[int]resources.VulnerableRowFixer, error) {
	vulnRowsFixers := make(map[int]resources.VulnerableRowFixer)
	unsupportedRowsCount := 0
	for rowNumber, rowData := range vulnerableRows {
		fixer, err := resources.GetFixerByRowType(rowData, rowNumber)
		if err != nil {
			log.Warn(fmt.Sprintf("couldn't get row fixer for row '%s' (row number: %d, file: %s): %q", rowData.Content, rowNumber, rowData.Filepath, err))
			unsupportedRowsCount++
		} else {
			vulnRowsFixers[rowNumber] = fixer
		}
	}

	// TODO check what to do in the case we could only fix several rows and not all of them
	totalVulnRows := len(vulnerableRows)
	if unsupportedRowsCount > 0 {
		if unsupportedRowsCount == totalVulnRows {
			return nil, errorutils.CheckErrorf("couldn't get fixer for any vulnerable row")
		}
		log.Warn(fmt.Sprintf("vulnerability fix is unavailable for %d out of %d vulnerable rows", unsupportedRowsCount, totalVulnRows))
	}
	return vulnRowsFixers, nil
}

// detectVulnerableRowType returns the row's type according to predefined patterns defined by RegexpNameToPattern in ./resources/gradlefixhelper.go
// if there is no match for some row with any known type, the row's type will be set to 'unknown'
func detectVulnerableRowType(vulnerableRow string) string {
	rowToCheck := strings.TrimLeft(vulnerableRow, " ")
	for patternName, regexpCompilers := range patternsCompilers {
		for _, compiler := range regexpCompilers {
			if compiler.MatchString(rowToCheck) {
				return patternName
			}
		}
	}
	return unknownRowType
}

func mapLineContainsImpactedPackage(rowContent string, impactedPackageName string) bool {
	seperatedVulnerability := strings.Split(impactedPackageName, ":")
	var re *regexp.Regexp
	re = regexp.MustCompile(fmt.Sprintf(mapLinePattern, seperatedVulnerability[0], seperatedVulnerability[1]))
	if re.MatchString(strings.TrimLeft(rowContent, " ")) {
		return true
	}
	return false
}

func isMapFormat(dependencyRow string) bool {
	return strings.Contains(dependencyRow, "group:") && strings.Contains(dependencyRow, "name:")
}

func getLeftWhitespaces(str string) string {
	firstNonWhiteSpace := 0
	for idx, char := range str {
		if !unicode.IsSpace(char) {
			firstNonWhiteSpace = idx
			break
		}
	}
	return str[:firstNonWhiteSpace]
}

func getAllPatternsCompilers() (patternsCompilers map[string][]*regexp.Regexp) {
	patternsCompilers = make(map[string][]*regexp.Regexp)
	for patternName, patterns := range resources.RegexpNameToPattern {
		for _, pattern := range patterns {
			var re *regexp.Regexp
			re = regexp.MustCompile(pattern)
			patternsCompilers[patternName] = append(patternsCompilers[patternName], re)
		}
	}
	return
}
