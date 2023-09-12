package packagehandlers

import (
	"fmt"
	fileutils "github.com/jfrog/build-info-go/utils"
	"github.com/jfrog/frogbot/packagehandlers/resources"
	"github.com/jfrog/frogbot/utils"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
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
	mapLinePattern  = "group:\\s[\\\"|\\']%s[\\\"|\\'],\\s?name:\\s?[\\\"|\\']%s[\\\"|\\']"
)

//[a-zA-Z]+\s?

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

//var patternsCompilers map[string][]*regexp.Regexp
/*
func init() {
	patternsCompilers = getAllPatternsCompilers()
}

*/

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
	// get all build files
	buildFiles, err := readBuildFiles()
	if err != nil {
		err = fmt.Errorf("error occured while getting project's build files: %q", err)
	}

	// fixing every build file separately
	for _, buildFile := range buildFiles {
		err = fixBuildFile2(buildFile, vulnDetails)
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

/*
func fixBuildFile(buildFileData buildFileData, vulnDetails *utils.VulnerabilityDetails) (err error) {
	// TODO improve implementation (finding 'dependencies' in the file and look below it, counting { and } )
	// TODO what should we do if the line doesn't contain any version?
	patternsCompilers, err := getAllPatternsCompilers2(vulnDetails)
	if err != nil {
		return
	}

	for rowIdx, rowContent := range buildFileData.fileContent {
		if strings.Contains(rowContent, vulnDetails.ImpactedDependencyName) || (isMapFormat(rowContent) && mapLineContainsImpactedPackage(rowContent, vulnDetails.ImpactedDependencyName)) {
			rowData := resources.VulnRowData{
				Content:         rowContent,
				RowType:         detectVulnerableRowType(rowContent, patternsCompilers),
				FileType:        buildFileData.fileType,
				Filepath:        buildFileData.filePath,
				LeftIndentation: getLeftWhitespaces(rowContent)}

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

// getVulnerableRowFixer returns a fixer object for each row type
func getVulnerableRowFixer(rowData resources.VulnRowData, rowNumberInFile int) (resources.VulnerableRowFixer, error) {
	fixer, err := resources.GetFixerByRowType(rowData, rowNumberInFile)
	if err != nil {
		return nil, fmt.Errorf("couldn't get row fixer for row '%s' (row number: %d, file: %s): %q", strings.TrimLeft(rowData.Content, " "), rowNumberInFile+1, rowData.Filepath, err)
	}
	return fixer, nil
}

func fixBuildFile2(buildFileData buildFileData, vulnDetails *utils.VulnerabilityDetails) (err error) {
	// TODO what should we do if the line doesn't contain any version?
	patternsCompilers, err := getAllPatternsCompilers2(vulnDetails)
	if err != nil {
		return
	}

	dependenciesScopeOpenCurlyParenthesis := 0
	insideDependenciesScope := false

	for rowIdx, rowContent := range buildFileData.fileContent {
		if isInsideDependenciesScope(rowContent, &insideDependenciesScope, &dependenciesScopeOpenCurlyParenthesis) {
			if vulnerableRowType := detectVulnerableRowType(rowContent, patternsCompilers); vulnerableRowType != unknownRowType {
				rowData := resources.VulnRowData{
					Content:         rowContent,
					RowType:         vulnerableRowType,
					FileType:        buildFileData.fileType,
					Filepath:        buildFileData.filePath,
					LeftIndentation: getLeftWhitespaces(rowContent)}

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
func detectVulnerableRowType(vulnerableRow string, patternsCompilers map[string][]*regexp.Regexp) string {
	rowToCheck := strings.TrimLeft(vulnerableRow, " ")
	for patternName, regexpCompilers := range patternsCompilers {
		for _, compiler := range regexpCompilers {
			if compiler.FindString(rowToCheck) != "" {
				return patternName
			}
		}
	}
	return unknownRowType
}

/*
// mapLineContainsImpactedPackage when 'map' format dependency line was detected- checks if it contains the vulnerable package
func mapLineContainsImpactedPackage(rowContent string, impactedPackageName string) bool {
	seperatedVulnerability := strings.Split(impactedPackageName, ":")
	var re *regexp.Regexp
	re = regexp.MustCompile(fmt.Sprintf(mapLinePattern, seperatedVulnerability[0], seperatedVulnerability[1]))
	tmp := re.FindString(strings.TrimLeft(rowContent, " "))
	fmt.Println(tmp)
	if re.MatchString(strings.TrimLeft(rowContent, " ")) {
		return true
	}
	return false
}

*/

/*
// isMapFormat checks if a given line is in 'map' format
func isMapFormat(dependencyRow string) bool {
	return strings.Contains(dependencyRow, "group:") && strings.Contains(dependencyRow, "name:")
}

*/

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

// getAllPatternsCompilers init function that creates all regexp compilers for the predefined regexps defined in ./resources/gradlefixhelper.go
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

func getAllPatternsCompilers2(vulnDetails *utils.VulnerabilityDetails) (patternsCompilers map[string][]*regexp.Regexp, err error) {
	seperatedImpactedDepName := strings.Split(vulnDetails.ImpactedDependencyName, ":")
	if len(seperatedImpactedDepName) != 2 {
		err = errorutils.CheckErrorf("unable to parse impacted dependency name '%s'", vulnDetails.ImpactedDependencyName)
		return
	}

	patternsCompilers = make(map[string][]*regexp.Regexp)
	for patternName, patterns := range resources.RegexpNameToPattern {
		for _, pattern := range patterns {
			completedPattern := fmt.Sprintf(pattern, seperatedImpactedDepName[0], seperatedImpactedDepName[1], vulnDetails.ImpactedDependencyVersion)
			var re *regexp.Regexp
			re = regexp.MustCompile(completedPattern)
			patternsCompilers[patternName] = append(patternsCompilers[patternName], re)
		}
	}
	return
}
