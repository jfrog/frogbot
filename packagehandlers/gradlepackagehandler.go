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
)

const (
	groovyFileType  = "groovy"
	kotlinFileType  = "kotlin"
	groovyBuildFile = "build.gradle"
	kotlinBuildFile = "build.gradle.kts"
	unknownRowType  = "unknown"
	//directStringWithVersionRegex = "[a-zA-Z]+\\s[\\\"|\\'][a-zA-Z]+:[a-zA-Z]+:[0-9]+\\.[0-9]+\\.?[0-9]*[\\\"|\\']"
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

type vulnRowData struct {
	content  string
	rowType  string
	fileType string
	filepath string // TODO DEL? check if needed
}

var buildFileToType = map[string]string{
	"build.gradle":     groovyFileType,
	"build.gradle.kts": kotlinFileType,
}

var patternsCompilers map[string]*regexp.Regexp

func init() {
	patternsCompilers = getAllPatternsCompilers()

}

func (gph *GradlePackageHandler) UpdateDependency(vulnDetails *utils.VulnerabilityDetails) error {
	// TODO check which kind of dependencies are being supported here in gradle (direct, with/without var, scripts?, plugins?, projects?)
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
		// TODO check if fixes fail in one file should I drop the entire flow???

		//get vulnerable rows
		//TODO check what to do if there are several rows with the same package, or in different build files
		vulnerableRows := getVulnerableRowsInFile(&buildFile, vulnDetails.ImpactedDependencyName)

		// detect kind of row
		vulnerableRows = detectVulnerableRowsType(vulnerableRows)

		// get all fixers for the vulnerable rows
		var vulnRowsFixers map[int]resources.VulnerableRowFixer
		vulnRowsFixers, err = getVulnerableRowsFixers(vulnerableRows)
		if err != nil {
			return
		}

		// issue a fix for each row in the current build file
		for rowNumber, fixer := range vulnRowsFixers {
			rowFix := fixer.GetVulnRowFix()
			fmt.Println(rowFix)
			buildFile.fileContent[rowNumber] = rowFix
		}

		err = writeUpdatedBuildFile(buildFile)
		if err != nil {
			return
		}
	}

	return //errors.New("stop at updateDirectDependency")
}

func writeUpdatedBuildFile(buildFile buildFileData) (err error) {
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

	/* todo check if its better to iterate once with this implementation
	file, err := os.OpenFile(buildFile.filePath, os.O_WRONLY, 0644)
	if err != nil {
		err = fmt.Errorf("couldn't open file '%s': %q", buildFile.filePath, err)
		return
	}
	defer func() {
		err = errors.Join(err, file.Close())
	}()

	for rowIdx, row := range buildFile.fileContent {
		_, err = file.WriteString(row + "\n") //TODO make sure that the newline doesn't make problems with new line in the middle of a dependency or anywhere else
		if err != nil {
			err = fmt.Errorf("couldn't write a fix at row %d in file %s: %q", rowIdx, buildFile.filePath, err)
			return
		}
	}

	*/
}

// getVulnerableRowsFixers returns a slice of fixers, one for each of the vulnerable rows, according to the row type detected sooner
// in case there are un
func getVulnerableRowsFixers(vulnerableRows map[int]vulnRowData) (map[int]resources.VulnerableRowFixer, error) {
	vulnRowsFixers := make(map[int]resources.VulnerableRowFixer)
	unsupportedRowsCount := 0
	for rowNumber, rowData := range vulnerableRows {
		// TODO use builder/ sent all those params of rowData as a single struct (and move this struct to gradlefixhelper.go): see Omer
		fixer, err := resources.GetFixerByRowType(rowData.content, rowData.rowType, rowData.fileType, rowData.filepath, rowNumber)
		if err != nil {
			log.Warn(fmt.Sprintf("couldn't get row fixer for row '%s' (row number: %d, file: %s): %q", rowData.content, rowNumber, rowData.filepath, err))
			unsupportedRowsCount++
		} else {
			vulnRowsFixers[rowNumber] = fixer
		}
	}
	totalVulnRows := len(vulnerableRows)
	if unsupportedRowsCount > 0 {
		if unsupportedRowsCount == totalVulnRows {
			return nil, errorutils.CheckErrorf("couldn't get fixer for any vulnerable row")
		}
		log.Warn(fmt.Sprintf("vulnerability fix is unavailable for %d out of %d vulnerable rows", unsupportedRowsCount, totalVulnRows))
	}
	return vulnRowsFixers, nil
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
			fileContent, err = fileutils.ReadNLines(fileName, math.MaxInt) // TODO should I use this function that closes the file?
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

func getVulnerableRowsInFile(buildFileData *buildFileData, impactedPackageName string) map[int]vulnRowData {
	//TODO check if better implementation is needed (finding 'dependencies' in the file and look below it, counting { and } )
	idxToRowMap := make(map[int]vulnRowData)

	for rowIdx, rowContent := range buildFileData.fileContent {
		if strings.Contains(rowContent, impactedPackageName) {
			idxToRowMap[rowIdx] = vulnRowData{content: rowContent, fileType: buildFileData.fileType, filepath: buildFileData.filePath}
		}
	}
	return idxToRowMap
}

// detectVulnerableRowsType detects each vulnerable row's type and updates vulnRowData map
// if there is no match for some row with any known type, the row's type will be set to 'unknown'
func detectVulnerableRowsType(vulnerableRows map[int]vulnRowData) map[int]vulnRowData {
	for rowIdx, data := range vulnerableRows {
		row := data.content //strings.TrimLeft(data.content, " ") //TODO make sure trimming spaces doesn't interfere fix in correct indentation/ or no trimmimg doesnnt interfere regexp detection
		rowType := unknownRowType
		for patternName, regexpCompiler := range patternsCompilers {
			if regexpCompiler.MatchString(row) {
				rowType = patternName
			}
		}
		vulnerableRows[rowIdx] = vulnRowData{
			content:  vulnerableRows[rowIdx].content,
			rowType:  rowType,
			fileType: vulnerableRows[rowIdx].fileType,
			filepath: vulnerableRows[rowIdx].filepath,
		}
	}
	return vulnerableRows
}

func getAllPatternsCompilers() (patternsCompilers map[string]*regexp.Regexp) {
	patternsCompilers = make(map[string]*regexp.Regexp)
	for patternName, pattern := range resources.RegexpNameToPattern {
		var re *regexp.Regexp
		re = regexp.MustCompile(pattern)
		patternsCompilers[patternName] = re
	}
	return
}
