package packagehandlers

import (
	"errors"
	"fmt"
	fileutils "github.com/jfrog/build-info-go/utils"
	"github.com/jfrog/frogbot/utils"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	"math"
	"os"
	"regexp"
	"strings"
	//"github.com/jfrog/frogbot/packagehandlers/resources"
)

const (
	groovyBuildFile              = "groovy"
	kotlinBuildFile              = "kotlin"
	directStringWithVersionRegex = "[a-zA-Z]+\\s[\\\"|\\'][a-zA-Z]+:[a-zA-Z]+:[0-9]+\\.[0-9]+\\.?[0-9]*[\\\"|\\']"
)

type GradlePackageHandler struct {
	CommonPackageHandler
}

type buildFileData struct {
	fileName    string
	fileType    string
	file        *os.File
	fileContent []string
}

type rowData struct {
	content string
	rowType string
}

var buildFileToType = map[string]string{
	"build.gradle":     groovyBuildFile,
	"build.gradle.kts": kotlinBuildFile,
}

var regexpNameToPattern = map[string]string{"directStringWithVersion": directStringWithVersionRegex}

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

	/* TODO delete if using ReadNLines at the end
	defer func() {
		for _, buildFileData := range buildFiles {
			err = errors.Join(err, buildFileData.file.Close())
		}
	}() */

	// search for the vulnerability
	for _, buildFile := range buildFiles {
		//get vulnerable rows
		//TODO check what to do if there are several rows with the same package, or in different build files
		vulnerableRows := getVulnerableRowsInFile(&buildFile, vulnDetails.ImpactedDependencyName)

		// detect kind of row
		vulnerableRows, err = detectVulnerableRowsType(vulnerableRows)
		if err != nil {
			return
		}

		// issue a fix
		//TODO make a factory for the fixers and get them by the name
		// CONTINUE FROM HERE!!!

	}

	return errors.New("stop at updateDirectDependency")
}

func readBuildFiles() (buildFiles []buildFileData, err error) {
	dirContent, err := os.ReadDir(".")
	if err != nil {
		err = fmt.Errorf("couldn't read working directory: %q", err)
		return
	}

	//TODO check if this process is working for multi-dir and can detect build files not in main dir
	for _, dirEntry := range dirContent {
		fileName := dirEntry.Name()
		if fileName == "build.gradle" || fileName == "build.gradle.kts" {
			var fileContent []string
			fileContent, err = fileutils.ReadNLines(fileName, math.MaxInt)
			if err != nil {
				err = fmt.Errorf("couldn't read %s file: %q", fileName, err)
				return
			}
			buildFiles = append(buildFiles, buildFileData{fileName: fileName, fileType: buildFileToType[fileName], fileContent: fileContent})

			//TODO delete if using ReadNLines at the end
			//var file *os.File
			//file, err = os.OpenFile(fileName, os.O_RDWR, 0666) //TODO validate perm number
			//if err != nil {
			//return
			//}
			//buildFiles = append(buildFiles, buildFileData{fileName: fileName, fileType: buildFileToType[fileName], file: file})
		}
	}
	if len(buildFiles) == 0 {
		err = errorutils.CheckErrorf("couldn't detect any build file in the project")
	}
	return
}

func getVulnerableRowsInFile(buildFileData *buildFileData, impactedPackageName string) map[int]rowData {
	idxToRowMap := make(map[int]rowData)

	for rowIdx, rowContent := range buildFileData.fileContent {
		if strings.Contains(rowContent, impactedPackageName) {
			idxToRowMap[rowIdx] = rowData{content: rowContent}
		}
	}
	return idxToRowMap
}

func detectVulnerableRowsType(vulnerableRows map[int]rowData) (map[int]rowData, error) {
	patternsCompilers, err := getAllPatternsCompilers()
	if err != nil {
		return nil, err
	}

	for rowIdx, data := range vulnerableRows {
		row := data.content
		for patternName, regexpCompiler := range patternsCompilers {
			if regexpCompiler.MatchString(row) {
				content := vulnerableRows[rowIdx].content
				vulnerableRows[rowIdx] = rowData{
					content: content,
					rowType: patternName,
				}
			}
		}
	}
	return vulnerableRows, err
}

func getAllPatternsCompilers() (patternsCompilers map[string]*regexp.Regexp, err error) {
	patternsCompilers = make(map[string]*regexp.Regexp)
	for patternName, pattern := range regexpNameToPattern {
		var re *regexp.Regexp
		re, err = regexp.Compile(pattern)
		if err != nil {
			err = fmt.Errorf("couldn't compile regex pattern '%s'")
			return
		}
		patternsCompilers[patternName] = re
	}
	return
}
