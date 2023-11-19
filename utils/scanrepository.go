package utils

import (
	"fmt"
	biutils "github.com/jfrog/build-info-go/utils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"os"
	"path/filepath"
)

// Generates a temporary directory and duplicates the current working directory files into it. Provides the complete path for the temporary directory.
func CopyCurrentDirFilesToTempDir() (tempDirPath string, err error) {
	var wd string
	tempDirPath, err = fileutils.CreateTempDir()
	if err != nil {
		err = fmt.Errorf("couldn't create a temp dir: %s", err.Error())
		return
	}

	wd, err = os.Getwd()
	if err != nil {
		return
	}
	// If modifications have been made in the current working directory since it was cloned, we retain a duplicate of its files before initiating a new branch from the initially cloned directory.
	err = biutils.CopyDir(wd, tempDirPath, false, nil)
	return
}

// Duplicates all files from sourceDirPath into the present working directory, omitting any files that already exist.
func CopyMissingFilesToCurrentWorkingDir(sourceDirPath string) (err error) {
	var wd string
	wd, err = os.Getwd()
	if err != nil {
		return
	}

	var alreadyExistingFiles []string
	alreadyExistingFiles, err = fileutils.ListFiles(wd, false)
	if err != nil {
		err = fmt.Errorf("couldn't get a list of files in current working directory '%s': %s", wd, err.Error())
		return
	}
	// We need only the filename, not its complete path, to omit it from the duplication process
	for idx, fileFullPath := range alreadyExistingFiles {
		alreadyExistingFiles[idx] = filepath.Base(fileFullPath)
	}

	err = biutils.CopyDir(sourceDirPath, wd, false, alreadyExistingFiles)
	return
}
