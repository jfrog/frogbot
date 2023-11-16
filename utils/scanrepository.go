package utils

import (
	"fmt"
	biutils "github.com/jfrog/build-info-go/utils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"os"
	"path/filepath"
)

// Creates a temp dir and copy curreent workding dir files into it. Returns a full path for the temp dir
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
	// If changes have been made in the current working dir since we cloned it we keep a copy of its files before we create a new branch from the original cloned dir
	err = biutils.CopyDir(wd, tempDirPath, false, nil)
	return
}

// Copies all files from sourceDirPath to the current working dir, while avoiding copying files that already exist
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
	// We must have only the name of the file and not its full path in order to exclude it from the copy
	for idx, fileFullPath := range alreadyExistingFiles {
		alreadyExistingFiles[idx] = filepath.Base(fileFullPath)
	}

	err = biutils.CopyDir(sourceDirPath, wd, false, alreadyExistingFiles)
	return
}
