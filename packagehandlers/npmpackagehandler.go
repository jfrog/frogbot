package packagehandlers

import (
	"errors"
	"fmt"
	"github.com/jfrog/frogbot/utils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"os"
	"path/filepath"
)

type NpmPackageHandler struct {
	CommonPackageHandler
}

func (npm *NpmPackageHandler) UpdateDependency(vulnDetails *utils.VulnerabilityDetails) error {
	if vulnDetails.IsDirectDependency {
		return npm.updateDirectDependency(vulnDetails)
	} else {
		return &utils.ErrUnsupportedFix{
			PackageName:  vulnDetails.ImpactedDependencyName,
			FixedVersion: vulnDetails.SuggestedFixedVersion,
			ErrorType:    utils.IndirectDependencyFixNotSupported,
		}
	}
}

func (npm *NpmPackageHandler) updateDirectDependency(vulnDetails *utils.VulnerabilityDetails) (err error) {
	tmpDir, err := fileutils.CreateTempDir()
	if err != nil {
		err = fmt.Errorf("failed to create temporary dir during '%s' dependency fix: %s", vulnDetails.ImpactedDependencyName, err.Error())
		return
	}
	defer func() {
		err = errors.Join(err, fileutils.RemoveTempDir(tmpDir))
	}()

	curWd, err := os.Getwd()
	if err != nil {
		return
	}

	packageJsonFilePath := filepath.Join(curWd, "package.json")
	updatedPackageJsonFilePath := filepath.Join(tmpDir, "package.json")

	// Package.json is assumed to be in the current working dir
	// We move package.json to a temp dir in order to execute the fix and leave the original dir unchanged but the updated package.json
	err = fileutils.MoveFile(packageJsonFilePath, updatedPackageJsonFilePath)
	if err != nil {
		err = fmt.Errorf("couldn't move package.json to a temporary dir in order to execute the fix for '%s' dependency: %s", vulnDetails.ImpactedDependencyName, err.Error())
		return
	}
	err = npm.CommonPackageHandler.UpdateDependency(vulnDetails, vulnDetails.Technology.GetPackageInstallationCommand(), "--prefix", tmpDir)
	if err != nil {
		err = fmt.Errorf("failed during executing fix command for '%s' dependency: %s", vulnDetails.ImpactedDependencyName, err.Error())
		return
	}

	err = fileutils.MoveFile(updatedPackageJsonFilePath, packageJsonFilePath)
	if err != nil {
		err = fmt.Errorf("couldn't move package.json from a temporary dir to the original working dir '%s': %s", curWd, err.Error())
	}
	return
}
