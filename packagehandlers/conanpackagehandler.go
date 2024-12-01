package packagehandlers

import (
	"errors"
	"fmt"
	"github.com/jfrog/frogbot/v2/utils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"os"
	"path/filepath"
	"strings"
)

const (
	conanFileTxt = "conanfile.txt"
	conanFilePy  = "conanfile.py"
)

type ConanPackageHandler struct {
	CommonPackageHandler
}

func (conan *ConanPackageHandler) UpdateDependency(vulnDetails *utils.VulnerabilityDetails) error {
	if vulnDetails.IsDirectDependency {
		return conan.updateDirectDependency(vulnDetails)
	} else {
		return &utils.ErrUnsupportedFix{
			PackageName:  vulnDetails.ImpactedDependencyName,
			FixedVersion: vulnDetails.SuggestedFixedVersion,
			ErrorType:    utils.IndirectDependencyFixNotSupported,
		}
	}
}

func (conan *ConanPackageHandler) updateDirectDependency(vulnDetails *utils.VulnerabilityDetails) (err error) {
	isConanFileTxtExists, err := fileutils.IsFileExists(conanFileTxt, false)
	if err != nil {
		err = fmt.Errorf("failed while serching for conanfile in project: %s", err.Error())
		return
	}
	if isConanFileTxtExists {
		if err = conan.updateConanFile(conanFileTxt, vulnDetails); err != nil {
			return
		}
		conan.logNoInstallationMessage()
		return
	}
	isConanFilePyExists, err := fileutils.IsFileExists(conanFilePy, false)
	if err != nil {
		err = fmt.Errorf("failed while serching for conanfile in project: %s", err.Error())
		return
	}
	if isConanFilePyExists {
		if err = conan.updateConanFile(conanFilePy, vulnDetails); err != nil {
			return
		}
		conan.logNoInstallationMessage()
		return
	}
	// If no conanfile found, return an error
	return fmt.Errorf("failed to update conan dependency: conanfile not found")

}

func (conan *ConanPackageHandler) updateConanFile(conanFileName string, vulnDetails *utils.VulnerabilityDetails) (err error) {
	var fixedFile string
	wd, err := os.Getwd()
	if err != nil {
		return
	}
	filePath := filepath.Clean(filepath.Join(wd, conanFileName))
	if !strings.HasPrefix(filePath, wd) {
		return errors.New("wrong requirements file input")
	}
	data, err := os.ReadFile(filePath)
	if err != nil {
		return errors.New("an error occurred while attempting to read the requirements file:\n" + err.Error())
	}
	currentFile := string(data)
	fixedPackage := vulnDetails.ImpactedDependencyName + "/" + vulnDetails.SuggestedFixedVersion
	impactedDependency := vulnDetails.ImpactedDependencyName + "/" + vulnDetails.ImpactedDependencyVersion
	fixedFile = strings.Replace(currentFile, impactedDependency, strings.ToLower(fixedPackage), 1)

	if fixedFile == "" {
		return fmt.Errorf("impacted package %s not found, fix failed", vulnDetails.ImpactedDependencyName)
	}
	if err = os.WriteFile(conanFileName, []byte(fixedFile), 0600); err != nil {
		err = fmt.Errorf("an error occured while writing the fixed version of %s to the requirements file '%s': %s", conanFileName, vulnDetails.ImpactedDependencyName, err.Error())
	}
	return
}

func (conan *ConanPackageHandler) logNoInstallationMessage() {
	log.Info("Requirements file was updated with a suggested fix version, but no installation was performed. " +
		"In order to update the dependencies, please run 'conan install' command")
}
