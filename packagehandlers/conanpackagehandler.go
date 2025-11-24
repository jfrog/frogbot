package packagehandlers

import (
	"fmt"
	"os"
	"strings"

	"github.com/jfrog/frogbot/v2/utils"
	"github.com/jfrog/jfrog-client-go/utils/log"
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
	conanDescriptors, err := conan.CommonPackageHandler.GetAllDescriptorFilesFullPaths([]string{conanFileTxt, conanFilePy})
	if err != nil {
		err = fmt.Errorf("failed while searching for Conan descriptor files in project: %s", err.Error())
		return
	}
	isAnyDescriptorFileChanged := false
	for _, descriptor := range conanDescriptors {
		var isFileChanged bool
		isFileChanged, err = conan.updateConanFile(descriptor, vulnDetails)
		if err != nil {
			return
		}
		isAnyDescriptorFileChanged = isAnyDescriptorFileChanged || isFileChanged
	}
	if !isAnyDescriptorFileChanged {
		err = fmt.Errorf("impacted package '%s' was not found or could not be fixed in all descriptor files", vulnDetails.ImpactedDependencyName)
	} else {
		log.Info("Requirements file was updated with a suggested fix version, but no installation was performed. " +
			"In order to update the dependencies, please run 'conan install' command")
	}
	return
}

func (conan *ConanPackageHandler) updateConanFile(conanFilePath string, vulnDetails *utils.VulnerabilityDetails) (isFileChanged bool, err error) {
	data, err := os.ReadFile(conanFilePath)
	if err != nil {
		return false, fmt.Errorf("an error occurred while attempting to read the requirements file '%s': %s\n", conanFilePath, err.Error())
	}
	currentFile := string(data)
	fixedPackage := vulnDetails.ImpactedDependencyName + "/" + vulnDetails.SuggestedFixedVersion
	impactedDependency := vulnDetails.ImpactedDependencyName + "/" + vulnDetails.ImpactedDependencyVersion
	fixedFile := strings.Replace(currentFile, impactedDependency, strings.ToLower(fixedPackage), 1)

	if fixedFile == currentFile {
		log.Debug(fmt.Sprintf("impacted dependency '%s' not found in descriptor '%s', moving to the next descriptor if exists...", impactedDependency, conanFilePath))
		return false, nil
	}
	if err = os.WriteFile(conanFilePath, []byte(fixedFile), 0600); err != nil {
		err = fmt.Errorf("an error occured while writing the fixed version of %s to the requirements file '%s': %s", vulnDetails.ImpactedDependencyName, conanFilePath, err.Error())
	}
	isFileChanged = true
	return
}
