package packagehandlers

import (
	"errors"
	"fmt"
	"github.com/jfrog/frogbot/v2/utils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	pnpmDependencyPattern    = "\\s*\"%s\"\\s*:\\s*\"[~|^]?%s\""
	pnpmDescriptorFileSuffix = "package.json"
	nodeModulesPathPattern   = ".*node_modules.*"
)

type PnpmPackageHandler struct {
	CommonPackageHandler
}

func (pnpm *PnpmPackageHandler) UpdateDependency(vulnDetails *utils.VulnerabilityDetails) error {
	if vulnDetails.IsDirectDependency {
		return pnpm.updateDirectDependency(vulnDetails)
	}

	return &utils.ErrUnsupportedFix{
		PackageName:  vulnDetails.ImpactedDependencyName,
		FixedVersion: vulnDetails.SuggestedFixedVersion,
		ErrorType:    utils.IndirectDependencyFixNotSupported,
	}
}

func (pnpm *PnpmPackageHandler) updateDirectDependency(vulnDetails *utils.VulnerabilityDetails) (err error) {
	descriptorFilesFullPaths, err := pnpm.CommonPackageHandler.GetAllDescriptorFilesFullPaths([]string{pnpmDescriptorFileSuffix}, nodeModulesPathPattern)
	if err != nil {
		return
	}

	wd, err := os.Getwd()
	if err != nil {
		err = fmt.Errorf("failed to get current working directory: %s", err.Error())
		return
	}

	var anyDescriptorChanged bool
	for _, descriptorFile := range descriptorFilesFullPaths {
		var isFileChanged bool
		isFileChanged, err = pnpm.fixVulnerabilityIfExists(vulnDetails, descriptorFile, wd)
		if err != nil {
			return
		}
		anyDescriptorChanged = anyDescriptorChanged || isFileChanged
	}
	if !anyDescriptorChanged {
		err = fmt.Errorf("impacted package '%s' was not found in any descriptor files", vulnDetails.ImpactedDependencyName)
	}
	return
}

func (pnpm *PnpmPackageHandler) fixVulnerabilityIfExists(vulnDetails *utils.VulnerabilityDetails, descriptorFilePath, originalWd string) (isFileChanged bool, err error) {
	var fileData []byte
	fileData, err = os.ReadFile(descriptorFilePath)
	if err != nil {
		err = fmt.Errorf("failed to read file '%s': %s", descriptorFilePath, err.Error())
		return
	}

	vulnDepRegexp := getRegexpCompilerForVulnerability(vulnDetails.ImpactedDependencyName, vulnDetails.ImpactedDependencyVersion)

	// Only if the vulnerable dependency is detected in the current descriptor, we initiate a fix
	if match := vulnDepRegexp.FindString(strings.ToLower(string(fileData))); match != "" {
		modulePath := path.Dir(descriptorFilePath)
		err = os.Chdir(modulePath)
		if err != nil {
			err = fmt.Errorf("failed to change directory to '%s': %s", modulePath, err.Error())
			return
		}
		defer func() {
			err = errors.Join(err, os.Chdir(originalWd))
		}()

		var nodeModulesDirExist bool
		nodeModulesDirExist, err = fileutils.IsDirExists(filepath.Join(modulePath, "node_modules"), false)

		err = pnpm.CommonPackageHandler.UpdateDependency(vulnDetails, vulnDetails.Technology.GetPackageInstallationCommand())
		if err != nil {
			err = fmt.Errorf("failed to update dependency '%s' from version '%s' to '%s': %s", vulnDetails.ImpactedDependencyName, vulnDetails.ImpactedDependencyVersion, vulnDetails.SuggestedFixedVersion, err.Error())
		}

		if !nodeModulesDirExist {
			// If the node_modules directory doesn't exist prior to the fix, we remove it to prevent it from being included in the pull request.
			err = fileutils.RemoveTempDir(filepath.Join(modulePath, "node_modules"))
		}
		isFileChanged = true
	}
	return
}

func getRegexpCompilerForVulnerability(vulnPackageName, vulnPackageVersion string) *regexp.Regexp {
	regexpAdjustedPackageName := strings.ReplaceAll(vulnPackageName, ".", "\\.")
	regexpAdjustedVersion := strings.ReplaceAll(vulnPackageVersion, ".", "\\.")
	patternToLookFor := strings.ToLower(fmt.Sprintf(pnpmDependencyPattern, regexpAdjustedPackageName, regexpAdjustedVersion))
	return regexp.MustCompile(patternToLookFor)
}
