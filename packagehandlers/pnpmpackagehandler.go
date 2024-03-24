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
	pnpmDependencyRegexpPattern = "\\s*\"%s\"\\s*:\\s*\"[~|^]?%s\""
	pnpmDescriptorFileSuffix    = "package.json"
	nodeModulesPathPattern      = ".*node_modules.*"
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
		return err
	}

	wd, err := os.Getwd()
	if err != nil {
		err = fmt.Errorf("failed to get current working directory: %s", err.Error())
		return err
	}

	vulnRegexpCompiler := GetVulnerabilityRegexCompiler(vulnDetails.ImpactedDependencyName, vulnDetails.ImpactedDependencyVersion, pnpmDependencyRegexpPattern)

	var anyDescriptorChanged bool
	for _, descriptorFile := range descriptorFilesFullPaths {
		var isFileChanged bool
		isFileChanged, err = pnpm.fixVulnerabilityIfExists(vulnDetails, descriptorFile, wd, vulnRegexpCompiler)
		if err != nil {
			return err
		}
		anyDescriptorChanged = anyDescriptorChanged || isFileChanged
	}
	if !anyDescriptorChanged {
		err = fmt.Errorf("impacted package %q was not found in any descriptor files", vulnDetails.ImpactedDependencyName)
	}
	return err
}

func (pnpm *PnpmPackageHandler) fixVulnerabilityIfExists(vulnDetails *utils.VulnerabilityDetails, descriptorFilePath, originalWd string, vulnRegexpCompiler *regexp.Regexp) (isFileChanged bool, err error) {
	var descriptorFileData []byte
	descriptorFileData, err = os.ReadFile(descriptorFilePath)
	if err != nil {
		err = fmt.Errorf("failed to read file '%s': %s", descriptorFilePath, err.Error())
		return isFileChanged, err
	}

	// Only if the vulnerable dependency is detected in the current descriptor, we initiate a fix
	if match := vulnRegexpCompiler.FindString(strings.ToLower(string(descriptorFileData))); match != "" {
		modulePath := path.Dir(descriptorFilePath)
		if err = os.Chdir(modulePath); err != nil {
			err = fmt.Errorf("failed to change directory to '%s': %s", modulePath, err.Error())
			return isFileChanged, err
		}
		defer func() {
			err = errors.Join(err, os.Chdir(originalWd))
		}()

		var nodeModulesDirExist bool
		if nodeModulesDirExist, err = fileutils.IsDirExists(filepath.Join(modulePath, "node_modules"), false); err != nil {
			return isFileChanged, err
		}

		if !nodeModulesDirExist {
			defer func() {
				// If node_modules directory doesn't exist prior to the dependency update we aim remove it after the update.
				err = errors.Join(err, fileutils.RemoveTempDir(filepath.Join(modulePath, "node_modules")))
			}()
		}

		if err = pnpm.CommonPackageHandler.UpdateDependency(vulnDetails, vulnDetails.Technology.GetPackageInstallationCommand()); err != nil {
			return isFileChanged, fmt.Errorf("failed to update dependency '%s' from version '%s' to '%s': %s", vulnDetails.ImpactedDependencyName, vulnDetails.ImpactedDependencyVersion, vulnDetails.SuggestedFixedVersion, err.Error())
		}
		isFileChanged = true
	}
	return isFileChanged, err
}
