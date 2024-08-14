package packagehandlers

import (
	"errors"
	"fmt"
	"github.com/jfrog/frogbot/v2/utils"
	"os"
	"path"
	"regexp"
	"strings"
)

const (
	dotnetUpdateCmdPackageExtraArg = "package"
	dotnetNoRestoreFlag            = "--no-restore"
	dotnetAssetsFilesSuffix        = "csproj"
	dotnetDependencyRegexpPattern  = "include=[\\\"|\\']%s[\\\"|\\']\\s*version=[\\\"|\\']%s[\\\"|\\']"
)

type NugetPackageHandler struct {
	CommonPackageHandler
}

func (nph *NugetPackageHandler) UpdateDependency(vulnDetails *utils.VulnerabilityDetails) error {
	if vulnDetails.IsDirectDependency {
		return nph.updateDirectDependency(vulnDetails)
	}

	return &utils.ErrUnsupportedFix{
		PackageName:  vulnDetails.ImpactedDependencyName,
		FixedVersion: vulnDetails.SuggestedFixedVersion,
		ErrorType:    utils.IndirectDependencyFixNotSupported,
	}
}

func (nph *NugetPackageHandler) updateDirectDependency(vulnDetails *utils.VulnerabilityDetails) (err error) {
	var descriptorFilesFullPaths []string
	descriptorFilesFullPaths, err = nph.GetAllDescriptorFilesFullPaths([]string{dotnetAssetsFilesSuffix})
	if err != nil {
		return
	}

	wd, err := os.Getwd()
	if err != nil {
		err = fmt.Errorf("failed to get current working directory: %s", err.Error())
		return
	}

	vulnRegexpCompiler := GetVulnerabilityRegexCompiler(vulnDetails.ImpactedDependencyName, vulnDetails.ImpactedDependencyVersion, dotnetDependencyRegexpPattern)
	var isAnyFileChanged bool

	for _, descriptorFilePath := range descriptorFilesFullPaths {
		var isFileChanged bool
		isFileChanged, err = nph.fixVulnerabilityIfExists(vulnDetails, descriptorFilePath, wd, vulnRegexpCompiler)
		if err != nil {
			err = fmt.Errorf("failed to update asset file '%s': %s", descriptorFilePath, err.Error())
			return
		}

		// We use logic OR in order to keep track whether any asset file changed during the fix process
		isAnyFileChanged = isAnyFileChanged || isFileChanged
	}

	if !isAnyFileChanged {
		err = fmt.Errorf("impacted package '%s' was not found or could not be fixed in all descriptor files", vulnDetails.ImpactedDependencyName)
	}
	return
}

func (nph *NugetPackageHandler) fixVulnerabilityIfExists(vulnDetails *utils.VulnerabilityDetails, descriptorFilePath, originalWd string, vulnRegexpCompiler *regexp.Regexp) (isFileChanged bool, err error) {
	modulePath := path.Dir(descriptorFilePath)

	var fileData []byte
	fileData, err = os.ReadFile(descriptorFilePath)
	if err != nil {
		err = fmt.Errorf("failed to read file '%s': %s", descriptorFilePath, err.Error())
		return
	}

	if matchingRow := vulnRegexpCompiler.FindString(strings.ToLower(string(fileData))); matchingRow != "" {
		err = os.Chdir(modulePath)
		if err != nil {
			err = fmt.Errorf("failed to change directory to '%s': %s", modulePath, err.Error())
			return
		}
		defer func() {
			err = errors.Join(err, os.Chdir(originalWd))
		}()

		err = nph.CommonPackageHandler.UpdateDependency(vulnDetails, vulnDetails.Technology.GetPackageInstallationCommand(), dotnetUpdateCmdPackageExtraArg, dotnetNoRestoreFlag)
		if err != nil {
			return
		}
		isFileChanged = true
	}
	return
}
