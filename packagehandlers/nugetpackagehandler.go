package packagehandlers

import (
	"errors"
	"fmt"
	"github.com/jfrog/frogbot/utils"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	dotnetUpdateCmdPackageExtraArg        = "package"
	dotnetNoRestoreFlag                   = "--no-restore"
	dotnetAssetsFilesSuffix               = "csproj"
	dotnetDependencyRegexpLowerCaseFormat = "include=[\\\"|\\']%s[\\\"|\\']\\s*version=[\\\"|\\']%s[\\\"|\\']"
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
	var modulesWithAssetsPaths []string
	modulesWithAssetsPaths, err = getAssetsFilesPaths()
	if err != nil {
		return
	}

	wd, err := os.Getwd()
	if err != nil {
		return
	}

	vulnRegexpCompiler := getVulnerabilityRegexCompiler(vulnDetails.ImpactedDependencyName, vulnDetails.ImpactedDependencyVersion)
	var isAnyFileChanged bool

	for _, assetFilePath := range modulesWithAssetsPaths {
		var isFileChanged bool
		isFileChanged, err = fixNugetVulnerabilityIfExists(nph, vulnDetails, assetFilePath, vulnRegexpCompiler, wd)
		if err != nil {
			err = fmt.Errorf("failed to update asset file '%s': %s", assetFilePath, err.Error())
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

func getAssetsFilesPaths() (modulesWithAssetsPaths []string, err error) {
	err = filepath.WalkDir(".", func(path string, d fs.DirEntry, innerErr error) error {
		if innerErr != nil {
			return fmt.Errorf("error has occurrd when trying to access or traverse the files system: %s", innerErr.Error())
		}

		if strings.HasSuffix(path, dotnetAssetsFilesSuffix) {
			var absFilePath string
			absFilePath, innerErr = filepath.Abs(path)
			if innerErr != nil {
				return fmt.Errorf("couldn't retrieve file's absolute path for './%s': %s", path, innerErr.Error())
			}
			modulesWithAssetsPaths = append(modulesWithAssetsPaths, absFilePath)
		}
		return nil
	})
	return
}

func fixNugetVulnerabilityIfExists(nph *NugetPackageHandler, vulnDetails *utils.VulnerabilityDetails, assetFilePath string, vulnRegexpCompiler *regexp.Regexp, originalWd string) (isFileChanged bool, err error) {
	modulePath := path.Dir(assetFilePath)

	var fileData []byte
	fileData, err = os.ReadFile(assetFilePath)
	if err != nil {
		return
	}
	fileContent := strings.ToLower(string(fileData))

	if matchingRow := vulnRegexpCompiler.FindString(fileContent); matchingRow != "" {
		err = os.Chdir(modulePath)
		if err != nil {
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

func getVulnerabilityRegexCompiler(impactedName string, impactedVersion string) *regexp.Regexp {
	// We replace '.' with '\\.' since '.' is a special character in regexp patterns, and we want to capture the character '.' itself
	// To avoid dealing with case sensitivity we lower all characters in the package's name and in the file we check
	regexpFitImpactedName := strings.ToLower(strings.ReplaceAll(impactedName, ".", "\\."))
	regexpCompleteFormat := fmt.Sprintf(dotnetDependencyRegexpLowerCaseFormat, regexpFitImpactedName, impactedVersion)
	return regexp.MustCompile(regexpCompleteFormat)
}
