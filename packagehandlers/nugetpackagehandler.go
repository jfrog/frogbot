package packagehandlers

import (
	"errors"
	"fmt"
	"github.com/jfrog/frogbot/v2/utils"
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
	var assetsFilePaths []string
	assetsFilePaths, err = getAssetsFilesPaths()
	if err != nil {
		return
	}

	wd, err := os.Getwd()
	if err != nil {
		err = fmt.Errorf("failed to get current working directory: %s", err.Error())
		return
	}

	vulnRegexpCompiler := getVulnerabilityRegexCompiler(vulnDetails.ImpactedDependencyName, vulnDetails.ImpactedDependencyVersion)
	var isAnyFileChanged bool

	for _, assetFilePath := range assetsFilePaths {
		var isFileChanged bool
		isFileChanged, err = nph.fixVulnerabilityIfExists(vulnDetails, assetFilePath, vulnRegexpCompiler, wd)
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

func getAssetsFilesPaths() (assetsFilePaths []string, err error) {
	err = filepath.WalkDir(".", func(path string, d fs.DirEntry, innerErr error) error {
		if innerErr != nil {
			return fmt.Errorf("an error has occurred when attempting to access or traverse the file system: %s", innerErr.Error())
		}

		if strings.HasSuffix(path, dotnetAssetsFilesSuffix) {
			var absFilePath string
			absFilePath, innerErr = filepath.Abs(path)
			if innerErr != nil {
				return fmt.Errorf("couldn't retrieve file's absolute path for './%s': %s", path, innerErr.Error())
			}
			assetsFilePaths = append(assetsFilePaths, absFilePath)
		}
		return nil
	})
	return
}

func (nph *NugetPackageHandler) fixVulnerabilityIfExists(vulnDetails *utils.VulnerabilityDetails, assetFilePath string, vulnRegexpCompiler *regexp.Regexp, originalWd string) (isFileChanged bool, err error) {
	modulePath := path.Dir(assetFilePath)

	var fileData []byte
	fileData, err = os.ReadFile(assetFilePath)
	if err != nil {
		err = fmt.Errorf("failed to read file '%s': %s", assetFilePath, err.Error())
		return
	}
	fileContent := strings.ToLower(string(fileData))

	if matchingRow := vulnRegexpCompiler.FindString(fileContent); matchingRow != "" {
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

func getVulnerabilityRegexCompiler(impactedName string, impactedVersion string) *regexp.Regexp {
	// We replace '.' with '\\.' since '.' is a special character in regexp patterns, and we want to capture the character '.' itself
	// To avoid dealing with case sensitivity we lower all characters in the package's name and in the file we check
	regexpFitImpactedName := strings.ToLower(strings.ReplaceAll(impactedName, ".", "\\."))
	regexpFitImpactedVersion := strings.ToLower(strings.ReplaceAll(impactedVersion, ".", "\\."))
	regexpCompleteFormat := fmt.Sprintf(dotnetDependencyRegexpLowerCaseFormat, regexpFitImpactedName, regexpFitImpactedVersion)
	return regexp.MustCompile(regexpCompleteFormat)
}
