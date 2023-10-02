package packagehandlers

import (
	"errors"
	"fmt"
	"github.com/jfrog/frogbot/utils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	dotnetPackageUpgradeExtraArg = "package"
	dotnetAssetsFilesSuffix      = "csproj"
	dotnetDependencyRegexpFormat = "(?i)Include=[\\\"|\\']%s[\\\"|\\'][\\s^\\n]*Version=[\\\"|\\']%s[\\\"|\\']"
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

	for _, assetFilePath := range modulesWithAssetsPaths {
		modulePath := path.Dir(assetFilePath)
		objDirPath := filepath.Join(modulePath, "obj")

		var objDirExists bool
		objDirExists, err = fileutils.IsDirExists(objDirPath, false)
		if err != nil {
			err = fmt.Errorf("couldn't check existence of 'obj' directory in '%s'", modulePath)
			return
		}

		var fileData []byte
		fileData, err = os.ReadFile(assetFilePath)
		if err != nil {
			return
		}
		fileContent := string(fileData)

		vulnRegexpCompiler := getVulnerabilityRegexCompiler(vulnDetails.ImpactedDependencyName, vulnDetails.ImpactedDependencyVersion)
		if matchingRow := vulnRegexpCompiler.FindString(fileContent); matchingRow != "" {
			err = os.Chdir(modulePath)
			if err != nil {
				return
			}

			err = nph.CommonPackageHandler.UpdateDependency(vulnDetails, vulnDetails.Technology.GetPackageInstallationCommand(), dotnetPackageUpgradeExtraArg)
			if err != nil {
				return
			}

			// 'obj' directory is created every time we update a dependency and if it doesn't already exist, we remove it
			if !objDirExists {
				err = fileutils.RemoveTempDir(objDirPath)
			}
			continue
		}
	}
	defer func() {
		err = errors.Join(err, os.Chdir(wd))
	}()

	return
}

func getAssetsFilesPaths() (modulesWithAssetsPaths []string, err error) {
	err = filepath.WalkDir(".", func(path string, d fs.DirEntry, innerErr error) error {
		if innerErr != nil {
			return fmt.Errorf("error has occured when trying to access or traverse the files system: %s", err.Error())
		}

		if strings.HasSuffix(path, dotnetAssetsFilesSuffix) {
			var absFilePath string
			absFilePath, innerErr = filepath.Abs(path)
			if innerErr != nil {
				return fmt.Errorf("couldn't retrieve file's absolute path for './%s':%s", path, innerErr.Error())
			}
			modulesWithAssetsPaths = append(modulesWithAssetsPaths, absFilePath)
		}
		return nil
	})
	return
}

func getVulnerabilityRegexCompiler(impactedName string, impactedVersion string) *regexp.Regexp {
	regexpCompleteFormat := fmt.Sprintf(dotnetDependencyRegexpFormat, impactedName, impactedVersion)
	return regexp.MustCompile(regexpCompleteFormat)
}
