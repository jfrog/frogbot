package packagehandlers

import (
	"errors"
	"fmt"
	"github.com/jfrog/frogbot/utils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	dotnetPackageUpgradeExtraArg = "package"
	dotnetAssetsFilesSuffix      = "csproj"
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

	// FROM HERE IS MULTI MODULE
	for _, assetFilePath := range modulesWithAssetsPaths {
		tmp := strings.Split(assetFilePath, string(filepath.Separator)) //TODO check if there is a built in func to remove last entry in a path
		tmp2 := filepath.Join(tmp[:len(tmp)-1]...)
		objDirPath := filepath.Join(string(filepath.Separator), tmp2, "obj")

		var objDirExists bool
		objDirExists, err = fileutils.IsDirExists(objDirPath, false)
		if err != nil {
			err = fmt.Errorf("couldn't check existence of 'obj' directory in '%s'", objDirPath)
			return
		}

		var fileData []byte
		fileData, err = os.ReadFile(assetFilePath)
		if err != nil {
			return
		}
		fileContent := string(fileData)
		// TODO move regexp preparation to better place
		// TODO deal with lower/ big letters in package name
		regexpFormat := fmt.Sprintf("(?i)PackageReference[\\s^\\n]*Include=[\\\"|\\']%s[\\\"|\\'][\\s^\\n]*Version=[\\\"|\\']%s[\\\"|\\']", vulnDetails.ImpactedDependencyName, vulnDetails.ImpactedDependencyVersion)
		regexpCompiler := regexp.MustCompile(regexpFormat)
		if matchingRow := regexpCompiler.FindString(fileContent); matchingRow != "" {
			//todo change the names here to be more clear
			//tmp3 := strings.Split(assetFilePath, string(filepath.Separator))[:len(assetFilePath)-1]
			moduleToUpdate := filepath.Join(string(filepath.Separator), tmp2)
			err = os.Chdir(moduleToUpdate)
			if err != nil {
				return
			}
			err = nph.CommonPackageHandler.UpdateDependency(vulnDetails, vulnDetails.Technology.GetPackageInstallationCommand(), dotnetPackageUpgradeExtraArg)
			if err != nil {
				return
			}
			if !objDirExists {
				err = fileutils.RemoveTempDir(objDirPath)
			}
			continue
		}
	}
	defer func() {
		err = errors.Join(err, os.Chdir(wd))
	}()

	/*
		// Fix for multi-module project is currently not supported. Fix is available only for a single asset file resides in the root directory
		if len(modulesWithAssetsPaths) > 1 {
			err = fmt.Errorf("fixing multi-module project or project with several assets files is currently unavailable")
			return
		}
		 *

		buildFilesDirPath := filepath.Join(string(filepath.Separator), modulesWithAssetsPaths[0], "obj")

		exists, err := fileutils.IsDirExists(buildFilesDirPath, false)
		err = nph.CommonPackageHandler.UpdateDependency(vulnDetails, vulnDetails.Technology.GetPackageInstallationCommand(), dotnetPackageUpgradeExtraArg)
		if err != nil {
			return
		}

		if !exists {
			err = fileutils.RemoveTempDir(buildFilesDirPath)
		}
		return
	*/
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
			// tmp := strings.Split(absFilePath, string(filepath.Separator)) //TODO check id use of separator is correct
			// absFilePath = filepath.Join(tmp[:len(tmp)-1]...)
			modulesWithAssetsPaths = append(modulesWithAssetsPaths, absFilePath)
		}
		return nil
	})
	return
}
