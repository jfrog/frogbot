package packagehandlers

import (
	"fmt"
	"github.com/jfrog/frogbot/utils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"io/fs"
	"path/filepath"
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
	modulesWithAssetsPaths, err = getModulesWithAssetsPaths()
	if err != nil {
		return
	}

	// Fix for multi-module project is currently not supported. Fix is available only for a single asset file resides in the root directory
	if len(modulesWithAssetsPaths) > 1 {
		err = fmt.Errorf("fixing multi-module project or project with several assets files is currently unavailable")
		return
	}

	// Checking existence of 'obj' directory before update in order to push only the correct changes into the PR
	//wd, err := os.Getwd()
	//if err != nil {
	//	return
	//}
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
}

func getModulesWithAssetsPaths() (modulesWithAssetsPaths []string, err error) {
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
			tmp := strings.Split(absFilePath, string(filepath.Separator)) //TODO check id use of separator is correct
			absFilePath = filepath.Join(tmp[:len(tmp)-1]...)
			modulesWithAssetsPaths = append(modulesWithAssetsPaths, absFilePath)
		}
		return nil
	})
	return
}
