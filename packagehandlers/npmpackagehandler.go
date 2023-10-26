package packagehandlers

import (
	"fmt"
	"github.com/jfrog/frogbot/utils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"path/filepath"
)

const (
	npmInstallPackageLockOnlyFlag = "--package-lock-only"
	npmInstallIgnoreScriptsFlag   = "--ignore-scripts"
)

type NpmPackageHandler struct {
	CommonPackageHandler
}

func (npm *NpmPackageHandler) UpdateDependency(vulnDetails *utils.VulnerabilityDetails) error {
	if vulnDetails.IsDirectDependency {
		return npm.updateDirectDependency(vulnDetails)
	} else {
		return &utils.ErrUnsupportedFix{
			PackageName:  vulnDetails.ImpactedDependencyName,
			FixedVersion: vulnDetails.SuggestedFixedVersion,
			ErrorType:    utils.IndirectDependencyFixNotSupported,
		}
	}
}

func (npm *NpmPackageHandler) updateDirectDependency(vulnDetails *utils.VulnerabilityDetails) (err error) {
	isNodeModulesExists, err := fileutils.IsDirExists(filepath.Join(".", "node_modules"), false)
	if err != nil {
		err = fmt.Errorf("failed while serching for node_modules in project: %s", err.Error())
		return
	}
	if !isNodeModulesExists {
		// In case node_modules don't exist in current dir the fix will update only package.json and package-lock.json
		return npm.CommonPackageHandler.UpdateDependency(vulnDetails, vulnDetails.Technology.GetPackageInstallationCommand(), npmInstallPackageLockOnlyFlag, npmInstallIgnoreScriptsFlag)
	}
	return npm.CommonPackageHandler.UpdateDependency(vulnDetails, vulnDetails.Technology.GetPackageInstallationCommand(), npmInstallIgnoreScriptsFlag)
}
