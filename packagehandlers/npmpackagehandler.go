package packagehandlers

import (
	"errors"
	"fmt"
	"github.com/jfrog/frogbot/v2/utils"
	npmCommand "github.com/jfrog/jfrog-cli-artifactory/artifactory/commands/npm"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
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
	isNodeModulesExists, err := fileutils.IsDirExists("node_modules", false)
	if err != nil {
		err = fmt.Errorf("failed while serching for node_modules in project: %s", err.Error())
		return
	}

	commandFlags := []string{npmInstallIgnoreScriptsFlag}
	if !isNodeModulesExists {
		// In case node_modules don't exist in current dir the fix will update only package.json and package-lock.json
		commandFlags = append(commandFlags, npmInstallPackageLockOnlyFlag)
	}

	// Configure resolution from an Artifactory server if needed
	if npm.depsRepo != "" {
		var clearResolutionServerFunc func() error
		clearResolutionServerFunc, err = npmCommand.SetArtifactoryAsResolutionServer(npm.serverDetails, npm.depsRepo)
		if err != nil {
			return
		}
		defer func() {
			err = errors.Join(err, clearResolutionServerFunc())
		}()
	}
	return npm.CommonPackageHandler.UpdateDependency(vulnDetails, vulnDetails.Technology.GetPackageInstallationCommand(), commandFlags...)
}
