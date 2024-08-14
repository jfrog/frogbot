package packagehandlers

import (
	"errors"
	"fmt"
	biUtils "github.com/jfrog/build-info-go/build/utils"
	"github.com/jfrog/frogbot/v2/utils"
	"github.com/jfrog/gofrog/version"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
)

const (
	yarnV2Version          = "2.0.0"
	yarnV1PackageUpdateCmd = "upgrade"
	yarnV2PackageUpdateCmd = "up"
	modulesFolderFlag      = "--modules-folder="
)

type YarnPackageHandler struct {
	CommonPackageHandler
}

func (yarn *YarnPackageHandler) UpdateDependency(vulnDetails *utils.VulnerabilityDetails) error {
	if vulnDetails.IsDirectDependency {
		return yarn.updateDirectDependency(vulnDetails)
	} else {
		return &utils.ErrUnsupportedFix{
			PackageName:  vulnDetails.ImpactedDependencyName,
			FixedVersion: vulnDetails.SuggestedFixedVersion,
			ErrorType:    utils.IndirectDependencyFixNotSupported,
		}
	}
}

func (yarn *YarnPackageHandler) updateDirectDependency(vulnDetails *utils.VulnerabilityDetails) (err error) {
	isYarn1, executableYarnVersion, err := isYarnV1Project()
	if err != nil {
		return
	}

	var installationCommand string
	var extraArgs []string

	if isYarn1 {
		installationCommand = yarnV1PackageUpdateCmd
		// This dir is created to store node_modules that are created during updating packages in Yarn V1. This dir is to be deleted and not pushed into the PR
		var tmpNodeModulesDir string
		tmpNodeModulesDir, err = fileutils.CreateTempDir()
		defer func() {
			err = errors.Join(err, fileutils.RemoveTempDir(tmpNodeModulesDir))
		}()

		if err != nil {
			return
		}
		extraArgs = append(extraArgs, modulesFolderFlag+tmpNodeModulesDir)
	} else {
		installationCommand = yarnV2PackageUpdateCmd
	}
	err = yarn.CommonPackageHandler.UpdateDependency(vulnDetails, installationCommand, extraArgs...)
	if err != nil {
		err = fmt.Errorf("running 'yarn %s for '%s' failed:\n%s\nHint: The Yarn version that was used is: %s. If your project was built with a different major version of Yarn, please configure your CI runner to include it",
			installationCommand,
			vulnDetails.ImpactedDependencyName,
			err.Error(),
			executableYarnVersion)
	}
	return
}

// isYarnV1Project gets the current executed yarn version and returns whether the current yarn version is V1 or not
func isYarnV1Project() (isYarn1 bool, executableYarnVersion string, err error) {
	// NOTICE: in case your global yarn version is 1.x this function will always return true even if the project is originally in higher yarn version
	executableYarnVersion, err = biUtils.GetVersion("yarn", "")
	if err != nil {
		return
	}
	log.Info("Using Yarn version: ", executableYarnVersion)
	isYarn1 = version.NewVersion(executableYarnVersion).Compare(yarnV2Version) > 0
	return
}
