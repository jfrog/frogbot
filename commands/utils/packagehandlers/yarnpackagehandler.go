package packagehandlers

import (
	"errors"
	biUtils "github.com/jfrog/build-info-go/build/utils"
	"github.com/jfrog/frogbot/commands/utils"
	"github.com/jfrog/gofrog/version"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
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
	executableYarnVersion, err := getYarnVersion()
	if err != nil {
		return
	}

	var tmpDirToDelete string
	var installationCommand string
	var extraArgs []string
	isV2AndAbove := version.NewVersion(executableYarnVersion).Compare(yarnV2Version) <= 0

	if isV2AndAbove {
		installationCommand = yarnV2PackageUpdateCmd
	} else {
		installationCommand = yarnV1PackageUpdateCmd
		tmpDirToDelete, err = fileutils.CreateTempDir()
		if err != nil {
			return
		}
		extraArgs = append(extraArgs, modulesFolderFlag+tmpDirToDelete)
	}
	err = yarn.CommonPackageHandler.UpdateDependency(vulnDetails, installationCommand, extraArgs...)
	if err != nil {
		return
	}

	if !isV2AndAbove {
		err = fileutils.RemoveTempDir(tmpDirToDelete)
	}
	return
}

// getYarnVersion gets the project's executed yarn version. This is required for fetching the correct command for updating packages
func getYarnVersion() (executableYarnVersion string, err error) {
	workingDirectory, err := coreutils.GetWorkingDirectory()
	if err != nil {
		err = errors.New("couldn't fetch current working directory: " + err.Error())
		return
	}
	yarnExecutablePath, err := biUtils.GetYarnExecutable()
	if err != nil {
		err = errors.New("couldn't fetch yarn executable: " + err.Error())
		return
	}
	executableYarnVersion, err = biUtils.GetVersion(yarnExecutablePath, workingDirectory)
	if err != nil {
		err = errors.New("couldn't get yarn executed version: " + err.Error())
	}
	return
}
