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
	var tmpDirToDelete string
	var installationCommand string
	var extraArgs []string

	isYarn1, err := isYarnV1()
	if err != nil {
		return
	}

	if isYarn1 {
		installationCommand = yarnV1PackageUpdateCmd
		tmpDirToDelete, err = fileutils.CreateTempDir()
		defer func() {
			err = fileutils.RemoveTempDir(tmpDirToDelete)
		}()

		if err != nil {
			return
		}
		extraArgs = append(extraArgs, modulesFolderFlag+tmpDirToDelete)
	} else {
		installationCommand = yarnV2PackageUpdateCmd
	}
	err = yarn.CommonPackageHandler.UpdateDependency(vulnDetails, installationCommand, extraArgs...)
	if err != nil {
		return
	}
	return
}

// isYarnV1 gets the current executed yarn version and returns whether the current yarn version is V1 or not
func isYarnV1() (isYarn1 bool, err error) {
	workingDirectory, err := coreutils.GetWorkingDirectory()
	if err != nil {
		err = errors.New("couldn't get current working directory: " + err.Error())
		return
	}
	yarnExecutablePath, err := biUtils.GetYarnExecutable()
	if err != nil {
		err = errors.New("couldn't find yarn executable: " + err.Error())
		return
	}
	executableYarnVersion, err := biUtils.GetVersion(yarnExecutablePath, workingDirectory)
	if err != nil {
		return
	}
	isYarn1 = version.NewVersion(executableYarnVersion).Compare(yarnV2Version) > 0
	return
}
