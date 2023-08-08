package packagehandlers

import (
	biUtils "github.com/jfrog/build-info-go/build/utils"
	"github.com/jfrog/frogbot/commands/utils"
	"github.com/jfrog/gofrog/version"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
)

const (
	yarnV2Version          = "2.0.0"
	yarnV1PackageUpdateCmd = "upgrade"
	yarnV2PackageUpdateCmd = "up"
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

func (yarn *YarnPackageHandler) updateDirectDependency(vulnDetails *utils.VulnerabilityDetails, extraArgs ...string) (err error) {
	clonedDirPath, err := coreutils.GetWorkingDirectory()
	if err != nil {
		return
	}
	yarnExecutablePath, err := biUtils.GetYarnExecutable()
	if errorutils.CheckError(err) != nil {
		return
	}
	executableYarnVersion, err := biUtils.GetVersion(yarnExecutablePath, clonedDirPath)
	if version.NewVersion(executableYarnVersion).Compare(yarnV2Version) <= 0 {
		// Yarn 2 & 3
		vulnDetails.Technology.SetPackageInstallationCommand(yarnV2PackageUpdateCmd)
	} else {
		// Yarn 1
		vulnDetails.Technology.SetPackageInstallationCommand(yarnV1PackageUpdateCmd)
	}
	return yarn.CommonPackageHandler.UpdateDependency(vulnDetails, extraArgs...)
}
