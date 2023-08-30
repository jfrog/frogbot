package packagehandlers

import (
	"github.com/jfrog/frogbot/utils"
)

const dotnetPackageUpgradeExtraArg = "package"

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
	return nph.CommonPackageHandler.UpdateDependency(vulnDetails, vulnDetails.Technology.GetPackageInstallationCommand(), dotnetPackageUpgradeExtraArg)
}
