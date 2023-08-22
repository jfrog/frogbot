package packagehandlers

import "github.com/jfrog/frogbot/utils"

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
	return npm.CommonPackageHandler.UpdateDependency(vulnDetails, vulnDetails.Technology.GetPackageInstallationCommand())
}
