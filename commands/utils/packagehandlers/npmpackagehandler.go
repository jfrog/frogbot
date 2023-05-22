package packagehandlers

import "github.com/jfrog/frogbot/commands/utils"

type NpmPackageHandler struct {
	CommonPackageHandler
}

func (npm *NpmPackageHandler) UpdateDependency(fixDetails *utils.FixDetails) error {
	if fixDetails.DirectDependency {
		return npm.updateDirectDependency(fixDetails)
	} else {
		return &utils.ErrUnsupportedFix{
			PackageName:  fixDetails.ImpactedDependency,
			FixedVersion: fixDetails.FixVersion,
			ErrorType:    utils.IndirectDependencyFixNotSupported,
		}
	}
}

func (npm *NpmPackageHandler) updateDirectDependency(fixDetails *utils.FixDetails, extraArgs ...string) (err error) {
	return npm.CommonPackageHandler.UpdateDependency(fixDetails, extraArgs...)
}
