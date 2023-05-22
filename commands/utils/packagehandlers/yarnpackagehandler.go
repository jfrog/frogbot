package packagehandlers

import "github.com/jfrog/frogbot/commands/utils"

type YarnPackageHandler struct {
	CommonPackageHandler
}

func (yarn *YarnPackageHandler) UpdateDependency(fixDetails *utils.FixDetails) error {
	if fixDetails.DirectDependency {
		return yarn.updateDirectDependency(fixDetails)
	} else {
		return &utils.ErrUnsupportedFix{
			PackageName:  fixDetails.ImpactedDependency,
			FixedVersion: fixDetails.FixVersion,
			ErrorType:    utils.IndirectDependencyFixNotSupported,
		}
	}
}

func (yarn *YarnPackageHandler) updateDirectDependency(fixDetails *utils.FixDetails, extraArgs ...string) (err error) {
	return yarn.CommonPackageHandler.UpdateDependency(fixDetails, extraArgs...)
}
