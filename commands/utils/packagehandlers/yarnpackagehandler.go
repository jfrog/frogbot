package packagehandlers

import "github.com/jfrog/frogbot/commands/utils"

type YarnPackageHandler struct {
	CommonPackageHandler
}

func (yarn *YarnPackageHandler) UpdateDependency(fixDetails *utils.FixDetails) (bool, error) {
	if fixDetails.DirectDependency {
		return yarn.updateDirectDependency(fixDetails)
	} else {
		return yarn.updateIndirectDependency(fixDetails)
	}
}

func (yarn *YarnPackageHandler) updateDirectDependency(fixDetails *utils.FixDetails, extraArgs ...string) (fixSupported bool, err error) {
	return yarn.CommonPackageHandler.UpdateDependency(fixDetails, extraArgs...)
}

func (yarn *YarnPackageHandler) updateIndirectDependency(fixDetails *utils.FixDetails, extraArgs ...string) (fixSupported bool, err error) {
	return false, nil
}
