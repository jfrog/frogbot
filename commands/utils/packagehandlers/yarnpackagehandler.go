package packagehandlers

import "github.com/jfrog/frogbot/commands/utils"

type YarnPackageHandler struct {
	common
}

func (n *YarnPackageHandler) UpdateDependency(fixDetails *utils.FixDetails) (bool, error) {
	if fixDetails.DirectDependency {
		return n.updateDirectDependency(fixDetails)
	} else {
		return n.updateIndirectDependency(fixDetails)
	}
}

func (n *YarnPackageHandler) updateDirectDependency(fixDetails *utils.FixDetails, extraArgs ...string) (supportedFix bool, err error) {
	return n.common.UpdateDependency(fixDetails, extraArgs...)
}

func (n *YarnPackageHandler) updateIndirectDependency(fixDetails *utils.FixDetails, extraArgs ...string) (supportedFix bool, err error) {
	return false, nil
}
