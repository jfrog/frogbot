package packagehandlers

import "github.com/jfrog/frogbot/commands/utils"

type YarnPackageHandler struct {
	common
}

func (n *YarnPackageHandler) UpdateDependency(details *utils.FixDetails) (bool, error) {
	if details.DirectDependency {
		return n.updateDirectDependency(details)
	} else {
		return n.updateIndirectDependency(details)
	}
}

func (n *YarnPackageHandler) updateDirectDependency(fixDetails *utils.FixDetails, extraArgs ...string) (shouldFix bool, err error) {
	return n.common.UpdateDependency(fixDetails, extraArgs...)
}

func (n *YarnPackageHandler) updateIndirectDependency(fixDetails *utils.FixDetails, extraArgs ...string) (shouldFix bool, err error) {
	return false, nil
}
