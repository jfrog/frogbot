package packagehandlers

import "github.com/jfrog/frogbot/commands/utils"

type NpmPackageHandler struct {
	common
}

func (n *NpmPackageHandler) UpdateDependency(details *utils.FixDetails) (bool, error) {
	if details.DirectDependency {
		return n.updateDirectDependency(details)
	} else {
		return n.updateIndirectDependency(details)
	}
}

func (n *NpmPackageHandler) updateDirectDependency(fixDetails *utils.FixDetails, extraArgs ...string) (shouldFix bool, err error) {
	return n.common.UpdateDependency(fixDetails, extraArgs...)
}

func (n *NpmPackageHandler) updateIndirectDependency(fixDetails *utils.FixDetails, extraArgs ...string) (shouldFix bool, err error) {
	return false, nil
}
