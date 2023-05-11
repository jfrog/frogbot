package packagehandlers

import "github.com/jfrog/frogbot/commands/utils"

type NpmPackageHandler struct {
	common
}

func (n *NpmPackageHandler) UpdateDependency(fixDetails *utils.FixDetails) (bool, error) {
	if fixDetails.DirectDependency {
		return n.updateDirectDependency(fixDetails)
	} else {
		return n.updateIndirectDependency(fixDetails)
	}
}

func (n *NpmPackageHandler) updateDirectDependency(fixDetails *utils.FixDetails, extraArgs ...string) (fixSupported bool, err error) {
	return n.common.UpdateDependency(fixDetails, extraArgs...)
}

func (n *NpmPackageHandler) updateIndirectDependency(fixDetails *utils.FixDetails, extraArgs ...string) (fixSupported bool, err error) {
	return false, nil
}
