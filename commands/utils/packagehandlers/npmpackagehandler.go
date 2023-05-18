package packagehandlers

import "github.com/jfrog/frogbot/commands/utils"

type NpmPackageHandler struct {
	CommonPackageHandler
}

func (npm *NpmPackageHandler) UpdateDependency(fixDetails *utils.FixDetails) (bool, error) {
	if fixDetails.DirectDependency {
		return npm.updateDirectDependency(fixDetails)
	} else {
		return npm.updateIndirectDependency(fixDetails)
	}
}

func (npm *NpmPackageHandler) updateDirectDependency(fixDetails *utils.FixDetails, extraArgs ...string) (fixSupported bool, err error) {
	return npm.CommonPackageHandler.UpdateDependency(fixDetails, extraArgs...)
}

func (npm *NpmPackageHandler) updateIndirectDependency(fixDetails *utils.FixDetails, extraArgs ...string) (fixSupported bool, err error) {
	return false, nil
}
