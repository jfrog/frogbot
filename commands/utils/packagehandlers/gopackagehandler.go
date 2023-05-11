package packagehandlers

import (
	"github.com/jfrog/frogbot/commands/utils"
)

type GoPackageHandler struct {
	common
}

func (golang *GoPackageHandler) UpdateDependency(fixDetails *utils.FixDetails) (bool, error) {
	if fixDetails.DirectDependency {
		return golang.updateDirectDependency(fixDetails)
	} else {
		return golang.updateIndirectDependency(fixDetails)
	}
}

func (golang *GoPackageHandler) updateIndirectDependency(fixDetails *utils.FixDetails, extraArgs ...string) (fixSupported bool, err error) {
	return golang.common.UpdateDependency(fixDetails, extraArgs...)
}

func (golang *GoPackageHandler) updateDirectDependency(fixDetails *utils.FixDetails, extraArgs ...string) (fixSupported bool, err error) {
	// In Golang, we can address every dependency as a direct dependency.
	return golang.common.UpdateDependency(fixDetails, extraArgs...)
}
