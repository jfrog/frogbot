package packagehandlers

import (
	"github.com/jfrog/frogbot/commands/utils"
)

type GoPackageHandler struct {
	common
}

func (golang *GoPackageHandler) UpdateDependency(details *utils.FixDetails) (bool, error) {
	if details.DirectDependency {
		return golang.updateDirectDependency(details)
	} else {
		return golang.updateIndirectDependency(details)
	}
}

func (golang *GoPackageHandler) updateIndirectDependency(fixDetails *utils.FixDetails, extraArgs ...string) (shouldFix bool, err error) {
	return golang.common.UpdateDependency(fixDetails, extraArgs...)
}

func (golang *GoPackageHandler) updateDirectDependency(fixDetails *utils.FixDetails, extraArgs ...string) (shouldFix bool, err error) {
	// In Golang, we can address every package as direct because of the way that 'go get' works
	return golang.common.UpdateDependency(fixDetails, extraArgs...)
}
