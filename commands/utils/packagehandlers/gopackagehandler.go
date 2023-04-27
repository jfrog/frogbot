package packagehandlers

import (
	"github.com/jfrog/frogbot/commands/utils"
)

type GoPackageHandler struct {
	GenericPackageHandler
}

func (golang *GoPackageHandler) UpdateImpactedPackage(impactedPackage string, fixVersionInfo *utils.FixVersionInfo, extraArgs ...string) (shouldFix bool, err error) {
	// In Golang, we can address every package as direct because of the way that 'go get' works
	fixVersionInfo.DirectDependency = true
	return golang.GenericPackageHandler.UpdateImpactedPackage(impactedPackage, fixVersionInfo, extraArgs...)
}
