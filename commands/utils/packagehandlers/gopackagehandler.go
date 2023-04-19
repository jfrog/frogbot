package packagehandlers

import (
	"github.com/jfrog/frogbot/commands/utils"
	"strings"
)

type GoPackageHandler struct {
	GenericPackageHandler
}

func (golang *GoPackageHandler) UpdateImpactedPackage(impactedPackage string, fixVersionInfo *utils.FixVersionInfo, extraArgs ...string) error {
	impactedPackage = strings.Trim(impactedPackage, "v")
	return golang.GenericPackageHandler.UpdateImpactedPackage(impactedPackage, fixVersionInfo, extraArgs...)
}
