package packagehandlers

import (
	"strings"
)

type GoPackageHandler struct {
	GenericPackageHandler
}

func (golang *GoPackageHandler) UpdateImpactedPackage(impactedPackage string, fixVersionInfo *FixVersionInfo, extraArgs ...string) error {
	impactedPackage = strings.Trim(impactedPackage, "v")
	return golang.GenericPackageHandler.UpdateImpactedPackage(impactedPackage, fixVersionInfo, extraArgs...)
}
