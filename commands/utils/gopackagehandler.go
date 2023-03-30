package utils

import "strings"

type GoPackageHandler struct {
	GenericPackageHandler
}

func (golang *GoPackageHandler) UpdatePackage(impactedPackage string, fixVersionInfo *FixVersionInfo, extraArgs ...string) error {
	impactedPackage = strings.Trim(impactedPackage, "v")
	return golang.GenericPackageHandler.UpdatePackage(impactedPackage, fixVersionInfo)
}
