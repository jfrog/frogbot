package packagehandlers

import (
	"github.com/jfrog/frogbot/commands/utils"
	"github.com/jfrog/jfrog-client-go/utils/log"
)

const (
	GoPackage = "github.com/golang/go"
)

type GoPackageHandler struct {
	GenericPackageHandler
}

func (golang *GoPackageHandler) UpdateImpactedPackage(impactedPackage string, fixVersionInfo *utils.FixVersionInfo, extraArgs ...string) error {
	if impactedPackage == GoPackage {
		log.Info("Skipping vulnerable package", impactedPackage, "since it is not defined in your go.mod file. Update Go version to", fixVersionInfo.FixVersion, "to fix this vulnerability.")
		return nil
	}
	return golang.GenericPackageHandler.UpdateImpactedPackage(impactedPackage, fixVersionInfo, extraArgs...)
}
