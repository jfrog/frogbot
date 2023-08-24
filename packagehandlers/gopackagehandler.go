package packagehandlers

import (
	"github.com/jfrog/frogbot/utils"
)

type GoPackageHandler struct {
	CommonPackageHandler
}

func (golang *GoPackageHandler) UpdateDependency(vulnDetails *utils.VulnerabilityDetails) error {
	// In Golang, we can address every dependency as a direct dependency.
	return golang.CommonPackageHandler.UpdateDependency(vulnDetails, vulnDetails.Technology.GetPackageInstallationCommand())
}
