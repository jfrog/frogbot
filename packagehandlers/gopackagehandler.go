package packagehandlers

import (
	"github.com/jfrog/frogbot/v2/utils"
	golangutils "github.com/jfrog/jfrog-cli-artifactory/artifactory/commands/golang"
)

type GoPackageHandler struct {
	CommonPackageHandler
}

func (golang *GoPackageHandler) UpdateDependency(vulnDetails *utils.VulnerabilityDetails) error {
	// Configure resolution from an Artifactory server if needed
	if golang.depsRepo != "" {
		if err := golangutils.SetArtifactoryAsResolutionServer(golang.serverDetails, golang.depsRepo, golangutils.GoProxyUrlParams{}); err != nil {
			return err
		}
	}
	// In Golang, we can address every dependency as a direct dependency.
	return golang.CommonPackageHandler.UpdateDependency(vulnDetails, vulnDetails.Technology.GetPackageInstallationCommand())
}
