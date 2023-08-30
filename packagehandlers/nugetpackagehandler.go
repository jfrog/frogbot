package packagehandlers

import (
	"fmt"
	"github.com/jfrog/frogbot/utils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"strings"
)

const dotnetPackageUpgradeExtraArg = "package"

type NugetPackageHandler struct {
	CommonPackageHandler
}

func (nph *NugetPackageHandler) UpdateDependency(vulnDetails *utils.VulnerabilityDetails) error {
	if vulnDetails.IsDirectDependency {
		return nph.updateDirectDependency(vulnDetails)
	}

	return &utils.ErrUnsupportedFix{
		PackageName:  vulnDetails.ImpactedDependencyName,
		FixedVersion: vulnDetails.SuggestedFixedVersion,
		ErrorType:    utils.IndirectDependencyFixNotSupported,
	}
}

func (nph *NugetPackageHandler) updateDirectDependency(vulnDetails *utils.VulnerabilityDetails) (err error) {
	impactedPackage := strings.ToLower(vulnDetails.ImpactedDependencyName)
	var commandArgs []string
	installationCommand := vulnDetails.Technology.GetPackageInstallationCommand()
	operator := vulnDetails.Technology.GetPackageOperator()
	commandArgs = append(commandArgs, installationCommand, dotnetPackageUpgradeExtraArg, impactedPackage, operator, vulnDetails.SuggestedFixedVersion)
	err = runPackageMangerCommand(vulnDetails.Technology.GetExecCommandName(), commandArgs)
	if err != nil {
		log.Debug("Fixing vulnerabilities for .NET projects is performed using .NET CLI. Make sure to have .NET CLI v3.1+ installed")
		err = fmt.Errorf("failed to update nuget package with error:\n%w", err)
	}
	return
}
