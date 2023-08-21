package packagehandlers

import (
	"github.com/jfrog/frogbot/utils"
	"strings"
)

const dotnetPackageUpgradeExtraArg = "package"

type NugetPackageHandler struct {
	CommonPackageHandler
}

func (dotnet *NugetPackageHandler) UpdateDependency(vulnDetails *utils.VulnerabilityDetails) error {
	if vulnDetails.IsDirectDependency {
		return dotnet.updateDirectDependency(vulnDetails)
	} else {
		return &utils.ErrUnsupportedFix{
			PackageName:  vulnDetails.ImpactedDependencyName,
			FixedVersion: vulnDetails.SuggestedFixedVersion,
			ErrorType:    utils.IndirectDependencyFixNotSupported,
		}
	}
}

func (dotnet *NugetPackageHandler) updateDirectDependency(vulnDetails *utils.VulnerabilityDetails) (err error) {
	impactedPackage := strings.ToLower(vulnDetails.ImpactedDependencyName)
	var commandArgs []string
	installationCommand := vulnDetails.Technology.GetPackageInstallationCommand()
	operator := vulnDetails.Technology.GetPackageOperator()
	commandArgs = append(commandArgs, installationCommand, dotnetPackageUpgradeExtraArg, impactedPackage, operator, vulnDetails.SuggestedFixedVersion)
	return runPackageMangerCommand(vulnDetails.Technology.GetExecCommandName(), commandArgs)
}
