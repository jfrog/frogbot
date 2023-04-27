package packagehandlers

import (
	"fmt"
	"github.com/jfrog/frogbot/commands/utils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"os/exec"
	"strings"
)

// PackageHandler interface to hold operations on packages
type PackageHandler interface {
	UpdateImpactedPackage(impactedPackage string, fixVersionInfo *utils.FixVersionInfo, extraArgs ...string) (shouldFix bool, err error)
}

func GetCompatiblePackageHandler(fixVersionInfo *utils.FixVersionInfo, pipfilePath *utils.ScanDetails, mavenPropertyMap *map[string][]string) PackageHandler {
	switch fixVersionInfo.PackageType {
	case coreutils.Go:
		return &GoPackageHandler{}
	case coreutils.Maven:
		return &MavenPackageHandler{mavenDepToPropertyMap: *mavenPropertyMap}
	case coreutils.Poetry:
		return &PythonPackageHandler{}
	case coreutils.Pip:
		return &PythonPackageHandler{pipRequirementsFile: pipfilePath.PipRequirementsFile}
	default:
		return &GenericPackageHandler{FixVersionInfo: fixVersionInfo}
	}
}

type GenericPackageHandler struct {
	FixVersionInfo *utils.FixVersionInfo
}

// UpdateImpactedPackage updates the impacted package to the fixed version
func (g *GenericPackageHandler) UpdateImpactedPackage(impactedPackage string, fixVersionInfo *utils.FixVersionInfo, extraArgs ...string) (shouldFix bool, err error) {
	// Indirect package fix should we implemented for each package handler
	if !fixVersionInfo.DirectDependency {
		log.Info("Since dependency", impactedPackage, " is indirect (transitive) its fix is skipped")
		return false, nil
	}
	// Lower the package name to avoid duplicates
	impactedPackage = strings.ToLower(impactedPackage)
	commandArgs := []string{fixVersionInfo.PackageType.GetPackageInstallOperator()}
	commandArgs = append(commandArgs, extraArgs...)
	operator := fixVersionInfo.PackageType.GetPackageOperator()
	fixedPackage := impactedPackage + operator + fixVersionInfo.FixVersion
	commandArgs = append(commandArgs, fixedPackage)
	return runPackageMangerCommand(fixVersionInfo.PackageType.GetExecCommandName(), commandArgs)
}

func runPackageMangerCommand(commandName string, commandArgs []string) (bool, error) {
	fullCommand := commandName + " " + strings.Join(commandArgs, " ")
	log.Debug(fmt.Sprintf("Running '%s'", fullCommand))
	output, err := exec.Command(commandName, commandArgs...).CombinedOutput() // #nosec G204
	if err != nil {
		return false, fmt.Errorf("%s command failed: %s\n%s", fullCommand, err.Error(), output)
	}
	return true, nil
}
