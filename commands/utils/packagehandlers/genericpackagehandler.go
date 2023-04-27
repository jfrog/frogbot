package packagehandlers

import (
	"fmt"
	"github.com/jfrog/frogbot/commands/utils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"golang.org/x/exp/slices"
	"os/exec"
	"strings"
)

// PackageHandler interface to hold operations on packages
type PackageHandler interface {
	UpdateImpactedPackage(impactedPackage string, fixVersionInfo *utils.FixVersionInfo, extraArgs ...string) error
}

var techEnvironmentPackagesMap = map[coreutils.Technology][]string{
	coreutils.Go:  {"github.com/golang/go"},
	coreutils.Pip: {"pip", "setuptools", "wheel"},
}

func GetCompatiblePackageHandler(fixVersionInfo *utils.FixVersionInfo, pipRequirementsFile string, mavenPropertyMap *map[string][]string) PackageHandler {
	switch fixVersionInfo.PackageType {
	case coreutils.Maven:
		return &MavenPackageHandler{mavenDepToPropertyMap: *mavenPropertyMap}
	case coreutils.Poetry:
		return &PythonPackageHandler{}
	case coreutils.Pip:
		return &PythonPackageHandler{pipRequirementsFile: pipRequirementsFile}
	default:
		return &GenericPackageHandler{FixVersionInfo: fixVersionInfo}
	}
}

type GenericPackageHandler struct {
	FixVersionInfo *utils.FixVersionInfo
}

// UpdateImpactedPackage updates the impacted package to the fixed version
func (g *GenericPackageHandler) UpdateImpactedPackage(impactedPackage string, fixVersionInfo *utils.FixVersionInfo, extraArgs ...string) error {
	// Indirect package fix should we implemented for each package handler
	if !fixVersionInfo.DirectDependency {
		return &utils.ErrUnsupportedIndirectFix{PackageName: impactedPackage}
	}
	if isEnvironmentPackage(impactedPackage, fixVersionInfo.FixVersion, fixVersionInfo.PackageType) {
		return nil
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

func isEnvironmentPackage(impactedPackage, fixVersion string, tech coreutils.Technology) bool {
	if slices.Contains(techEnvironmentPackagesMap[tech], impactedPackage) {
		log.Info("Skipping vulnerable package", impactedPackage, "since it is not defined in your package descriptor. Update", impactedPackage, "version to", fixVersion, "to fix this vulnerability.")
		return true
	}
	return false
}

func runPackageMangerCommand(commandName string, commandArgs []string) error {
	fullCommand := commandName + " " + strings.Join(commandArgs, " ")
	log.Debug(fmt.Sprintf("Running '%s'", fullCommand))
	output, err := exec.Command(commandName, commandArgs...).CombinedOutput() // #nosec G204
	if err != nil {
		return fmt.Errorf("%s command failed: %s\n%s", fullCommand, err.Error(), output)
	}
	return nil
}
