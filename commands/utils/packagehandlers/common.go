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
	UpdateDependency(details *utils.FixDetails) (bool, error)
	updateDirectDependency(fixDetails *utils.FixDetails, extraArgs ...string) (shouldFix bool, err error)
	updateIndirectDependency(fixDetails *utils.FixDetails, extraArgs ...string) (shouldFix bool, err error)
}

func GetCompatiblePackageHandler(fixVersionInfo *utils.FixDetails, details *utils.ScanDetails, mavenPropertyMap *map[string][]string) (PackageHandler, error) {
	switch fixVersionInfo.PackageType {
	case coreutils.Go:
		return &GoPackageHandler{}, nil
	case coreutils.Poetry:
		return &PythonPackageHandler{}, nil
	case coreutils.Pipenv:
		return &PythonPackageHandler{}, nil
	case coreutils.Npm:
		return &NpmPackageHandler{}, nil
	case coreutils.Yarn:
		return &YarnPackageHandler{}, nil
	case coreutils.Pip:
		return &PythonPackageHandler{pipRequirementsFile: details.PipRequirementsFile}, nil
	case coreutils.Maven:
		return &MavenPackageHandler{mavenDepToPropertyMap: *mavenPropertyMap}, nil
	default:
		return nil, fmt.Errorf("incompatiable package handler: %s", fixVersionInfo.PackageType)
	}
}

type common struct{}

// UpdateImpactedPackage updates the impacted package to the fixed version
func (g *common) UpdateDependency(fixDetails *utils.FixDetails, extraArgs ...string) (shouldFix bool, err error) {
	// Lower the package name to avoid duplicates
	impactedPackage := strings.ToLower(fixDetails.ImpactedDependency)
	commandArgs := []string{fixDetails.PackageType.GetPackageInstallOperator()}
	commandArgs = append(commandArgs, extraArgs...)
	operator := fixDetails.PackageType.GetPackageOperator()
	fixedPackage := impactedPackage + operator + fixDetails.FixVersion
	commandArgs = append(commandArgs, fixedPackage)
	err = runPackageMangerCommand(fixDetails.PackageType.GetExecCommandName(), commandArgs)
	return err == nil, err
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
