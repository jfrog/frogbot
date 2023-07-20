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
	UpdateDependency(details *utils.VulnerabilityDetails) error
}

func GetCompatiblePackageHandler(vulnDetails *utils.VulnerabilityDetails, details *utils.ScanDetails) (handler PackageHandler) {
	switch vulnDetails.Technology {
	case coreutils.Go:
		handler = &GoPackageHandler{}
	case coreutils.Poetry:
		handler = &PythonPackageHandler{}
	case coreutils.Pipenv:
		handler = &PythonPackageHandler{}
	case coreutils.Npm:
		handler = &NpmPackageHandler{}
	case coreutils.Yarn:
		handler = &YarnPackageHandler{}
	case coreutils.Pip:
		handler = &PythonPackageHandler{pipRequirementsFile: details.PipRequirementsFile}
	case coreutils.Maven:
		handler = &MavenPackageHandler{depsRepo: details.Repository, ServerDetails: details.ServerDetails}
	default:
		handler = &UnsupportedPackageHandler{}
	}
	return
}

type CommonPackageHandler struct{}

// UpdateDependency updates the impacted package to the fixed version
func (cph *CommonPackageHandler) UpdateDependency(vulnDetails *utils.VulnerabilityDetails, extraArgs ...string) (err error) {
	// Lower the package name to avoid duplicates
	impactedPackage := strings.ToLower(vulnDetails.ImpactedDependencyName)
	commandArgs := []string{vulnDetails.Technology.GetPackageInstallOperator()}
	commandArgs = append(commandArgs, extraArgs...)
	operator := vulnDetails.Technology.GetPackageOperator()
	fixedPackage := impactedPackage + operator + vulnDetails.SuggestedFixedVersion
	commandArgs = append(commandArgs, fixedPackage)
	return runPackageMangerCommand(vulnDetails.Technology.GetExecCommandName(), commandArgs)
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
