package packagehandlers

import (
	"fmt"
	"github.com/jfrog/frogbot/commands/utils"
	"github.com/jfrog/gofrog/version"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"os/exec"
	"strings"
)

// FixVersionInfo is a basic struct used to hold needed information about version fixing
type FixVersionInfo struct {
	FixVersion       string
	PackageType      coreutils.Technology
	DirectDependency bool
}

func NewFixVersionInfo(newFixVersion string, packageType coreutils.Technology, directDependency bool) *FixVersionInfo {
	return &FixVersionInfo{newFixVersion, packageType, directDependency}
}

func (fvi *FixVersionInfo) UpdateFixVersion(newFixVersion string) {
	// Update fvi.FixVersion as the maximum version if found a new version that is greater than the previous maximum version.
	if fvi.FixVersion == "" || version.NewVersion(fvi.FixVersion).Compare(newFixVersion) > 0 {
		fvi.FixVersion = newFixVersion
	}
}

// PackageHandler interface to hold operations on packages
type PackageHandler interface {
	UpdateImpactedPackage(impactedPackage string, fixVersionInfo *FixVersionInfo, extraArgs ...string) error
}

func GetCompatiblePackageHandler(fixVersionInfo *FixVersionInfo, pipfilePath *utils.ScanDetails, mavenPropertyMap *map[string][]string) PackageHandler {
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
	FixVersionInfo *FixVersionInfo
}

// UpdateImpactedPackage updates the impacted package to the fixed version
func (g *GenericPackageHandler) UpdateImpactedPackage(impactedPackage string, fixVersionInfo *FixVersionInfo, extraArgs ...string) error {
	// Lower the package name to avoid duplicates
	impactedPackage = strings.ToLower(impactedPackage)
	commandArgs := []string{fixVersionInfo.PackageType.GetPackageInstallOperator()}
	commandArgs = append(commandArgs, extraArgs...)
	operator := fixVersionInfo.PackageType.GetPackageOperator()
	fixedPackage := impactedPackage + operator + fixVersionInfo.FixVersion
	commandArgs = append(commandArgs, fixedPackage)
	return runPackageMangerCommand(fixVersionInfo.PackageType.GetExecCommandName(), commandArgs)
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
