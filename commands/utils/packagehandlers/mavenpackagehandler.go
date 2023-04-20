package packagehandlers

import (
	"fmt"
	"github.com/jfrog/frogbot/commands/utils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"os/exec"
	"strings"
)

type MavenPackageHandler struct {
	mavenDepToPropertyMap map[string][]string
	GenericPackageHandler
}

func (mvn *MavenPackageHandler) UpdateImpactedPackage(impactedPackage string, fixVersionInfo *utils.FixVersionInfo, extraArgs ...string) error {
	// In Maven, fix only direct dependencies
	if !fixVersionInfo.DirectDependency {
		return nil
	}
	properties := mvn.mavenDepToPropertyMap[impactedPackage]
	// Update the package version. This command updates it only if the version is not a reference to a property.
	updateVersionArgs := []string{"-B", "versions:use-dep-version", "-Dincludes=" + impactedPackage, "-DdepVersion=" + fixVersionInfo.FixVersion, "-DgenerateBackupPoms=false"}
	updateVersionCmd := fmt.Sprintf("mvn %s", strings.Join(updateVersionArgs, " "))
	log.Debug(fmt.Sprintf("Running '%s'", updateVersionCmd))
	updateVersionOutput, err := exec.Command("mvn", updateVersionArgs...).CombinedOutput() // #nosec G204
	if err != nil {
		return fmt.Errorf("mvn command failed: %s\n%s", err.Error(), updateVersionOutput)
	}

	// Update properties that represent this package's version.
	for _, property := range properties {
		updatePropertyArgs := []string{"-B", "versions:set-property", "-Dproperty=" + property, "-DnewVersion=" + fixVersionInfo.FixVersion, "-DgenerateBackupPoms=false"}
		updatePropertyCmd := fmt.Sprintf("mvn %s", strings.Join(updatePropertyArgs, " "))
		log.Debug(fmt.Sprintf("Running '%s'", updatePropertyCmd))
		updatePropertyOutput, err := exec.Command("mvn", updatePropertyArgs...).CombinedOutput() // #nosec G204
		if err != nil {
			return fmt.Errorf("mvn command failed: %s\n%s", err.Error(), updatePropertyOutput)
		}
	}
	return nil
}
