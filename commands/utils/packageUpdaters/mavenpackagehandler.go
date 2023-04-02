package packageUpdaters

import (
	"fmt"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"os/exec"
	"strings"
)

type MavenPackageHandler struct {
	MavenDepToPropertyMap map[string][]string
	GenericPackageHandler
}

func (mvn *MavenPackageHandler) UpdatePackage(impactedPackage string, fixVersionInfo *FixVersionInfo, extraArgs ...string) error {
	// In Maven, fix only direct dependencies
	if !fixVersionInfo.IsDirectDependency {
		return nil
	}
	properties := mvn.MavenDepToPropertyMap[impactedPackage]
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
