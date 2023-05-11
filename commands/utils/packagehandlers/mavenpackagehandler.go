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
}

func (mvn *MavenPackageHandler) UpdateDependency(fixDetails *utils.FixDetails) (bool, error) {
	if fixDetails.DirectDependency {
		return mvn.updateDirectDependency(fixDetails)
	} else {
		return mvn.updateIndirectDependency(fixDetails)
	}
}

func (mvn *MavenPackageHandler) updateIndirectDependency(fixDetails *utils.FixDetails, extraArgs ...string) (fixSupported bool, err error) {
	// In Maven, fix only direct dependencies
	log.Debug("Since dependency", fixDetails.ImpactedDependency, "is indirect (transitive) its fix is skipped")
	return false, nil
}

func (mvn *MavenPackageHandler) updateDirectDependency(fixDetails *utils.FixDetails, extraArgs ...string) (fixSupported bool, err error) {
	properties := mvn.mavenDepToPropertyMap[fixDetails.ImpactedDependency]
	// Update the package version. This command updates it only if the version is not a reference to a property.
	updateVersionArgs := []string{"-B", "versions:use-dep-version", "-Dincludes=" + fixDetails.ImpactedDependency, "-DdepVersion=" + fixDetails.FixVersion, "-DgenerateBackupPoms=false"}
	updateVersionCmd := fmt.Sprintf("mvn %s", strings.Join(updateVersionArgs, " "))
	log.Debug(fmt.Sprintf("Running '%s'", updateVersionCmd))
	updateVersionOutput, err := exec.Command("mvn", updateVersionArgs...).CombinedOutput() // #nosec G204
	if err != nil {
		return false, fmt.Errorf("mvn command failed: %s\n%s", err.Error(), updateVersionOutput)
	}

	// Update properties that represent this package's version.
	for _, property := range properties {
		updatePropertyArgs := []string{"-B", "versions:set-property", "-Dproperty=" + property, "-DnewVersion=" + fixDetails.FixVersion, "-DgenerateBackupPoms=false"}
		updatePropertyCmd := fmt.Sprintf("mvn %s", strings.Join(updatePropertyArgs, " "))
		log.Debug(fmt.Sprintf("Running '%s'", updatePropertyCmd))
		updatePropertyOutput, err := exec.Command("mvn", updatePropertyArgs...).CombinedOutput() // #nosec G204
		if err != nil {
			return false, fmt.Errorf("mvn command failed: %s\n%s", err.Error(), updatePropertyOutput)
		}
	}
	return true, nil
}
