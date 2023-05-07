package packagehandlers

import (
	_ "embed"
	"fmt"
	"github.com/jfrog/frogbot/commands/utils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"os"
	"os/exec"
	"strings"
)

const mavenGavReader = "maven-gav-reader.jar"

var (
	//go:embed resources/maven-gav-reader.jar
	mavenGavReaderContent []byte
)

type MavenPackageHandler struct {
	mavenDepToPropertyMap     map[string][]string
	IsMavenGavReaderInstalled bool
	GenericPackageHandler
}

func (mph *MavenPackageHandler) UpdateImpactedPackage(impactedPackage string, fixVersionInfo *utils.FixVersionInfo, extraArgs ...string) error {
	if err := mph.installMavenGavReader(); err != nil {
		return err
	}
	// In Maven, fix only direct dependencies
	if !fixVersionInfo.DirectDependency {
		return nil
	}
	properties := mph.mavenDepToPropertyMap[impactedPackage]
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

func (mph *MavenPackageHandler) installMavenGavReader() (err error) {
	if mph.IsMavenGavReaderInstalled {
		return nil
	}
	// Create maven-gav-reader plugin file and write the maven-gav-reader.jar content to it
	mavenGavReaderFile, err := os.CreateTemp("", fmt.Sprintf("*-%s", mavenGavReader))
	if err != nil {
		return fmt.Errorf("failed to create a temp %s file: \n%s", mavenGavReader, err.Error())
	}
	defer func() {
		e := os.Remove(mavenGavReaderFile.Name())
		if err == nil {
			err = e
		}
	}()
	if _, err = mavenGavReaderFile.Write(mavenGavReaderContent); err != nil {
		return fmt.Errorf("failed to write content to the %s file: \n%s", mavenGavReader, err.Error())
	}
	// Install the plugin
	var output []byte
	installProperties := []string{"org.apache.maven.plugins:maven-install-plugin:2.5.2:install-file", "-Dfile=" + mavenGavReaderFile.Name()}
	if output, err = exec.Command("mvn", installProperties...).CombinedOutput(); err != nil {
		return fmt.Errorf("failed to install the maven-gav-reader plugin. Maven output: %s\n\n Error received:%s", string(output), err.Error())
	}
	mph.IsMavenGavReaderInstalled = true
	return
}
