package packagehandlers

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/jfrog/frogbot/v2/utils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-client-go/utils/log"
)

type GoPackageUpdater struct{}

// TODO: Remove SetCommonParams from interface once all handlers no longer need it
func (gpu *GoPackageUpdater) SetCommonParams(serverDetails *config.ServerDetails, depsRepo string) {
}

func (gpu *GoPackageUpdater) UpdateDependency(vulnDetails *utils.VulnerabilityDetails) error {
	env := gpu.allowLockfileManipulation()

	if err := gpu.updateDependency(vulnDetails, env); err != nil {
		return err
	}

	return gpu.tidyLockfiles(env)
}

func (gpu *GoPackageUpdater) allowLockfileManipulation() []string {
	return append(os.Environ(), "GOFLAGS=-mod=mod")
}

func (gpu *GoPackageUpdater) updateDependency(vulnDetails *utils.VulnerabilityDetails, env []string) error {
	impactedPackage := strings.ToLower(vulnDetails.ImpactedDependencyName)
	fixedVersion := strings.TrimSpace(vulnDetails.SuggestedFixedVersion)

	fixedVersion = "v" + fixedVersion
	fixedPackage := strings.TrimSpace(impactedPackage) + "@" + fixedVersion

	cmd := exec.Command("go", "get", fixedPackage)
	cmd.Env = env
	log.Debug(fmt.Sprintf("Running 'go get %s'", fixedPackage))

	//#nosec G204 -- False positive - the subprocess only runs after the user's approval.
	output, err := cmd.CombinedOutput()
	if len(output) > 0 {
		log.Debug(fmt.Sprintf("go get output:\n%s", string(output)))
	}

	if err != nil {
		return fmt.Errorf("go get failed: %s\n%s", err.Error(), output)
	}
	return nil
}

func (gpu *GoPackageUpdater) tidyLockfiles(env []string) error {
	cmd := exec.Command("go", "mod", "tidy")
	cmd.Env = env
	log.Debug("Running 'go mod tidy'")

	//#nosec G204 -- False positive - the subprocess only runs after the user's approval.
	output, err := cmd.CombinedOutput()
	if len(output) > 0 {
		log.Debug(fmt.Sprintf("go mod tidy output:\n%s", string(output)))
	}

	if err != nil {
		return fmt.Errorf("go mod tidy failed: %s\n%s", err.Error(), output)
	}

	if gpu.hasVendorDirectory() {
		if err := gpu.updateVendor(env); err != nil {
			return err
		}
	}

	return nil
}

func (gpu *GoPackageUpdater) hasVendorDirectory() bool {
	vendorModulesPath := filepath.Join("vendor", "modules.txt")
	if _, err := os.Stat(vendorModulesPath); err == nil {
		log.Debug(fmt.Sprintf("Detected vendor directory at: %s", vendorModulesPath))
		return true
	}
	return false
}

func (gpu *GoPackageUpdater) updateVendor(env []string) error {
	vendorCmd := exec.Command("go", "mod", "vendor")
	vendorCmd.Env = env
	log.Debug("Running 'go mod vendor' to update vendored dependencies")

	//#nosec G204 -- False positive - the subprocess only runs after the user's approval.
	vendorOutput, err := vendorCmd.CombinedOutput()
	if len(vendorOutput) > 0 {
		log.Debug(fmt.Sprintf("go mod vendor output:\n%s", string(vendorOutput)))
	}

	if err != nil {
		return fmt.Errorf("go mod vendor failed: %s\n%s", err.Error(), vendorOutput)
	}

	log.Debug("Successfully updated vendor directory")
	return nil
}
