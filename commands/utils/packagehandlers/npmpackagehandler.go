package packagehandlers

import (
	"fmt"
	"github.com/Jeffail/gabs/v2"
	"github.com/Masterminds/semver/v3"
	"github.com/jfrog/frogbot/commands/utils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"os"
	"unicode"
)

const (
	packageLockName              = "package-lock.json"
	supportedPackageLockVersion  = 3
	lockFileVersionAttributeName = "lockfileVersion"
	indirectDependencyPath       = "packages.node_modules/%s.dependencies.%s"
)

type NpmPackageHandler struct {
	CommonPackageHandler
}

func (npm *NpmPackageHandler) UpdateDependency(fixDetails *utils.FixDetails) error {
	if fixDetails.DirectDependency {
		return npm.updateDirectDependency(fixDetails)
	}
	return npm.updateIndirectDependency(fixDetails)
}

func (npm *NpmPackageHandler) updateDirectDependency(fixDetails *utils.FixDetails) (err error) {
	return npm.CommonPackageHandler.UpdateDependency(fixDetails)
}

// Attempts modifying indirect dependency in the package-lock file, and run npm install.
// The fix version should be compatible with the root package version constraints in order to fix the indirect package.
func (npm *NpmPackageHandler) updateIndirectDependency(fixDetails *utils.FixDetails) (err error) {
	parsedJson, err := loadPackageLockFile()
	if err != nil {
		log.Debug("Failed trying to load package-lock file:", err)
		return
	}
	if err = modifyIndirectDependency(fixDetails, parsedJson); err != nil {
		log.Debug("Failed while trying to modify package-lock file:", err.Error())
		return
	}
	if err = saveModifiedFile(parsedJson); err != nil {
		log.Debug("Failed trying to save package-lock file:", err)
		return
	}
	// Rewrites the package-lock file with updated hashes
	return runPackageMangerCommand(fixDetails.PackageType.GetExecCommandName(), []string{fixDetails.PackageType.GetPackageInstallOperator()})
}

func saveModifiedFile(parsedJson *gabs.Container) (err error) {
	bytes := parsedJson.Bytes()
	if err = os.WriteFile(packageLockName, bytes, 0644); err != nil {
		return
	}
	return
}

func modifyIndirectDependency(fixDetails *utils.FixDetails, parsedJson *gabs.Container) (err error) {
	pathToModule := fmt.Sprintf(indirectDependencyPath, fixDetails.DirectDependencyName, fixDetails.ImpactedDependency)
	// Get current value
	rawVersionWithConstraint := parsedJson.Path(pathToModule).Data()
	versionWithConstraintStr, ok := rawVersionWithConstraint.(string)
	if !ok {
		return fmt.Errorf("failed to extract version with constratin from package-lock.json")
	}
	// Check constraints
	validFix, caret, err := validateSemverConstraint(versionWithConstraintStr, fixDetails.FixVersion)
	if err != nil || !validFix {
		return fmt.Errorf("fix version is not compatiable with version constraint,cannot update:'%s' to:'%s'", versionWithConstraintStr, fixDetails.FixVersion)
	}
	// Update fix version
	fixVersionWithOriginalConstraint := caret + fixDetails.FixVersion
	if _, err = parsedJson.SetP(fixVersionWithOriginalConstraint, pathToModule); err != nil {
		return
	}
	return
}

func loadPackageLockFile() (*gabs.Container, error) {
	packageLockFile, err := os.ReadFile(packageLockName)
	if err != nil {
		return nil, err
	}
	container, err := gabs.ParseJSON(packageLockFile)
	if err != nil {
		return nil, err
	}
	packageLockVersionRaw := container.Path(lockFileVersionAttributeName).Data()
	packageLockVersion, ok := packageLockVersionRaw.(float64)
	if !ok {
		return nil, fmt.Errorf("failed to convert packagelock version")
	}
	if packageLockVersion < supportedPackageLockVersion {
		return nil, fmt.Errorf("unsupported version of package lock file %f", packageLockVersionRaw)
	}
	return container, nil
}

// Verifies if the fix version is compatible to the defined semantic version constraints.
// Returns whether the fix version is valid, along with the original constraint for reference.
// For example, versionWithConstraint= "^1.2.3" fixVersion= "1.2.4" will result in True,"".
func validateSemverConstraint(versionWithConstraint string, fixVersion string) (valid bool, originalConstraint string, err error) {
	constraint, err := semver.NewConstraint(versionWithConstraint)
	if err != nil {
		return
	}
	candidate, err := semver.NewVersion(fixVersion)
	if err != nil {
		return
	}
	return constraint.Check(candidate), extractOriginalConstraint(versionWithConstraint), nil
}

func extractOriginalConstraint(versionWithConstraint string) string {
	// No constraint exists
	if versionWithConstraint == "" || len(versionWithConstraint) == 0 || unicode.IsNumber(rune(versionWithConstraint[0])) {
		return ""
	}
	// Check constraint char length, i.e "<" or "<="
	constraintLength := 1
	if !unicode.IsNumber(rune(versionWithConstraint[1])) {
		constraintLength += 1
	}
	return versionWithConstraint[:constraintLength]
}
