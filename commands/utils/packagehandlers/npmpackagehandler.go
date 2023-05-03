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
	common
}

func (n *NpmPackageHandler) UpdateDependency(fixDetails *utils.FixDetails) (bool, error) {
	if fixDetails.DirectDependency {
		return n.updateDirectDependency(fixDetails)
	} else {
		return n.updateIndirectDependency(fixDetails)
	}
}

func (n *NpmPackageHandler) updateDirectDependency(fixDetails *utils.FixDetails, extraArgs ...string) (supportedFix bool, err error) {
	return n.common.UpdateDependency(fixDetails, extraArgs...)
}

// updateIndirectDependency attempts changing the indirect dependency version
// The fix version should be compatible with the root package in order to fix the indirect package.
// If fails, log the error and return nil to avoid crashing the whole operation.
// See https://github.com/npm/node-semver#caret-ranges-123-025-004 for more info
func (n *NpmPackageHandler) updateIndirectDependency(fixDetails *utils.FixDetails, extraArgs ...string) (supportedFix bool, err error) {
	parsedJson, err := loadPackageLockFile()
	if err != nil {
		log.Debug("Failed trying to load package-lock file: ", err)
		return
	}
	shouldFix, err := modifyIndirectDependency(fixDetails, parsedJson)
	if err != nil {
		log.Debug("Failed trying to modify package-lock file: ", err)
		return
	}
	if !shouldFix {
		log.Debug("Cannot update as fixed version does not match constraint")
		return false, nil
	}
	if err = saveModifiedFile(parsedJson); err != nil {
		log.Debug("Failed trying to save package-lock file: ", err)
		return
	}
	// Rewrites the package-lock file with updated hashes
	return true, runPackageMangerCommand(fixDetails.PackageType.GetExecCommandName(), []string{"install"})
}

func saveModifiedFile(parsedJson *gabs.Container) error {
	bytes := parsedJson.Bytes()
	err := os.WriteFile(packageLockName, bytes, 0644)
	if err != nil {
		return err
	}
	return nil
}

func modifyIndirectDependency(fixDetails *utils.FixDetails, parsedJson *gabs.Container) (shouldFix bool, err error) {
	// Get value
	directDependencyName := fixDetails.DirectDependencyName
	pathToModule := fmt.Sprintf(indirectDependencyPath, directDependencyName, fixDetails.ImpactedDependency)
	versionWithConstraint := parsedJson.Path(pathToModule).Data()
	if versionWithConstraint == nil {
		return false, fmt.Errorf("failed to extract version with constratin from package-lock.json")
	}
	// Check constraints
	validFix, caret, err := passesConstraint(versionWithConstraint.(string), fixDetails.FixVersion)
	if err != nil || !validFix {
		log.Info("Cannot update indirect dependency due constraint compatibility, skipping ...")
		return false, nil
	}
	// Update fix version
	fixVersionWithOriginalConstraint := caret + fixDetails.FixVersion
	if _, err = parsedJson.SetP(fixVersionWithOriginalConstraint, pathToModule); err != nil {
		return
	}
	return true, nil
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
	packageLockVersion := container.Path(lockFileVersionAttributeName).Data().(float64)
	if packageLockVersion < supportedPackageLockVersion {
		return nil, fmt.Errorf("unsupported version of package lock file %f", packageLockVersion)
	}
	return container, nil
}

// Check that version is compatible with semantic version constraint
// Returns is valid fix, the original constraint, so we can pass it to our fix.
// Example ^1.2.3 -> 1.2.4 will result in True,'^'
func passesConstraint(versionWithConstraint string, fixVersion string) (valid bool, originalConstraint string, err error) {
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
	// No constraint
	if unicode.IsNumber(rune(versionWithConstraint[0])) {
		return ""
	}
	// Check constraint length
	constraintLength := 1
	if !unicode.IsNumber(rune(versionWithConstraint[1])) {
		constraintLength += 1
	}
	return versionWithConstraint[:constraintLength]
}
