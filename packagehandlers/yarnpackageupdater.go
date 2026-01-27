package packagehandlers

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/jfrog/frogbot/v2/utils"
	"github.com/jfrog/jfrog-client-go/utils/log"
)

const (
	yarnLockFileName        = "yarn.lock"
	resolutionsSection      = "resolutions"
	yarnInstallTimeout      = 15 * time.Minute
	yarnIgnoreScriptsFlag   = "--ignore-scripts"
	yarnFrozenLockfileFlag  = "--frozen-lockfile=false"
	yarnModeFlag            = "--mode"
	yarnModeUpdateLockfile  = "update-lockfile"
	ciEnvYarn               = "CI"
	yarnBerryLockfileHeader = "__metadata:"
)

var yarnAllowedSections = []string{dependenciesSectionName, devDependenciesSectionName, optionalDependenciesSectionName, resolutionsSection}

var yarnInstallEnvVars = map[string]string{
	ciEnvYarn: "true",
}

type YarnPackageUpdater struct {
	CommonPackageHandler
}

func (yarn *YarnPackageUpdater) UpdateDependency(vulnDetails *utils.VulnerabilityDetails) error {
	if vulnDetails.IsDirectDependency {
		return yarn.updateDirectDependency(vulnDetails)
	}
	return &utils.ErrUnsupportedFix{
		PackageName:  vulnDetails.ImpactedDependencyName,
		FixedVersion: vulnDetails.SuggestedFixedVersion,
		ErrorType:    utils.IndirectDependencyFixNotSupported,
	}
}

func (yarn *YarnPackageUpdater) updateDirectDependency(vulnDetails *utils.VulnerabilityDetails) error {
	descriptorPaths, err := GetDescriptorsToFixFromVulnerability(vulnDetails, yarnLockFileName)
	if err != nil {
		return err
	}

	originalWd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get current working directory: %w", err)
	}

	var failingDescriptors []string
	for _, descriptorPath := range descriptorPaths {
		if fixErr := UpdatePackageAndRegenerateLock(
			vulnDetails.ImpactedDependencyName,
			vulnDetails.ImpactedDependencyVersion,
			vulnDetails.SuggestedFixedVersion,
			descriptorPath,
			originalWd,
			yarnLockFileName,
			yarnAllowedSections,
			yarn.regenerateLockFileWithRetry,
		); fixErr != nil {
			failedFixErrorMsg := fmt.Errorf("failed to fix '%s' in descriptor '%s': %w", vulnDetails.ImpactedDependencyName, descriptorPath, fixErr)
			log.Warn(failedFixErrorMsg.Error())
			err = errors.Join(err, failedFixErrorMsg)
			failingDescriptors = append(failingDescriptors, descriptorPath)
		}
	}
	if err != nil {
		return fmt.Errorf("encountered errors while fixing '%s' vulnerability in descriptors [%s]: %w", vulnDetails.ImpactedDependencyName, strings.Join(failingDescriptors, ", "), err)
	}

	return nil
}

func (yarn *YarnPackageUpdater) regenerateLockFileWithRetry() error {
	err := yarn.runYarnInstall()
	if err != nil {
		log.Debug(fmt.Sprintf("First yarn install attempt failed: %s. Retrying...", err.Error()))
		if err = yarn.runYarnInstall(); err != nil {
			return fmt.Errorf("yarn install failed after retry: %w", err)
		}
	}
	return nil
}

func (yarn *YarnPackageUpdater) detectYarnVersion() (isBerry bool, err error) {
	content, err := os.ReadFile(yarnLockFileName)
	if err != nil {
		return false, fmt.Errorf("failed to read %s: %w", yarnLockFileName, err)
	}
	if strings.HasPrefix(string(content), yarnBerryLockfileHeader) {
		return true, nil
	}
	return false, nil
}

func (yarn *YarnPackageUpdater) runYarnInstall() error {
	isBerry, err := yarn.detectYarnVersion()
	if err != nil {
		return fmt.Errorf("failed to detect yarn version: %w", err)
	}

	args := []string{"install"}

	if isBerry {
		args = append(args, yarnModeFlag, yarnModeUpdateLockfile)
	} else {
		args = append(args, yarnIgnoreScriptsFlag, yarnFrozenLockfileFlag)
	}

	fullCommand := "yarn " + strings.Join(args, " ")
	log.Debug(fmt.Sprintf("Running '%s' (Yarn %s)", fullCommand, map[bool]string{true: "Berry 2+", false: "Classic 1"}[isBerry]))

	ctx, cancel := context.WithTimeout(context.Background(), yarnInstallTimeout)
	defer cancel()

	//#nosec G204 -- False positive - the subprocess only runs after the user's approval
	cmd := exec.CommandContext(ctx, "yarn", args...)

	cmd.Env = buildIsolatedEnv(yarnInstallEnvVars)
	output, err := cmd.CombinedOutput()

	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return fmt.Errorf("yarn install timed out after %v", yarnInstallTimeout)
	}

	if err != nil {
		return fmt.Errorf("yarn install failed: %w\nOutput: %s", err, string(output))
	}

	return nil
}
