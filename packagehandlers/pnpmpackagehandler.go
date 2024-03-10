package packagehandlers

import (
	"errors"
	"fmt"
	"github.com/jfrog/frogbot/v2/utils"
	"os"
	"path"
	"regexp"
	"strings"
)

const (
	pnpmDependencyPattern = "\\s*\"%s\"\\s*:\\s*\"[~|^]?%s\""
)

type PnpmPackageHandler struct {
	CommonPackageHandler
}

func (pnpm *PnpmPackageHandler) UpdateDependency(vulnDetails *utils.VulnerabilityDetails) error {
	if vulnDetails.IsDirectDependency {
		return pnpm.updateDirectDependency(vulnDetails)
	}

	return &utils.ErrUnsupportedFix{
		PackageName:  vulnDetails.ImpactedDependencyName,
		FixedVersion: vulnDetails.SuggestedFixedVersion,
		ErrorType:    utils.IndirectDependencyFixNotSupported,
	}
}

func (pnpm *PnpmPackageHandler) updateDirectDependency(vulnDetails *utils.VulnerabilityDetails) (err error) {
	// TODO similar to NPM take care of node_module exist or not

	descriptorFilesFullPaths, err := pnpm.CommonPackageHandler.GetAllDescriptorFilesFullPaths([]string{"package.json"}, ".*node_modules.*")
	if err != nil {
		return
	}

	wd, err := os.Getwd()
	if err != nil {
		err = fmt.Errorf("failed to get current working directory: %s", err.Error())
		return
	}

	// TODO ERAN check about this: var anyDescriptorFileChanged bool

	for _, descriptorFile := range descriptorFilesFullPaths {
		err = pnpm.fixVulnerabilityIfExists(vulnDetails, descriptorFile, wd)
		if err != nil {
			return
		}
	}

	return nil
}

func (pnpm *PnpmPackageHandler) fixVulnerabilityIfExists(vulnDetails *utils.VulnerabilityDetails, descriptorFilePath, originalWd string) (err error) {
	// TODO ERAN consult if it is best to check for the vulnerability in the descriptor before fixing it (overhead)
	var fileData []byte
	fileData, err = os.ReadFile(descriptorFilePath)
	if err != nil {
		err = fmt.Errorf("failed to read file '%s': %s", descriptorFilePath, err.Error())
		return
	}

	regexpAdjustedPackageName := strings.ReplaceAll(vulnDetails.ImpactedDependencyName, ".", "\\.")
	regexpAdjustedVersion := strings.ReplaceAll(vulnDetails.ImpactedDependencyVersion, ".", "\\.")
	patternToLookFor := strings.ToLower(fmt.Sprintf(pnpmDependencyPattern, regexpAdjustedPackageName, regexpAdjustedVersion))
	vulnDepRegexp := regexp.MustCompile(patternToLookFor)

	// If the vulnerability dependency was found in the current descriptor we want to fix it
	if match := vulnDepRegexp.FindString(strings.ToLower(string(fileData))); match != "" {
		modulePath := path.Dir(descriptorFilePath)
		err = os.Chdir(modulePath)
		if err != nil {
			err = fmt.Errorf("failed to change directory to '%s': %s", modulePath, err.Error())
			return
		}
		defer func() {
			err = errors.Join(err, os.Chdir(originalWd))
		}()

		// TODO ERAN make sure that the update command updates in the correct scope (dep, dev dep, optional dep..) - check with vulnerabilities in different scopes
		err = pnpm.CommonPackageHandler.UpdateDependency(vulnDetails, vulnDetails.Technology.GetPackageInstallationCommand())
		if err != nil {
			err = fmt.Errorf("failed to update dependency '%s' from version '%s' to '%s': %s", vulnDetails.ImpactedDependencyName, vulnDetails.ImpactedDependencyVersion, vulnDetails.SuggestedFixedVersion, err.Error())
		}
		// TODO ERAN check if its possible that a descriptor file cannot be fixed, and there will be no change to commit, so a PR should not be opened. since we use a built-in command this is not likely, but still check
	}
	// TODO ERAN check usecase: can we have the same package in 2 deps scopes in teh same file and we need to fix only in one scope?
	return
}
