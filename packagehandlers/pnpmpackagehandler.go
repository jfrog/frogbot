package packagehandlers

import (
	"errors"
	"fmt"
	"github.com/jfrog/frogbot/v2/utils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"os"
	"path"
	"path/filepath"
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

	vulnDepRegexp := getRegexpCompilerForVulnerability(vulnDetails.ImpactedDependencyName, vulnDetails.ImpactedDependencyVersion)

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

		var nodeModulesDirExist bool
		// If node_modules doesn't exist before the fix we delete it after fixing, so it will not be pushed into the PR
		nodeModulesDirExist, err = fileutils.IsDirExists(filepath.Join(modulePath, "node_modules"), false)

		err = pnpm.CommonPackageHandler.UpdateDependency(vulnDetails, vulnDetails.Technology.GetPackageInstallationCommand())
		if err != nil {
			err = fmt.Errorf("failed to update dependency '%s' from version '%s' to '%s': %s", vulnDetails.ImpactedDependencyName, vulnDetails.ImpactedDependencyVersion, vulnDetails.SuggestedFixedVersion, err.Error())
		}

		if !nodeModulesDirExist {
			err = fileutils.RemoveTempDir(filepath.Join(modulePath, "node_modules"))
		}
	}
	return
}

func getRegexpCompilerForVulnerability(vulnPackageName, vulnPackageVersion string) *regexp.Regexp {
	regexpAdjustedPackageName := strings.ReplaceAll(vulnPackageName, ".", "\\.")
	regexpAdjustedVersion := strings.ReplaceAll(vulnPackageVersion, ".", "\\.")
	patternToLookFor := strings.ToLower(fmt.Sprintf(pnpmDependencyPattern, regexpAdjustedPackageName, regexpAdjustedVersion))
	return regexp.MustCompile(patternToLookFor)
}
