package packagehandlers

import (
	"errors"
	"fmt"
	"github.com/jfrog/frogbot/commands/utils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const (

	// Package names are case-insensitive with this prefix
	PythonPackageRegexPrefix = "(?i)"
	// Match all possible operators and versions syntax
	PythonPackageRegexSuffix = "\\s*(([\\=\\<\\>\\~]=)|([\\>\\<]))\\s*(\\.|\\d)*(\\d|(\\.\\*))(\\,\\s*(([\\=\\<\\>\\~]=)|([\\>\\<])).*\\s*(\\.|\\d)*(\\d|(\\.\\*)))?"
)

// PythonPackageHandler Handles all the python package mangers as they share behavior
type PythonPackageHandler struct {
	pipRequirementsFile string
	CommonPackageHandler
}

func (py *PythonPackageHandler) UpdateDependency(fixDetails *utils.FixDetails) error {
	if fixDetails.DirectDependency {
		return py.updateDirectDependency(fixDetails)
	} else {
		return &utils.ErrUnsupportedFix{
			PackageName: fixDetails.ImpactedDependency,
			Reason:      utils.IndirectDependencyNotSupported,
		}
	}
}

func (py *PythonPackageHandler) updateDirectDependency(fixDetails *utils.FixDetails, extraArgs ...string) (err error) {
	switch fixDetails.PackageType {
	case coreutils.Poetry:
		return py.handlePoetry(fixDetails)
	case coreutils.Pip:
		return py.handlePip(fixDetails)
	case coreutils.Pipenv:
		return py.CommonPackageHandler.UpdateDependency(fixDetails, extraArgs...)
	default:
		return errors.New("Unknown python package manger: " + fixDetails.PackageType.GetPackageType())
	}
}

func (py *PythonPackageHandler) handlePoetry(fixDetails *utils.FixDetails) (err error) {
	// Install the desired fixed version
	if err = py.CommonPackageHandler.UpdateDependency(fixDetails); err != nil {
		return
	}
	// Update Poetry lock file as well
	return runPackageMangerCommand(coreutils.Poetry.GetExecCommandName(), []string{"update"})
}

func (py *PythonPackageHandler) handlePip(fixDetails *utils.FixDetails) (err error) {
	var fixedFile string
	// This function assumes that the version of the dependencies is statically pinned in the requirements file or inside the 'install_requires' array in the setup.py file
	fixedPackage := fixDetails.ImpactedDependency + "==" + fixDetails.FixVersion
	if py.pipRequirementsFile == "" {
		py.pipRequirementsFile = "setup.py"
	}
	wd, err := os.Getwd()
	if err != nil {
		return
	}
	fullPath := filepath.Join(wd, py.pipRequirementsFile)
	if !strings.HasPrefix(filepath.Clean(fullPath), wd) {
		return errors.New("wrong requirements file input")
	}
	data, err := os.ReadFile(filepath.Clean(py.pipRequirementsFile))
	if err != nil {
		return
	}
	currentFile := string(data)

	// Check both original and lowered package name and replace to only one lowered result
	// This regex will match the impactedPackage with it's pinned version e.py. PyJWT==1.7.1
	re := regexp.MustCompile(PythonPackageRegexPrefix + "(" + fixDetails.ImpactedDependency + "|" + strings.ToLower(fixDetails.ImpactedDependency) + ")" + PythonPackageRegexSuffix)
	if packageToReplace := re.FindString(currentFile); packageToReplace != "" {
		fixedFile = strings.Replace(currentFile, packageToReplace, strings.ToLower(fixedPackage), 1)
	}
	if fixedFile == "" {
		return fmt.Errorf("impacted package %s not found, fix failed", fixDetails.ImpactedDependency)
	}
	return os.WriteFile(py.pipRequirementsFile, []byte(fixedFile), 0600)
}
