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
	common
}

func (py *PythonPackageHandler) UpdateDependency(fixDetails *utils.FixDetails) (bool, error) {
	if fixDetails.DirectDependency {
		return py.updateDirectDependency(fixDetails)
	} else {
		return py.updateIndirectDependency(fixDetails)
	}
}

func (py *PythonPackageHandler) updateIndirectDependency(fixDetails *utils.FixDetails, extraArgs ...string) (shouldFix bool, err error) {
	// Indirect fixes are currently not supported
	return false, nil
}

func (py *PythonPackageHandler) updateDirectDependency(fixDetails *utils.FixDetails, extraArgs ...string) (shouldFix bool, err error) {
	switch fixDetails.PackageType {
	case coreutils.Poetry:
		return py.handlePoetry(fixDetails)
	case coreutils.Pip:
		return py.handlePip(fixDetails)
	case coreutils.Pipenv:
		return py.common.UpdateDependency(fixDetails, extraArgs...)
	default:
		return false, errors.New("Unknown python package manger: " + fixDetails.PackageType.GetPackageType())
	}
}

func (py *PythonPackageHandler) handlePoetry(fixDetails *utils.FixDetails) (shouldFix bool, err error) {
	// Install the desired fixed version
	shouldFix, err = py.common.UpdateDependency(fixDetails)
	if err != nil {
		return
	}
	if shouldFix {
		// Update Poetry lock file as well
		return err == nil, runPackageMangerCommand(coreutils.Poetry.GetExecCommandName(), []string{"update"})
	}
	return
}

func (py *PythonPackageHandler) handlePip(fixDetails *utils.FixDetails) (shouldFix bool, err error) {
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
		return false, errors.New("wrong requirements file input")
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
		return false, fmt.Errorf("impacted package %s not found, fix failed", fixDetails.ImpactedDependency)
	}
	if err = os.WriteFile(py.pipRequirementsFile, []byte(fixedFile), 0600); err != nil {
		return
	}
	return true, nil
}
