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

func (py *PythonPackageHandler) UpdateDependency(vulnDetails *utils.VulnerabilityDetails) error {
	if vulnDetails.IsDirectDependency {
		return py.updateDirectDependency(vulnDetails)
	}

	return &utils.ErrUnsupportedFix{
		PackageName:  vulnDetails.ImpactedDependencyName,
		FixedVersion: vulnDetails.SuggestedFixedVersion,
		ErrorType:    utils.IndirectDependencyFixNotSupported,
	}
}

func (py *PythonPackageHandler) updateDirectDependency(vulnDetails *utils.VulnerabilityDetails, extraArgs ...string) (err error) {
	switch vulnDetails.Technology {
	case coreutils.Poetry:
		return py.handlePoetry(vulnDetails)
	case coreutils.Pip:
		return py.handlePip(vulnDetails)
	case coreutils.Pipenv:
		return py.CommonPackageHandler.UpdateDependency(vulnDetails, extraArgs...)
	default:
		return errors.New("unknown python package manger: " + vulnDetails.Technology.GetPackageType())
	}
}

func (py *PythonPackageHandler) handlePoetry(vulnDetails *utils.VulnerabilityDetails) (err error) {
	// Install the desired fixed version
	if err = py.CommonPackageHandler.UpdateDependency(vulnDetails); err != nil {
		return
	}
	// Update Poetry lock file as well
	return runPackageMangerCommand(coreutils.Poetry.GetExecCommandName(), []string{"update"})
}

func (py *PythonPackageHandler) handlePip(vulnDetails *utils.VulnerabilityDetails) (err error) {
	var fixedFile string
	// This function assumes that the version of the dependencies is statically pinned in the requirements file or inside the 'install_requires' array in the setup.py file
	fixedPackage := vulnDetails.ImpactedDependencyName + "==" + vulnDetails.SuggestedFixedVersion
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
		return errors.New("an error occurred while attempting to read the requirements file:\n" + err.Error())
	}
	currentFile := string(data)

	// Check both original and lowered package name and replace to only one lowered result
	// This regex will match the impactedPackage with it's pinned version e.py. PyJWT==1.7.1
	re := regexp.MustCompile(PythonPackageRegexPrefix + "(" + vulnDetails.ImpactedDependencyName + "|" + strings.ToLower(vulnDetails.ImpactedDependencyName) + ")" + PythonPackageRegexSuffix)
	if packageToReplace := re.FindString(currentFile); packageToReplace != "" {
		fixedFile = strings.Replace(currentFile, packageToReplace, strings.ToLower(fixedPackage), 1)
	}
	if fixedFile == "" {
		return fmt.Errorf("impacted package %s not found, fix failed", vulnDetails.ImpactedDependencyName)
	}
	if err = os.WriteFile(py.pipRequirementsFile, []byte(fixedFile), 0600); err != nil {
		err = fmt.Errorf("an error occured while writing the fixed version of %s to the requirements file:\n%s", vulnDetails.SuggestedFixedVersion, err.Error())
	}
	return
}
