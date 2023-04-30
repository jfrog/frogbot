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
	GenericPackageHandler
}

func (py *PythonPackageHandler) UpdateImpactedPackage(impactedPackage string, fixVersionInfo *utils.FixVersionInfo, extraArgs ...string) (shouldFix bool, err error) {
	switch fixVersionInfo.PackageType {
	case coreutils.Poetry:
		return py.handlePoetry(impactedPackage, fixVersionInfo)
	case coreutils.Pip:
		return py.handlePip(impactedPackage, fixVersionInfo)
	case coreutils.Pipenv:
		return py.GenericPackageHandler.UpdateImpactedPackage(impactedPackage, fixVersionInfo, extraArgs...)
	default:
		return false, errors.New("Unknown python package manger: " + fixVersionInfo.PackageType.GetPackageType())
	}
}

func (py *PythonPackageHandler) handlePoetry(impactedPackage string, fixVersionInfo *utils.FixVersionInfo) (shouldFix bool, err error) {
	// Install the desired fixed version
	shouldFix, err = py.GenericPackageHandler.UpdateImpactedPackage(impactedPackage, fixVersionInfo)
	if err != nil {
		return
	}
	if shouldFix {
		// Update Poetry lock file as well
		return err == nil, runPackageMangerCommand(coreutils.Poetry.GetExecCommandName(), []string{"update"})
	}
	return
}

func (py *PythonPackageHandler) handlePip(impactedPackage string, info *utils.FixVersionInfo) (shouldFix bool, err error) {
	var fixedFile string
	// This function assumes that the version of the dependencies is statically pinned in the requirements file or inside the 'install_requires' array in the setup.py file
	fixedPackage := impactedPackage + "==" + info.FixVersion
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
	re := regexp.MustCompile(PythonPackageRegexPrefix + "(" + impactedPackage + "|" + strings.ToLower(impactedPackage) + ")" + PythonPackageRegexSuffix)
	if packageToReplace := re.FindString(currentFile); packageToReplace != "" {
		fixedFile = strings.Replace(currentFile, packageToReplace, strings.ToLower(fixedPackage), 1)
	}
	if fixedFile == "" {
		return false, fmt.Errorf("impacted package %s not found, fix failed", impactedPackage)
	}
	if err = os.WriteFile(py.pipRequirementsFile, []byte(fixedFile), 0600); err != nil {
		return
	}
	return true, nil
}
