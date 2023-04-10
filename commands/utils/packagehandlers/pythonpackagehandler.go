package packagehandlers

import (
	"errors"
	"fmt"
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

func (py *PythonPackageHandler) UpdateImpactedPackage(impactedPackage string, fixVersionInfo *FixVersionInfo, extraArgs ...string) error {
	switch fixVersionInfo.PackageType {
	case coreutils.Poetry:
		return py.handlePoetry(impactedPackage, fixVersionInfo)
	case coreutils.Pip:
		return py.handlePip(impactedPackage, fixVersionInfo)
	case coreutils.Pipenv:
		return py.GenericPackageHandler.UpdateImpactedPackage(impactedPackage, fixVersionInfo, extraArgs...)
	default:
		return errors.New("Unknown python package manger: " + fixVersionInfo.PackageType.GetPackageType())
	}
}

func (py *PythonPackageHandler) handlePoetry(impactedPackage string, fixVersionInfo *FixVersionInfo) error {
	// Install the desired fixed version
	if err := py.GenericPackageHandler.UpdateImpactedPackage(impactedPackage, fixVersionInfo); err != nil {
		return err
	}
	// Update Poetry lock file as well
	return runPackageMangerCommand(coreutils.Poetry.GetExecCommandName(), []string{"update"})
}

func (py *PythonPackageHandler) handlePip(impactedPackage string, info *FixVersionInfo) error {
	// This function assumes that the version of the dependencies is statically pinned in the requirements file or inside the 'install_requires' array in the setup.py file
	fixedPackage := impactedPackage + "==" + info.FixVersion
	if py.pipRequirementsFile == "" {
		py.pipRequirementsFile = "setup.py"
	}
	wd, err := os.Getwd()
	if err != nil {
		return err
	}
	fullPath := filepath.Join(wd, py.pipRequirementsFile)
	if !strings.HasPrefix(filepath.Clean(fullPath), wd) {
		return errors.New("wrong requirements file input")
	}
	data, err := os.ReadFile(filepath.Clean(py.pipRequirementsFile))
	if err != nil {
		return err
	}
	currentFile := string(data)
	// This regex will match the impactedPackage with it's pinned version e.py. PyJWT==1.7.1
	re := regexp.MustCompile(PythonPackageRegexPrefix + impactedPackage + PythonPackageRegexSuffix)
	packageToReplace := re.FindString(currentFile)
	if packageToReplace == "" {
		return fmt.Errorf("impacted package %s not found, fix failed", packageToReplace)
	}
	fixedFile := strings.Replace(currentFile, packageToReplace, fixedPackage, 1)
	return os.WriteFile(py.pipRequirementsFile, []byte(fixedFile), 0600)
}
