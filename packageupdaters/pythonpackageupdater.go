package packageupdaters

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/jfrog/jfrog-cli-security/utils/techutils"

	"github.com/jfrog/frogbot/v2/utils"
)

const (
	defaultRequirementFile = "requirements.txt"
	// Package names are case-insensitive with this prefix
	PythonPackageRegexPrefix = "(?i)"
	// Match all possible operators and versions syntax
	PythonPackageRegexSuffix = "\\s*(([\\=\\<\\>\\~]=)|([\\>\\<]))\\s*(\\.|\\d)*(\\d|(\\.\\*))(\\,\\s*(([\\=\\<\\>\\~]=)|([\\>\\<])).*\\s*(\\.|\\d)*(\\d|(\\.\\*)))?"
)

type PythonPackageUpdater struct {
	pipRequirementsFile string
	CommonPackageUpdater
}

func (py *PythonPackageUpdater) UpdateDependency(vulnDetails *utils.VulnerabilityDetails) error {
	if vulnDetails.IsDirectDependency {
		return py.updateDirectDependency(vulnDetails)
	}

	return &utils.ErrUnsupportedFix{
		PackageName:  vulnDetails.ImpactedDependencyName,
		FixedVersion: vulnDetails.SuggestedFixedVersion,
		ErrorType:    utils.IndirectDependencyFixNotSupported,
	}
}

func (py *PythonPackageUpdater) updateDirectDependency(vulnDetails *utils.VulnerabilityDetails) (err error) {
	switch vulnDetails.Technology {
	case techutils.Poetry:
		return py.handlePoetry(vulnDetails)
	case techutils.Pip:
		return py.handlePip(vulnDetails)
	case techutils.Pipenv:
		return py.CommonPackageUpdater.UpdateDependency(vulnDetails, vulnDetails.Technology.GetPackageInstallationCommand())
	default:
		return errors.New("unknown python package manger: " + vulnDetails.Technology.GetPackageType())
	}
}

func (py *PythonPackageUpdater) handlePoetry(vulnDetails *utils.VulnerabilityDetails) (err error) {
	if err = py.CommonPackageUpdater.UpdateDependency(vulnDetails, vulnDetails.Technology.GetPackageInstallationCommand()); err != nil {
		return
	}
	return runPackageMangerCommand(techutils.Poetry.GetExecCommandName(), techutils.Poetry.String(), []string{"update"})
}

func (py *PythonPackageUpdater) handlePip(vulnDetails *utils.VulnerabilityDetails) (err error) {
	var fixedFile string
	fixedPackage := vulnDetails.ImpactedDependencyName + "==" + vulnDetails.SuggestedFixedVersion
	currentFile, err := py.tryGetRequirementFile()
	if err != nil {
		return errors.New("failed to read pip requirements file: " + err.Error())
	}
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

func (py *PythonPackageUpdater) tryGetRequirementFile() (string, error) {
	if py.pipRequirementsFile != "" {
		fileContent, err := py.tryReadRequirementFile(py.pipRequirementsFile)
		if err != nil {
			return "", err
		}
		return fileContent, nil
	} else {
		// if we don't have a value in py.pipRequirementsFile - we try first setup.py and then requirements.txt
		py.pipRequirementsFile = "setup.py"
		fileContent, err := py.tryReadRequirementFile(py.pipRequirementsFile)
		if err != nil {
			py.pipRequirementsFile = "requirements.txt"
			fileContent, err = py.tryReadRequirementFile(py.pipRequirementsFile)
			if err != nil {
				return "", err
			}
			return fileContent, nil
		}
		return fileContent, nil
	}
}

func (py *PythonPackageUpdater) tryReadRequirementFile(file string) (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	fullPath := filepath.Join(wd, file)
	if !strings.HasPrefix(filepath.Clean(fullPath), wd) {
		return "", errors.New("wrong requirements file input: " + fullPath)
	}
	data, err := os.ReadFile(filepath.Clean(file))
	if err != nil {
		return "", errors.New("an error occurred while attempting to read the requirements file:\n" + err.Error())
	}
	return string(data), nil
}
