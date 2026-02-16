package packageupdaters

import (
	"fmt"
	"io/fs"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/jfrog/frogbot/v2/utils"
	"github.com/jfrog/gofrog/datastructures"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"golang.org/x/exp/slices"
)

// PackageUpdater interface to hold operations on packages
type PackageUpdater interface {
	UpdateDependency(details *utils.VulnerabilityDetails) error
}

func GetCompatiblePackageUpdater(vulnDetails *utils.VulnerabilityDetails, details *utils.ScanDetails) (handler PackageUpdater) {
	switch vulnDetails.Technology {
	case techutils.Go:
		handler = &GoPackageUpdater{}
	case techutils.Poetry:
		handler = &PythonPackageUpdater{}
	case techutils.Pipenv:
		handler = &PythonPackageUpdater{}
	case techutils.Npm:
		handler = &NpmPackageUpdater{}
	case techutils.Yarn:
		handler = &YarnPackageUpdater{}
	case techutils.Pip:
		handler = &PythonPackageUpdater{pipRequirementsFile: defaultRequirementFile}
	case techutils.Maven:
		handler = NewMavenPackageUpdater(details)
	case techutils.Nuget:
		handler = &NugetPackageUpdater{}
	case techutils.Gradle:
		handler = &GradlePackageUpdater{}
	case techutils.Pnpm:
		handler = &PnpmPackageUpdater{}
	case techutils.Conan:
		handler = &ConanPackageUpdater{}
	default:
		handler = &UnsupportedPackageUpdater{}
	}
	return
}

// TODO can be deleted if not needed after refactoring all package updaters
type CommonPackageUpdater struct{}

// UpdateDependency updates the impacted package to the fixed version
func (cph *CommonPackageUpdater) UpdateDependency(vulnDetails *utils.VulnerabilityDetails, installationCommand string, extraArgs ...string) (err error) {
	// Lower the package name to avoid duplicates
	impactedPackage := strings.ToLower(vulnDetails.ImpactedDependencyName)
	commandArgs := []string{installationCommand}
	commandArgs = append(commandArgs, extraArgs...)
	versionOperator := vulnDetails.Technology.GetPackageVersionOperator()
	fixedPackageArgs := getFixedPackage(impactedPackage, versionOperator, vulnDetails.SuggestedFixedVersion)
	commandArgs = append(commandArgs, fixedPackageArgs...)
	return runPackageMangerCommand(vulnDetails.Technology.GetExecCommandName(), vulnDetails.Technology.String(), commandArgs)
}

func runPackageMangerCommand(commandName string, techName string, commandArgs []string) error {
	fullCommand := commandName + " " + strings.Join(commandArgs, " ")
	log.Debug(fmt.Sprintf("Running '%s'", fullCommand))
	//#nosec G204 -- False positive - the subprocess only runs after the user's approval.
	output, err := exec.Command(commandName, commandArgs...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to update %s dependency: '%s' command failed: %s\n%s", techName, fullCommand, err.Error(), output)
	}
	return nil
}

// Returns the updated package and version as it should be run in the update command:
// If the package manager expects a single string (example: <packName>@<version>) it returns []string{<packName>@<version>}
// If the command args suppose to be seperated by spaces (example: <packName> -v <version>) it returns []string{<packName>, "-v", <version>}
func getFixedPackage(impactedPackage string, versionOperator string, suggestedFixedVersion string) (fixedPackageArgs []string) {
	fixedPackageString := strings.TrimSpace(impactedPackage) + versionOperator + strings.TrimSpace(suggestedFixedVersion)
	fixedPackageArgs = strings.Split(fixedPackageString, " ")
	return
}

// Recursively scans the current directory for descriptor files based on the provided list of suffixes, while excluding paths that match the specified exclusion patterns.
// The patternsToExclude must be provided as regexp patterns. For instance, if the pattern ".*node_modules.*" is provided, any paths containing "node_modules" will be excluded from the result.
// Returns a slice of all discovered descriptor files, represented as absolute paths.
func (cph *CommonPackageUpdater) GetAllDescriptorFilesFullPaths(descriptorFilesSuffixes []string, patternsToExclude ...string) (descriptorFilesFullPaths []string, err error) {
	if len(descriptorFilesSuffixes) == 0 {
		return
	}

	var regexpPatternsCompilers []*regexp.Regexp
	for _, patternToExclude := range patternsToExclude {
		regexpPatternsCompilers = append(regexpPatternsCompilers, regexp.MustCompile(patternToExclude))
	}

	err = filepath.WalkDir(".", func(path string, d fs.DirEntry, innerErr error) error {
		if innerErr != nil {
			return fmt.Errorf("an error has occurred when attempting to access or traverse the file system: %w", innerErr)
		}

		for _, regexpCompiler := range regexpPatternsCompilers {
			if match := regexpCompiler.FindString(path); match != "" {
				return filepath.SkipDir
			}
		}

		for _, assetFileSuffix := range descriptorFilesSuffixes {
			if strings.HasSuffix(path, assetFileSuffix) {
				var absFilePath string
				absFilePath, innerErr = filepath.Abs(path)
				if innerErr != nil {
					return fmt.Errorf("couldn't retrieve file's absolute path for './%s': %w", path, innerErr)
				}
				descriptorFilesFullPaths = append(descriptorFilesFullPaths, absFilePath)
			}
		}
		return nil
	})
	if err != nil {
		err = fmt.Errorf("failed to get descriptor files absolute paths: %w", err)
	}
	return
}

func BuildPackageWithVersionRegex(impactedName, impactedVersion, dependencyLineFormat string) *regexp.Regexp {
	regexpFitImpactedName := strings.ToLower(regexp.QuoteMeta(impactedName))
	regexpFitImpactedVersion := strings.ToLower(regexp.QuoteMeta(impactedVersion))
	regexpCompleteFormat := fmt.Sprintf(strings.ToLower(dependencyLineFormat), regexpFitImpactedName, regexpFitImpactedVersion)
	return regexp.MustCompile(regexpCompleteFormat)
}

func GetVulnerabilityLocations(vulnDetails *utils.VulnerabilityDetails, namesFilters []string, ignoreFilters []string) []string {
	pathsSet := datastructures.MakeSet[string]()
	for _, component := range vulnDetails.Components {
		for _, evidence := range component.Evidences {
			if evidence.File == "" || techutils.IsTechnologyDescriptor(evidence.File) == techutils.NoTech || slices.ContainsFunc(ignoreFilters, func(pattern string) bool { return strings.Contains(evidence.File, pattern) }) {
				continue
			}
			if len(namesFilters) == 0 || slices.Contains(namesFilters, filepath.Base(evidence.File)) {
				pathsSet.Add(evidence.File)
			}
		}
	}
	return pathsSet.ToSlice()
}
