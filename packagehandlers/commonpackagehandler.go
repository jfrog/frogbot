package packagehandlers

import (
	"fmt"
	"io/fs"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/jfrog/frogbot/v2/utils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
)

// PackageHandler interface to hold operations on packages
type PackageHandler interface {
	UpdateDependency(details *utils.VulnerabilityDetails) error
	SetCommonParams(serverDetails *config.ServerDetails, depsRepo string)
}

func GetCompatiblePackageHandler(vulnDetails *utils.VulnerabilityDetails, details *utils.ScanDetails) (handler PackageHandler) {
	switch vulnDetails.Technology {
	case techutils.Go:
		handler = &GoPackageHandler{}
	case techutils.Poetry:
		handler = &PythonPackageHandler{}
	case techutils.Pipenv:
		handler = &PythonPackageHandler{}
	case techutils.Npm:
		handler = &NpmPackageHandler{}
	case techutils.Yarn:
		handler = &YarnPackageHandler{}
	case techutils.Pip:
		handler = &PythonPackageHandler{pipRequirementsFile: details.PipRequirementsFile}
	case techutils.Maven:
		handler = NewMavenPackageHandler(details)
	case techutils.Nuget:
		handler = &NugetPackageHandler{}
	case techutils.Gradle:
		handler = &GradlePackageHandler{}
	case techutils.Pnpm:
		handler = &PnpmPackageHandler{}
	case techutils.Conan:
		handler = &ConanPackageHandler{}
	default:
		handler = &UnsupportedPackageHandler{}
	}
	handler.SetCommonParams(details.ServerDetails, details.DepsRepo)
	return
}

type CommonPackageHandler struct {
	serverDetails *config.ServerDetails
	depsRepo      string
}

// UpdateDependency updates the impacted package to the fixed version
func (cph *CommonPackageHandler) UpdateDependency(vulnDetails *utils.VulnerabilityDetails, installationCommand string, extraArgs ...string) (err error) {
	// Lower the package name to avoid duplicates
	impactedPackage := strings.ToLower(vulnDetails.ImpactedDependencyName)
	commandArgs := []string{installationCommand}
	commandArgs = append(commandArgs, extraArgs...)
	versionOperator := vulnDetails.Technology.GetPackageVersionOperator()
	fixedPackageArgs := getFixedPackage(impactedPackage, versionOperator, vulnDetails.SuggestedFixedVersion)
	commandArgs = append(commandArgs, fixedPackageArgs...)
	return runPackageMangerCommand(vulnDetails.Technology.GetExecCommandName(), vulnDetails.Technology.String(), commandArgs)
}

func (cph *CommonPackageHandler) SetCommonParams(serverDetails *config.ServerDetails, depsRepo string) {
	cph.serverDetails = serverDetails
	cph.depsRepo = depsRepo
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
func (cph *CommonPackageHandler) GetAllDescriptorFilesFullPaths(descriptorFilesSuffixes []string, patternsToExclude ...string) (descriptorFilesFullPaths []string, err error) {
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

// This function adjusts the name and version of a dependency to conform to a regular expression format and constructs the complete regular expression pattern for searching.
// Note: 'dependencyLineFormat' should be a template with two placeholders to be populated. The first one will be replaced with 'impactedName', and the second one with 'impactedVersion'.
// Note: All supplied arguments are converted to lowercase. Hence, when utilizing this function, the file in which we search for the patterns must also be converted to lowercase.
// Note: This function may not support all package manager dependency formats. It is designed for package managers where the dependency's name consists of a single component.
// For example, in Gradle descriptors, a dependency line may consist of two components for the dependency's name (e.g., implementation group: 'junit', name: 'junit', version: '4.7'), therefore this func cannot be utilized in this case.
func GetVulnerabilityRegexCompiler(impactedName, impactedVersion, dependencyLineFormat string) *regexp.Regexp {
	// We replace '.' with '\\.' since '.' is a special character in regexp patterns, and we want to capture the character '.' itself
	// To avoid dealing with case sensitivity we lower all characters in the package's name and in the file we check
	regexpFitImpactedName := strings.ToLower(strings.ReplaceAll(impactedName, ".", "\\."))
	regexpFitImpactedVersion := strings.ToLower(strings.ReplaceAll(impactedVersion, ".", "\\."))
	regexpCompleteFormat := fmt.Sprintf(strings.ToLower(dependencyLineFormat), regexpFitImpactedName, regexpFitImpactedVersion)
	return regexp.MustCompile(regexpCompleteFormat)
}
