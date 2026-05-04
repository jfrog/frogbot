package packageupdaters

import (
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/jfrog/gofrog/datastructures"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
	"golang.org/x/exp/slices"

	"github.com/jfrog/frogbot/v2/utils"
)

// Node
const (
	nodePackageJSONFileName         = "package.json"
	nodeModulesDirName              = "node_modules"
	nodeDependenciesSection         = "dependencies"
	nodeDevDependenciesSection      = "devDependencies"
	nodeOptionalDependenciesSection = "optionalDependencies"
	nodeOverridesSection            = "overrides"
)

var nodePackageManifestSections = []string{
	nodeDependenciesSection,
	nodeDevDependenciesSection,
	nodeOptionalDependenciesSection,
	nodeOverridesSection,
}

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
		handler = &MavenPackageUpdater{}
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

// evidencePathLooksLikeNpmPackageCoordinate reports paths such as "lodash@4.17.19/package.json" that scanners
// sometimes attach as evidence; they mirror "name@version" coordinates and are not real filesystem paths.
// Used by the pnpm updater only; npm collection behavior is unchanged.
func evidencePathLooksLikeNpmPackageCoordinate(evidenceFile string) bool {
	dir := filepath.Dir(evidenceFile)
	if dir == "." || dir == "" {
		return false
	}
	for _, part := range strings.Split(filepath.ToSlash(dir), "/") {
		if part == "" || part == "." {
			continue
		}
		// Scoped npm folders use a leading "@", e.g. "@types/node"; "pkg@1.2.3" is a coordinate, not a scope.
		if strings.Contains(part, "@") && !strings.HasPrefix(part, "@") {
			return true
		}
	}
	return false
}

// CollectVulnerabilityDescriptorPaths returns descriptor paths from vulnerability evidence (npm / pnpm package.json flow).
// Pnpm applies an additional filter for coordinate-style pseudo paths; see PnpmPackageUpdater.updateDirectDependency.
func (cph *CommonPackageUpdater) CollectVulnerabilityDescriptorPaths(vulnDetails *utils.VulnerabilityDetails, namesFilters []string, ignoreFilters []string) []string {
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

// BuildPackageDependencyLineRegex builds a regexp for matching a dependency line in a manifest.
func (cph *CommonPackageUpdater) BuildPackageDependencyLineRegex(impactedName, impactedVersion, dependencyLineFormat string) *regexp.Regexp {
	regexpFitImpactedName := strings.ToLower(regexp.QuoteMeta(impactedName))
	regexpFitImpactedVersion := strings.ToLower(regexp.QuoteMeta(impactedVersion))
	regexpCompleteFormat := fmt.Sprintf(strings.ToLower(dependencyLineFormat), regexpFitImpactedName, regexpFitImpactedVersion)
	return regexp.MustCompile(regexpCompleteFormat)
}

// EscapeJSONPathKey escapes gjson/sjson path keys for package names in package.json.
func (cph *CommonPackageUpdater) EscapeJSONPathKey(key string) string {
	r := strings.NewReplacer(".", "\\.", "*", "\\*", "?", "\\?")
	return r.Replace(key)
}

// GetFixedPackageJSONManifest returns manifest bytes with packageName set to newVersion in allowed sections.
func (cph *CommonPackageUpdater) GetFixedPackageJSONManifest(content []byte, packageName, newVersion, descriptorPath string) ([]byte, error) {
	updated := false
	escapedName := cph.EscapeJSONPathKey(packageName)

	for _, section := range nodePackageManifestSections {
		path := section + "." + escapedName
		if gjson.GetBytes(content, path).Exists() {
			var err error
			content, err = sjson.SetBytes(content, path, newVersion)
			if err != nil {
				return nil, fmt.Errorf("failed to set version for '%s' in section '%s': %w", packageName, section, err)
			}
			updated = true
		}
	}

	if !updated {
		return nil, fmt.Errorf("package '%s' not found in allowed sections [%s] in '%s'", packageName, strings.Join(nodePackageManifestSections, ", "), descriptorPath)
	}
	return content, nil
}

// UpdatePackageJSONDescriptor writes the fixed version for packageName to descriptorPath and returns original file bytes for rollback.
func (cph *CommonPackageUpdater) UpdatePackageJSONDescriptor(descriptorPath, packageName, newVersion string) ([]byte, error) {
	descriptorContent, err := os.ReadFile(descriptorPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file '%s': %w", descriptorPath, err)
	}

	backupContent := make([]byte, len(descriptorContent))
	copy(backupContent, descriptorContent)

	updatedContent, err := cph.GetFixedPackageJSONManifest(descriptorContent, packageName, newVersion, descriptorPath)
	if err != nil {
		return nil, fmt.Errorf("failed to update version in descriptor: %w", err)
	}

	//#nosec G703 -- False positive - the path is determined by internal file scanning, not user input, and was already validated by the preceding Stat call.
	if err = os.WriteFile(descriptorPath, updatedContent, 0644); err != nil {
		return nil, fmt.Errorf("failed to write updated descriptor '%s': %w", descriptorPath, err)
	}
	return backupContent, nil
}

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
	cmd := exec.Command(commandName, commandArgs...)
	if commandName == "pnpm" {
		cmd.Env = envWithCorepackIntegrityWorkaround(os.Environ())
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to update %s dependency: '%s' command failed: %s\n%s", techName, fullCommand, err.Error(), output)
	}
	return nil
}

// envWithCorepackIntegrityWorkaround avoids Corepack "Cannot find matching keyid" failures on Node versions
// whose bundled Corepack lags npm registry signing keys (see nodejs/corepack#612).
func envWithCorepackIntegrityWorkaround(base []string) []string {
	const key = "COREPACK_INTEGRITY_KEYS"
	prefix := key + "="
	out := make([]string, 0, len(base)+1)
	for _, e := range base {
		if !strings.HasPrefix(e, prefix) {
			out = append(out, e)
		}
	}
	return append(out, prefix+"0")
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
	var c CommonPackageUpdater
	return c.BuildPackageDependencyLineRegex(impactedName, impactedVersion, dependencyLineFormat)
}

func GetVulnerabilityLocations(vulnDetails *utils.VulnerabilityDetails, namesFilters []string, ignoreFilters []string) []string {
	var c CommonPackageUpdater
	return c.CollectVulnerabilityDescriptorPaths(vulnDetails, namesFilters, ignoreFilters)
}
