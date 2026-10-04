package autopr

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/jfrog/jfrog-cli-security/sca/bom/buildinfo/technologies/python"
	"github.com/jfrog/jfrog-cli-security/sca/bom/xrayplugin"
	"github.com/jfrog/jfrog-cli-security/utils/formats/cdxutils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
)

// componentMatch collects data extracted from the SBOM for a matched component.
type componentMatch struct {
	descriptorPaths  []string
	purlType         string
	isDirectFromRoot bool
}

func findDescriptorPaths(workspaceDir, componentName, affectedVersion string) ([]string, techutils.Technology, bool, error) {
	log.Debug("Preparing Xray-Lib plugin for dependency tree analysis")
	generator := xrayplugin.NewXrayLibBomGenerator()
	if err := generator.PrepareGenerator(); err != nil {
		return nil, techutils.NoTech, false, fmt.Errorf("failed to prepare Xray-Lib plugin: %w", err)
	}

	log.Debug(fmt.Sprintf("Generating SBOM for workspace: %s", workspaceDir))
	sbom, err := generator.GenerateSbom(results.ScanTarget{Target: workspaceDir})
	if err != nil {
		return nil, techutils.NoTech, false, fmt.Errorf("failed to generate SBOM: %w", err)
	}
	if sbom.Components != nil {
		log.Debug(fmt.Sprintf("SBOM generated with %d components", len(*sbom.Components)))
	}

	log.Debug(fmt.Sprintf("Searching SBOM for '%s@%s'", componentName, affectedVersion))
	match, err := extractComponentMatch(sbom, componentName, affectedVersion)
	if err != nil {
		return nil, techutils.NoTech, false, err
	}
	if len(match.descriptorPaths) == 0 {
		log.Warn(fmt.Sprintf("Component '%s@%s' was not found in the SBOM", componentName, affectedVersion))
		return nil, techutils.NoTech, false, nil
	}

	tech := resolveTechnology(match.purlType, workspaceDir, match.descriptorPaths)
	log.Info(fmt.Sprintf("Found '%s@%s' (%s, direct=%t) in %d descriptor file(s): %v",
		componentName, affectedVersion, tech, match.isDirectFromRoot, len(match.descriptorPaths), match.descriptorPaths))
	return match.descriptorPaths, tech, match.isDirectFromRoot, nil
}

func extractComponentMatch(sbom *cyclonedx.BOM, componentName, affectedVersion string) (componentMatch, error) {
	empty := componentMatch{}
	if sbom == nil || sbom.Components == nil {
		return empty, fmt.Errorf("SBOM is empty")
	}

	bomIndex := cdxutils.NewBOMIndex(sbom, true)
	match := componentMatch{}
	var directPaths, transitivePaths []string
	directSeen, transitiveSeen := map[string]bool{}, map[string]bool{}

	for _, component := range *sbom.Components {
		compName, compVersion, compType := techutils.SplitPackageURL(component.PackageURL)
		log.Debug(fmt.Sprintf("Inspecting SBOM component: %s@%s (type: %s)", compName, compVersion, compType))

		if !componentNamesMatch(componentName, compName, compType) || compVersion != affectedVersion {
			continue
		}
		log.Debug(fmt.Sprintf("Matched component '%s@%s' — checking evidence occurrences", compName, compVersion))

		if match.purlType == "" {
			match.purlType = compType
		}
		relation := bomIndex.GetComponentRelation(component.BOMRef)
		isDirect := relation == cdxutils.RootRelation || relation == cdxutils.DirectRelation
		if isDirect {
			match.isDirectFromRoot = true
		}

		for _, location := range results.CdxEvidencesToLocations(component) {
			if location.File == "" {
				continue
			}
			if isDirect {
				if directSeen[location.File] {
					continue
				}
				directSeen[location.File] = true
				directPaths = append(directPaths, location.File)
			} else {
				if transitiveSeen[location.File] {
					continue
				}
				transitiveSeen[location.File] = true
				transitivePaths = append(transitivePaths, location.File)
			}
			log.Debug(fmt.Sprintf("Found descriptor: %s", location.File))
		}
	}
	match.descriptorPaths = directPaths
	if !match.isDirectFromRoot {
		match.descriptorPaths = transitivePaths
	}
	return match, nil
}

// resolveTechnology maps a PURL type to a package manager, disambiguating ambiguous
// types (npm, python, maven) by inspecting the workspace.
func resolveTechnology(purlType, workspaceDir string, descriptorPaths []string) techutils.Technology {
	if tech := techutils.CdxPackageTypeToTechnology(purlType); tech != techutils.NoTech {
		return tech
	}
	switch strings.ToLower(purlType) {
	case string(techutils.Npm):
		if isPnpmWorkspace(workspaceDir, descriptorPaths) {
			return techutils.Pnpm
		}
		if isYarnWorkspace(workspaceDir, descriptorPaths) {
			return techutils.Yarn
		}
		return techutils.Npm
	case techutils.Pypi:
		if isUvWorkspace(workspaceDir, descriptorPaths) {
			return techutils.Uv
		}
		return techutils.Pip
	case techutils.Maven.String():
		return techutils.Maven
	}
	return techutils.NoTech
}

func isPnpmWorkspace(workspaceDir string, descriptorPaths []string) bool {
	return hasMarker(workspaceDir, descriptorPaths, "pnpm-lock.yaml", "pnpm-workspace.yaml")
}

func isYarnWorkspace(workspaceDir string, descriptorPaths []string) bool {
	return hasMarker(workspaceDir, descriptorPaths, "yarn.lock", ".yarnrc.yml", ".yarnrc", ".yarn")
}

func isUvWorkspace(workspaceDir string, descriptorPaths []string) bool {
	return hasMarker(workspaceDir, descriptorPaths, "uv.lock")
}

// hasMarker reports whether the workspace or any descriptor directory contains one of the given marker files.
func hasMarker(workspaceDir string, descriptorPaths []string, markers ...string) bool {
	candidates := []string{workspaceDir}
	for _, path := range descriptorPaths {
		if !filepath.IsAbs(path) {
			path = filepath.Join(workspaceDir, path)
		}
		candidates = append(candidates, filepath.Dir(path))
	}
	for _, dir := range candidates {
		for _, marker := range markers {
			if _, err := os.Stat(filepath.Join(dir, marker)); err == nil {
				return true
			}
		}
	}
	return false
}

// componentNamesMatch compares a user-supplied component name with a PURL name.
// Maven coordinates may use ":" or "/"; PyPI names are case-insensitive and treat "-", "_", "." as equivalent.
func componentNamesMatch(input, fromPurl, purlType string) bool {
	switch strings.ToLower(purlType) {
	case techutils.Pypi:
		return python.NormalizePypiName(input) == python.NormalizePypiName(fromPurl)
	case techutils.Maven.String():
		return strings.ReplaceAll(input, ":", "/") == strings.ReplaceAll(fromPurl, ":", "/")
	default:
		return input == fromPurl
	}
}
