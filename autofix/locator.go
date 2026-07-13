package autofix

import (
	"fmt"
	"strings"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/jfrog/jfrog-cli-security/sca/bom/xrayplugin"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
)

func findDescriptorPaths(workspaceDir, componentName, affectedVersion string) ([]string, techutils.Technology, error) {
	log.Debug("Preparing Xray-Lib plugin for dependency tree analysis")
	generator := xrayplugin.NewXrayLibBomGenerator()
	if err := generator.PrepareGenerator(); err != nil {
		return nil, techutils.NoTech, fmt.Errorf("failed to prepare Xray-Lib plugin: %w", err)
	}

	log.Debug(fmt.Sprintf("Generating SBOM for workspace: %s", workspaceDir))
	sbom, err := generator.GenerateSbom(results.ScanTarget{Target: workspaceDir})
	if err != nil {
		return nil, techutils.NoTech, fmt.Errorf("failed to generate SBOM: %w", err)
	}
	if sbom.Components != nil {
		log.Debug(fmt.Sprintf("SBOM generated with %d components", len(*sbom.Components)))
	}

	log.Debug(fmt.Sprintf("Searching SBOM for '%s@%s'", componentName, affectedVersion))
	paths, tech, err := extractDescriptorPaths(sbom, componentName, affectedVersion)
	if err != nil {
		return nil, techutils.NoTech, err
	}
	if len(paths) == 0 {
		log.Warn(fmt.Sprintf("Component '%s@%s' was not found in the SBOM", componentName, affectedVersion))
		return nil, techutils.NoTech, nil
	}
	log.Info(fmt.Sprintf("Found '%s@%s' (%s) in %d descriptor file(s): %v", componentName, affectedVersion, tech, len(paths), paths))
	return paths, tech, nil
}

func extractDescriptorPaths(sbom *cyclonedx.BOM, componentName, affectedVersion string) ([]string, techutils.Technology, error) {
	if sbom == nil || sbom.Components == nil {
		return nil, techutils.NoTech, fmt.Errorf("SBOM is empty")
	}

	normalise := func(name string) string {
		return strings.ReplaceAll(name, ":", "/")
	}
	normaliseComponentName := normalise(componentName)

	seen := map[string]bool{}
	var paths []string
	tech := techutils.NoTech

	for _, component := range *sbom.Components {
		compName, compVersion, compType := techutils.SplitPackageURL(component.PackageURL)
		log.Debug(fmt.Sprintf("Inspecting SBOM component: %s@%s (type: %s)", compName, compVersion, compType))

		if normalise(compName) != normaliseComponentName || compVersion != affectedVersion {
			continue
		}
		log.Debug(fmt.Sprintf("Matched component '%s@%s' — checking evidence occurrences", compName, compVersion))

		if tech == techutils.NoTech {
			tech = techutils.ToTechnology(compType)
		}

		if component.Evidence == nil || component.Evidence.Occurrences == nil {
			log.Debug(fmt.Sprintf("Component '%s@%s' has no evidence occurrences, skipping", compName, compVersion))
			continue
		}
		for _, occurrence := range *component.Evidence.Occurrences {
			if occurrence.Location == "" {
				continue
			}
			if seen[occurrence.Location] {
				log.Debug(fmt.Sprintf("Skipping duplicate occurrence location: %s", occurrence.Location))
				continue
			}
			seen[occurrence.Location] = true
			paths = append(paths, occurrence.Location)
			log.Debug(fmt.Sprintf("Found descriptor: %s", occurrence.Location))
		}
	}
	return paths, tech, nil
}
