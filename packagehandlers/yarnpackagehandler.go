package packagehandlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	biUtils "github.com/jfrog/build-info-go/build/utils"
	"github.com/jfrog/frogbot/v2/utils"
	"github.com/jfrog/gofrog/version"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
)

const (
	yarnV2Version          = "2.0.0"
	yarnV1PackageUpdateCmd = "upgrade"
	yarnV2PackageUpdateCmd = "up"
	modulesFolderFlag      = "--modules-folder="
	yarnWorkspaceCmd       = "workspace"
)

// workspaceInfo holds the workspace root directory and the name of the current workspace package.
type workspaceInfo struct {
	rootDir     string
	packageName string
}

type YarnPackageHandler struct {
	CommonPackageHandler
}

func (yarn *YarnPackageHandler) UpdateDependency(vulnDetails *utils.VulnerabilityDetails) error {
	if vulnDetails.IsDirectDependency {
		return yarn.updateDirectDependency(vulnDetails)
	}
	return &utils.ErrUnsupportedFix{
		PackageName:  vulnDetails.ImpactedDependencyName,
		FixedVersion: vulnDetails.SuggestedFixedVersion,
		ErrorType:    utils.IndirectDependencyFixNotSupported,
	}
}

func (yarn *YarnPackageHandler) updateDirectDependency(vulnDetails *utils.VulnerabilityDetails) (err error) {
	wd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get current working directory: %w", err)
	}

	workspace, err := findYarnWorkspaceRoot(wd)
	if err != nil {
		return fmt.Errorf("failed to find yarn workspace root: %w", err)
	}

	// Version detection uses the workspace root's .yarnrc.yml when in a workspace,
	// otherwise falls back to the current directory and then the global binary.
	yarnrcSearchDir := wd
	if workspace != nil {
		yarnrcSearchDir = workspace.rootDir
	}
	isYarn1, executableYarnVersion, err := isYarnV1Project(yarnrcSearchDir)
	if err != nil {
		return fmt.Errorf("failed to detect yarn version: %w", err)
	}

	var installationCommand string
	var extraArgs []string

	if workspace != nil {
		// Move to the workspace root so yarn can locate the lock file and workspace config.
		if err = os.Chdir(workspace.rootDir); err != nil {
			return fmt.Errorf("failed to change directory to workspace root '%s': %w", workspace.rootDir, err)
		}
		defer func() {
			err = errors.Join(err, os.Chdir(wd))
		}()

		installationCommand = yarnWorkspaceCmd
		extraArgs = append(extraArgs, workspace.packageName)
		if isYarn1 {
			extraArgs = append(extraArgs, yarnV1PackageUpdateCmd)
			var tmpNodeModulesDir string
			tmpNodeModulesDir, err = fileutils.CreateTempDir()
			defer func() {
				err = errors.Join(err, fileutils.RemoveTempDir(tmpNodeModulesDir))
			}()
			if err != nil {
				return
			}
			extraArgs = append(extraArgs, modulesFolderFlag+tmpNodeModulesDir)
		} else {
			extraArgs = append(extraArgs, yarnV2PackageUpdateCmd)
		}
	} else {
		if isYarn1 {
			installationCommand = yarnV1PackageUpdateCmd
			// This dir is created to store node_modules that are created during updating packages in Yarn V1. This dir is to be deleted and not pushed into the PR
			var tmpNodeModulesDir string
			tmpNodeModulesDir, err = fileutils.CreateTempDir()
			defer func() {
				err = errors.Join(err, fileutils.RemoveTempDir(tmpNodeModulesDir))
			}()
			if err != nil {
				return
			}
			extraArgs = append(extraArgs, modulesFolderFlag+tmpNodeModulesDir)
		} else {
			installationCommand = yarnV2PackageUpdateCmd
		}
	}

	err = yarn.CommonPackageHandler.UpdateDependency(vulnDetails, installationCommand, extraArgs...)
	if err != nil {
		err = fmt.Errorf("running 'yarn %s' for '%s' failed: %w\nHint: The Yarn version that was used is: %s. If your project was built with a different major version of Yarn, please configure your CI runner to include it",
			installationCommand,
			vulnDetails.ImpactedDependencyName,
			err,
			executableYarnVersion)
	}
	return
}

// findYarnWorkspaceRoot walks up from startDir looking for a parent directory whose
// package.json declares a "workspaces" field. Returns nil if startDir is not inside
// a Yarn workspace.
func findYarnWorkspaceRoot(startDir string) (*workspaceInfo, error) {
	currentDir := startDir
	for {
		parentDir := filepath.Dir(currentDir)
		if parentDir == currentDir {
			// Reached the filesystem root without finding a workspace.
			return nil, nil
		}

		pkgJsonPath := filepath.Join(parentDir, "package.json")
		data, err := os.ReadFile(pkgJsonPath)
		if os.IsNotExist(err) {
			currentDir = parentDir
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("failed to read '%s': %w", pkgJsonPath, err)
		}

		var rootPkg struct {
			Workspaces json.RawMessage `json:"workspaces"`
		}
		if jsonErr := json.Unmarshal(data, &rootPkg); jsonErr != nil || rootPkg.Workspaces == nil {
			currentDir = parentDir
			continue
		}

		// Found a workspace root. Read the package name from startDir's own package.json.
		wsPkgJsonPath := filepath.Join(startDir, "package.json")
		wsPkgData, err := os.ReadFile(wsPkgJsonPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read workspace package descriptor at '%s': %w", wsPkgJsonPath, err)
		}
		var wsPkg struct {
			Name string `json:"name"`
		}
		if err = json.Unmarshal(wsPkgData, &wsPkg); err != nil {
			return nil, fmt.Errorf("failed to parse workspace package descriptor at '%s': %w", wsPkgJsonPath, err)
		}
		if wsPkg.Name == "" {
			return nil, fmt.Errorf("workspace package at '%s' is missing a 'name' field in package.json", startDir)
		}

		return &workspaceInfo{rootDir: parentDir, packageName: wsPkg.Name}, nil
	}
}

// getYarnVersionFromYarnrc parses the yarnPath entry from a .yarnrc.yml file in dir
// and extracts the version string from the filename (e.g. "yarn-3.4.1.cjs" → "3.4.1").
// Returns an empty string when no yarnPath entry is present or the file does not exist.
func getYarnVersionFromYarnrc(dir string) (string, error) {
	yarnrcPath := filepath.Join(dir, ".yarnrc.yml")
	data, err := os.ReadFile(yarnrcPath)
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("failed to read '%s': %w", yarnrcPath, err)
	}

	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "yarnPath:") {
			continue
		}
		parts := strings.SplitN(trimmed, ":", 2)
		if len(parts) != 2 {
			continue
		}
		// Extract the version from a path like ".yarn/releases/yarn-3.4.1.cjs".
		base := strings.TrimSpace(parts[1])
		base = filepath.Base(base)
		base = strings.TrimPrefix(base, "yarn-")
		for _, suffix := range []string{".cjs", ".js"} {
			base = strings.TrimSuffix(base, suffix)
		}
		if strings.ContainsRune(base, '.') {
			return base, nil
		}
	}
	return "", nil
}

// isYarnV1Project reports whether the project uses Yarn v1.
// It first tries to read the version from .yarnrc.yml in searchDir, then falls back
// to the globally installed yarn binary.
func isYarnV1Project(searchDir string) (bool, string, error) {
	yarnVersion, err := getYarnVersionFromYarnrc(searchDir)
	if err != nil {
		return false, "", fmt.Errorf("failed to read .yarnrc.yml: %w", err)
	}
	if yarnVersion == "" {
		// NOTICE: if the global yarn version is 1.x this will always return true even
		// if the project targets a higher version. Use .yarnrc.yml yarnPath to avoid this.
		yarnVersion, err = biUtils.GetVersion("yarn", "")
		if err != nil {
			return false, "", fmt.Errorf("failed to get yarn version: %w", err)
		}
	}
	log.Info("Using Yarn version: ", yarnVersion)
	isYarn1 := version.NewVersion(yarnVersion).Compare(yarnV2Version) > 0
	return isYarn1, yarnVersion, nil
}
