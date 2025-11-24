package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

type buildTarget struct {
	pkg           string
	goos          string
	goarch        string
	fileExtension string
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: builder <version>")
		os.Exit(1)
	}

	version := os.Args[1]
	pkgPath := "ecosys-frogbot/v2"

	// All build targets
	targets := []buildTarget{
		{"frogbot-linux-386", "linux", "386", ""},
		{"frogbot-linux-amd64", "linux", "amd64", ""},
		{"frogbot-linux-s390x", "linux", "s390x", ""},
		{"frogbot-linux-arm64", "linux", "arm64", ""},
		{"frogbot-linux-arm", "linux", "arm", ""},
		{"frogbot-linux-ppc64", "linux", "ppc64", ""},
		{"frogbot-linux-ppc64le", "linux", "ppc64le", ""},
		{"frogbot-mac-386", "darwin", "amd64", ""},
		{"frogbot-mac-arm64", "darwin", "arm64", ""},
		{"frogbot-windows-amd64", "windows", "amd64", ".exe"},
	}

	// Build linux-386 first and verify version
	fmt.Println("Building and verifying linux-386 first...")
	if err := buildAndUpload(targets[0], version, pkgPath, true); err != nil {
		fmt.Fprintf(os.Stderr, "Error building linux-386: %v\n", err)
		os.Exit(1)
	}

	// Build remaining targets in parallel (all at once!)
	fmt.Printf("\nBuilding remaining %d targets in parallel...\n\n", len(targets)-1)

	var wg sync.WaitGroup
	errorsChan := make(chan error, len(targets)-1)

	// Launch all builds concurrently
	for i := 1; i < len(targets); i++ {
		wg.Add(1)
		go func(target buildTarget) {
			defer wg.Done()
			if err := buildAndUpload(target, version, pkgPath, false); err != nil {
				errorsChan <- fmt.Errorf("%s: %w", target.pkg, err)
			}
		}(targets[i])
	}

	// Wait for all builds to complete
	wg.Wait()
	close(errorsChan)

	// Collect errors
	var errors []string
	for err := range errorsChan {
		errors = append(errors, err.Error())
	}

	if len(errors) > 0 {
		fmt.Fprintln(os.Stderr, "\nBuild errors occurred:")
		for _, err := range errors {
			fmt.Fprintf(os.Stderr, "  - %s\n", err)
		}
		os.Exit(1)
	}

	// Upload the getFrogbot.sh script
	fmt.Println("\nUploading getFrogbot.sh...")
	if err := uploadFile("./buildscripts/getFrogbot.sh", fmt.Sprintf("%s/%s/", pkgPath, version)); err != nil {
		fmt.Fprintf(os.Stderr, "Error uploading getFrogbot.sh: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("\n✅ All builds completed successfully!")
}

func buildAndUpload(target buildTarget, version, pkgPath string, verify bool) error {
	exeName := "frogbot" + target.fileExtension

	// Build
	if err := build(target, exeName, version); err != nil {
		return fmt.Errorf("build failed: %w", err)
	}

	// Verify version (only for linux-386)
	if verify {
		if err := verifyVersion(exeName, version); err != nil {
			return fmt.Errorf("version verification failed: %w", err)
		}
	}

	// Upload
	destPath := fmt.Sprintf("%s/%s/%s/%s", pkgPath, version, target.pkg, exeName)
	if err := upload(exeName, destPath); err != nil {
		return fmt.Errorf("upload failed: %w", err)
	}

	return nil
}

func build(target buildTarget, exeName, version string) error {
	fmt.Printf("🔨 Building %s for %s-%s...\n", exeName, target.goos, target.goarch)

	ldflags := fmt.Sprintf("-w -extldflags \"-static\" -X github.com/jfrog/frogbot/v2/utils.FrogbotVersion=%s", version)

	cmd := exec.Command("jf", "go", "build", "-o", exeName, "-ldflags", ldflags)
	cmd.Env = append(os.Environ(),
		"CGO_ENABLED=0",
		"GOOS="+target.goos,
		"GOARCH="+target.goarch,
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return err
	}

	// Make executable
	if err := os.Chmod(exeName, 0755); err != nil {
		return fmt.Errorf("chmod failed: %w", err)
	}

	fmt.Printf("✅ Built %s\n", exeName)
	return nil
}

func verifyVersion(exeName, expectedVersion string) error {
	fmt.Println("🔍 Verifying version matches...")

	cmd := exec.Command("./"+exeName, "-v")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to run -v: %w", err)
	}

	outputStr := strings.TrimSpace(string(output))
	fmt.Printf("Output: %s\n", outputStr)

	// Get the version which is after the last space
	parts := strings.Fields(outputStr)
	if len(parts) == 0 {
		return fmt.Errorf("unexpected version output format")
	}
	builtVersion := parts[len(parts)-1]

	if builtVersion != expectedVersion {
		return fmt.Errorf("versions don't match. Provided: %s, Actual: %s", expectedVersion, builtVersion)
	}

	fmt.Println("✅ Versions match")
	return nil
}

func upload(sourcePath, destPath string) error {
	fmt.Printf("📦 Uploading %s to %s...\n", sourcePath, destPath)

	cmd := exec.Command("jf", "rt", "u", sourcePath, destPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return err
	}

	// Clean up the built binary after upload
	if err := os.Remove(sourcePath); err != nil {
		// Don't fail if cleanup fails
		fmt.Printf("Warning: failed to remove %s: %v\n", sourcePath, err)
	}

	fmt.Printf("✅ Uploaded %s\n", filepath.Base(sourcePath))
	return nil
}

func uploadFile(sourcePath, destPath string) error {
	fmt.Printf("📦 Uploading %s to %s...\n", sourcePath, destPath)

	cmd := exec.Command("jf", "rt", "u", sourcePath, destPath, "--flat")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}
