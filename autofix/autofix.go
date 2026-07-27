package autofix

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/jfrog/froggit-go/vcsclient"
	securitypkgupdaters "github.com/jfrog/jfrog-cli-security/remediation/sca/packageupdaters"
	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-client-go/utils/log"

	"github.com/jfrog/frogbot/v3/utils"
)

const (
	componentNameEnv    = "JF_COMPONENT_NAME"
	affectedVersionEnv  = "JF_AFFECTED_VERSION"
	fixVersionEnv       = "JF_FIX_VERSION"
	commitHashEnv       = "JF_COMMIT_HASH"
	autoFixBranchPrefix = "jfrog-auto-fix"
	autoFixBranchMaxLen = 255
)

type AutoFixCmd struct{}

func (a *AutoFixCmd) Run(repository utils.Repository, client vcsclient.VcsClient) error {
	componentName := os.Getenv(componentNameEnv)
	affectedVersion := os.Getenv(affectedVersionEnv)
	fixVersion := os.Getenv(fixVersionEnv)

	if err := validateInputs(componentName, affectedVersion, fixVersion); err != nil {
		return err
	}

	log.Info(fmt.Sprintf("Starting auto-fix for component '%s' (%s → %s) in %s/%s",
		componentName, affectedVersion, fixVersion,
		repository.Params.Git.RepoOwner, repository.Params.Git.RepoName))

	fixed, err := fixDependency(componentName, affectedVersion, fixVersion)
	if err != nil {
		return err
	}
	if !fixed {
		return nil
	}

	return openFixPullRequest(repository, client, componentName, affectedVersion, fixVersion)
}

func fixDependency(componentName, affectedVersion, fixVersion string) (bool, error) {
	workspaceDir, err := os.Getwd()
	if err != nil {
		return false, fmt.Errorf("failed to get current working directory: %w", err)
	}

	log.Info(fmt.Sprintf("Scanning project to locate '%s@%s' in dependency tree...", componentName, affectedVersion))
	descriptorPaths, tech, err := findDescriptorPaths(workspaceDir, componentName, affectedVersion)
	if err != nil {
		return false, err
	}
	if len(descriptorPaths) == 0 {
		log.Info(fmt.Sprintf("Component '%s@%s' was not found in the project dependency tree; skipping auto-fix", componentName, affectedVersion))
		return false, nil
	}
	if tech == techutils.NoTech {
		return false, fmt.Errorf("could not determine package manager for component '%s@%s'", componentName, affectedVersion)
	}

	updater, err := newUpdater(tech)
	if err != nil {
		return false, err
	}

	log.Info(fmt.Sprintf("Updating '%s' from %s to %s in %d file(s): %v",
		componentName, affectedVersion, fixVersion, len(descriptorPaths), descriptorPaths))
	if err = updater.UpdateDependency(buildFixDetails(componentName, affectedVersion, fixVersion, tech, descriptorPaths)); err != nil {
		return false, fmt.Errorf("failed to update dependency: %w", err)
	}
	log.Info(fmt.Sprintf("Successfully updated '%s' to %s", componentName, fixVersion))
	return true, nil
}

func openFixPullRequest(repository utils.Repository, client vcsclient.VcsClient, componentName, affectedVersion, fixVersion string) error {
	gitManager, err := utils.NewGitManager().
		SetAuth(repository.Params.Git.Username, repository.Params.Git.Token).
		SetLocalRepositoryAndRemoteName()
	if err != nil {
		return fmt.Errorf("failed to initialize git manager: %w", err)
	}
	gitManager = gitManager.SetGitParams(&repository.Params.Git)

	fixBranchName := generateAutoFixBranchName(componentName, fixVersion)

	existsInRemote, err := gitManager.BranchExistsInRemote(fixBranchName)
	if err != nil {
		return fmt.Errorf("failed to check if fix branch '%s' exists: %w", fixBranchName, err)
	}
	if existsInRemote {
		log.Info(fmt.Sprintf("Skipping fix pull request for dependency '%s' to version '%s': a fix branch already exists. If the pull request was previously closed, delete the fix branch to allow a new one to be created.",
			componentName, fixVersion))
		return nil
	}

	if err = gitManager.CreateBranchAndCheckout(fixBranchName, true); err != nil {
		return fmt.Errorf("failed to create fix branch '%s': %w", fixBranchName, err)
	}

	commitMessage := fmt.Sprintf("fix: update %s from %s to %s", componentName, affectedVersion, fixVersion)
	if err = gitManager.AddAllAndCommit(commitMessage, componentName); err != nil {
		var errNoChanges *utils.ErrNothingToCommit
		if errors.As(err, &errNoChanges) {
			log.Info(err.Error())
			return nil
		}
		return fmt.Errorf("failed to commit changes: %w", err)
	}

	if err = gitManager.Push(false, fixBranchName); err != nil {
		return fmt.Errorf("failed to push branch '%s': %w", fixBranchName, err)
	}
	log.Info(fmt.Sprintf("Branch '%s' pushed to origin", fixBranchName))

	baseBranch, err := resolveBaseBranch(repository)
	if err != nil {
		return err
	}
	prTitle := fmt.Sprintf("[Auto-Fix] Update %s to %s", componentName, fixVersion)
	log.Info(fmt.Sprintf("Creating pull request from '%s' to '%s'", fixBranchName, baseBranch))
	if err = client.CreatePullRequest(context.Background(),
		repository.Params.Git.RepoOwner, repository.Params.Git.RepoName,
		fixBranchName, baseBranch, prTitle, buildPRBody(componentName, affectedVersion, fixVersion)); err != nil {
		return fmt.Errorf("failed to create pull request: %w", err)
	}

	log.Info("Pull request created successfully")
	return nil
}

func resolveBaseBranch(repository utils.Repository) (string, error) {
	if len(repository.Params.Git.Branches) == 0 {
		return "", fmt.Errorf("no base branch provided. Please set the `JF_GIT_BASE_BRANCH` environment variable")
	}
	return repository.Params.Git.Branches[0], nil
}

func validateInputs(componentName, affectedVersion, fixVersion string) error {
	var missing []string
	if componentName == "" {
		missing = append(missing, componentNameEnv)
	}
	if affectedVersion == "" {
		missing = append(missing, affectedVersionEnv)
	}
	if fixVersion == "" {
		missing = append(missing, fixVersionEnv)
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing required environment variable(s): %s", strings.Join(missing, ", "))
	}
	return nil
}

func newUpdater(tech techutils.Technology) (securitypkgupdaters.PackageUpdater, error) {
	switch tech {
	case techutils.Maven:
		return &securitypkgupdaters.MavenPackageUpdater{}, nil
	case techutils.Npm:
		return &securitypkgupdaters.NpmPackageUpdater{}, nil
	case techutils.Pnpm:
		return &securitypkgupdaters.PnpmPackageUpdater{}, nil
	case techutils.Go:
		return &securitypkgupdaters.GoPackageUpdater{}, nil
	case techutils.Pip:
		return &securitypkgupdaters.PythonPackageUpdater{}, nil
	default:
		return nil, fmt.Errorf("unsupported technology '%s' for auto-fix", tech)
	}
}

func buildFixDetails(componentName, affectedVersion, fixVersion string, tech techutils.Technology, descriptorPaths []string) *securitypkgupdaters.FixDetails {
	evidences := make([]formats.Location, len(descriptorPaths))
	for i, path := range descriptorPaths {
		evidences[i] = formats.Location{File: path}
	}
	return &securitypkgupdaters.FixDetails{
		ImpactedDependencyName:    componentName,
		ImpactedDependencyVersion: affectedVersion,
		SuggestedFixedVersion:     fixVersion,
		IsDirectDependency:        true,
		Technology:                tech,
		Components: []formats.ComponentRow{
			{
				Name:      componentName,
				Version:   affectedVersion,
				Evidences: evidences,
			},
		},
	}
}

func buildPRBody(componentName, affectedVersion, fixVersion string) string {
	body := fmt.Sprintf(
		"This PR was automatically created by JFrog Frogbot auto-fix.\n\n"+
			"**Component:** `%s`\n"+
			"**Affected version:** `%s`\n"+
			"**Fix version:** `%s`\n",
		componentName, affectedVersion, fixVersion,
	)
	if commitHash := os.Getenv(commitHashEnv); commitHash != "" {
		body += fmt.Sprintf("**Scanned commit:** `%s`\n", commitHash)
	}
	return body
}

func generateAutoFixBranchName(componentName, fixVersion string) string {
	safe := strings.NewReplacer(":", "-", "/", "-", "@", "", " ", "-").Replace(componentName)
	branchName := fmt.Sprintf("%s/%s-%s", autoFixBranchPrefix, safe, fixVersion)
	if len(branchName) > autoFixBranchMaxLen {
		branchName = strings.TrimRight(branchName[:autoFixBranchMaxLen], "-/")
	}
	return branchName
}
