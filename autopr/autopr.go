package autopr

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
	"github.com/jfrog/frogbot/v3/utils/outputwriter"
)

const (
	componentNameEnv   = "JF_COMPONENT_NAME"
	affectedVersionEnv = "JF_AFFECTED_VERSION"
	fixVersionEnv      = "JF_FIX_VERSION"
	commitHashEnv      = "JF_COMMIT_HASH"
)

// ErrAutoPrSkipped is returned when auto-pr cannot proceed but the situation is not fatal
// (e.g. component not found, fix branch already exists). Callers can distinguish it from real failures.
type ErrAutoPrSkipped struct {
	Reason string
}

func (e *ErrAutoPrSkipped) Error() string {
	return fmt.Sprintf("auto-pr skipped: %s", e.Reason)
}

type AutoPrCmd struct{}

func (a *AutoPrCmd) Run(repository utils.Repository, client vcsclient.VcsClient) error {
	componentName := os.Getenv(componentNameEnv)
	affectedVersion := os.Getenv(affectedVersionEnv)
	fixVersion := os.Getenv(fixVersionEnv)

	if err := validateInputs(componentName, affectedVersion, fixVersion); err != nil {
		return err
	}

	log.Info(fmt.Sprintf("Starting auto-pr for component '%s' (%s → %s) in %s/%s",
		componentName, affectedVersion, fixVersion,
		repository.Params.Git.RepoOwner, repository.Params.Git.RepoName))

	// Base branch is validated by getconfiguration.setDefaultsIfNeeded before Run is invoked.
	baseBranch := repository.Params.Git.Branches[0]

	gitManager, err := utils.NewGitManager().
		SetAuth(repository.Params.Git.Username, repository.Params.Git.Token).
		SetLocalRepositoryAndRemoteName()
	if err != nil {
		return fmt.Errorf("failed to initialize git manager: %w", err)
	}
	gitManager = gitManager.SetGitParams(&repository.Params.Git)

	customTemplates, err := utils.LoadCustomTemplates(
		repository.ConfigProfile.FrogbotConfig.CommitMessageTemplate,
		repository.ConfigProfile.FrogbotConfig.BranchNameTemplate,
		repository.ConfigProfile.FrogbotConfig.PrTitleTemplate,
	)
	if err != nil {
		return fmt.Errorf("failed to load custom templates: %w", err)
	}
	gitManager = gitManager.SetCustomTemplates(customTemplates)

	fixBranchName, err := gitManager.GenerateFixBranchName(baseBranch, componentName, fixVersion)
	if err != nil {
		return fmt.Errorf("failed to generate fix branch name: %w", err)
	}

	existsInRemote, err := gitManager.BranchExistsInRemote(fixBranchName)
	if err != nil {
		return fmt.Errorf("failed to check if fix branch '%s' exists: %w", fixBranchName, err)
	}
	if existsInRemote {
		return &ErrAutoPrSkipped{Reason: fmt.Sprintf(
			"a fix branch '%s' already exists for '%s' to version '%s'. If the pull request was previously closed, delete the fix branch to allow a new one to be created.",
			fixBranchName, componentName, fixVersion)}
	}

	workspaceDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get current working directory: %w", err)
	}
	descriptorPaths, tech, isDirect, err := findDescriptorPaths(workspaceDir, componentName, affectedVersion)
	if err != nil {
		return err
	}
	if len(descriptorPaths) == 0 {
		return &ErrAutoPrSkipped{Reason: fmt.Sprintf("component '%s@%s' was not found in the project dependency tree", componentName, affectedVersion)}
	}
	if tech == techutils.NoTech {
		return fmt.Errorf("could not determine package manager for component '%s@%s'", componentName, affectedVersion)
	}
	if !isDirect {
		// Updaters generally cannot fix transitive dependencies via a simple manifest change.
		return fmt.Errorf("component '%s@%s' is a transitive dependency; auto-pr only supports direct dependencies", componentName, affectedVersion)
	}

	if err = gitManager.CreateBranchAndCheckout(fixBranchName, false); err != nil {
		return fmt.Errorf("failed to create fix branch '%s': %w", fixBranchName, err)
	}

	if err = runUpdater(componentName, affectedVersion, fixVersion, tech, isDirect, descriptorPaths); err != nil {
		return err
	}

	if err = utils.CleanUntrackedFiles(workspaceDir); err != nil {
		log.Warn(fmt.Sprintf("failed to clean untracked files from '%s': %s", workspaceDir, err.Error()))
	}

	commitMessage := gitManager.GenerateCommitMessage(componentName, fixVersion)
	if err = gitManager.AddAllAndCommit(commitMessage, componentName); err != nil {
		var errNoChanges *utils.ErrNothingToCommit
		if errors.As(err, &errNoChanges) {
			log.Info(err.Error())
			return &ErrAutoPrSkipped{Reason: err.Error()}
		}
		return fmt.Errorf("failed to commit changes: %w", err)
	}

	if err = gitManager.Push(false, fixBranchName); err != nil {
		return fmt.Errorf("failed to push branch '%s': %w", fixBranchName, err)
	}
	log.Info(fmt.Sprintf("Branch '%s' pushed to origin", fixBranchName))

	prTitle := gitManager.GeneratePullRequestTitle(componentName, fixVersion)
	prBody := buildPRBody(repository, componentName, affectedVersion, fixVersion, tech, descriptorPaths)
	log.Info(fmt.Sprintf("Creating pull request from '%s' to '%s'", fixBranchName, baseBranch))
	if err = client.CreatePullRequest(context.Background(),
		repository.Params.Git.RepoOwner, repository.Params.Git.RepoName,
		fixBranchName, baseBranch, prTitle, prBody); err != nil {
		return fmt.Errorf("failed to create pull request: %w", err)
	}

	log.Info("Pull request created successfully")
	return nil
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

func runUpdater(componentName, affectedVersion, fixVersion string, tech techutils.Technology, isDirect bool, descriptorPaths []string) error {
	fixDetails := buildFixDetails(componentName, affectedVersion, fixVersion, tech, isDirect, descriptorPaths)
	updater, supported := securitypkgupdaters.GetCompatiblePackageUpdater(fixDetails)
	if !supported {
		return fmt.Errorf("unsupported technology '%s' for auto-pr", tech)
	}
	log.Info(fmt.Sprintf("Updating '%s' from %s to %s in %d file(s): %v",
		componentName, affectedVersion, fixVersion, len(descriptorPaths), descriptorPaths))
	if err := updater.UpdateDependency(fixDetails); err != nil {
		return fmt.Errorf("failed to update dependency: %w", err)
	}
	log.Info(fmt.Sprintf("Successfully updated '%s' to %s", componentName, fixVersion))
	return nil
}

func buildFixDetails(componentName, affectedVersion, fixVersion string, tech techutils.Technology, isDirect bool, descriptorPaths []string) *securitypkgupdaters.FixDetails {
	evidences := make([]formats.Location, len(descriptorPaths))
	for i, path := range descriptorPaths {
		evidences[i] = formats.Location{File: path}
	}
	return &securitypkgupdaters.FixDetails{
		ImpactedDependencyName:    componentName,
		ImpactedDependencyVersion: affectedVersion,
		SuggestedFixedVersion:     fixVersion,
		IsDirectDependency:        isDirect,
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

// buildPRBody reuses the standard fix-PR content produced by scan-repository so auto-pr messages
// stay consistent with the rest of Frogbot.
func buildPRBody(repository utils.Repository, componentName, affectedVersion, fixVersion string, tech techutils.Technology, descriptorPaths []string) string {
	writer := repository.OutputWriter
	if writer == nil {
		writer = outputwriter.GetCompatibleOutputWriter(repository.Params.Git.GitProvider, false)
	}
	componentRow := formats.ComponentRow{Name: componentName, Version: affectedVersion}
	rootRow := formats.ComponentRow{Name: repository.Params.Git.RepoName, Version: ""}
	row := formats.VulnerabilityOrViolationRow{
		ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
			ImpactedDependencyName:    componentName,
			ImpactedDependencyVersion: affectedVersion,
			Components:                buildComponentRows(componentName, affectedVersion, descriptorPaths),
		},
		FixedVersions: []string{fixVersion},
		ImpactPaths:   [][]formats.ComponentRow{{rootRow, componentRow}},
		Technology:    tech,
	}
	description, _ := utils.GenerateFixPullRequestDetails([]formats.VulnerabilityOrViolationRow{row}, "", writer)
	if commitHash := os.Getenv(commitHashEnv); commitHash != "" {
		description += outputwriter.MarkdownComment(fmt.Sprintf("Scanned commit: %s", commitHash))
	}
	return description
}

func buildComponentRows(componentName, affectedVersion string, descriptorPaths []string) []formats.ComponentRow {
	evidences := make([]formats.Location, len(descriptorPaths))
	for i, path := range descriptorPaths {
		evidences[i] = formats.Location{File: path}
	}
	return []formats.ComponentRow{{
		Name:      componentName,
		Version:   affectedVersion,
		Evidences: evidences,
	}}
}
