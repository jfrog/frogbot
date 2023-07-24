package utils

import (
	"errors"
	"fmt"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing/protocol/packp/capability"
	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/plumbing/transport/client"
	"github.com/jfrog/froggit-go/vcsutils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/format/gitignore"
	"github.com/go-git/go-git/v5/plumbing/object"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
)

const (
	refFormat = "refs/heads/%s:refs/heads/%[1]s"

	// Timout is seconds for the git operations performed by the go-git client.
	goGitTimeoutSeconds = 120

	// Https clone url formats for each service provider
	githubHttpsFormat          = "%s/%s/%s.git"
	gitLabHttpsFormat          = "%s/%s/%s.git"
	bitbucketServerHttpsFormat = "%s/scm/%s/%s.git"
	azureDevopsHttpsFormat     = "https://%s@%s%s/_git/%s"
)

type GitManager struct {
	// repository represents a git repository as a .git dir.
	repository *git.Repository
	// remoteName is name of the Git remote server
	remoteName string
	// The authentication struct consisting a username/password
	auth *githttp.BasicAuth
	// dryRun is used for testing purposes, mocking part of the git commands that requires networking
	dryRun bool
	// When dryRun is enabled, dryRunRepoPath specifies the repository local path to clone
	dryRunRepoPath string
	// When dryRun is enabled, skipClone allows skipping the cloning of a repository for testing purposes
	SkipClone bool
	// Custom naming formats
	customTemplates CustomTemplates
	// Git details
	git *Git
}

type CustomTemplates struct {
	// New commit message template
	commitMessageTemplate string
	// New branch name template
	branchNameTemplate string
	// New pull request title template
	pullRequestTitleTemplate string
}

func NewGitManager(dryRun bool, clonedRepoPath, projectPath, remoteName, token, username string, g *Git) (*GitManager, error) {
	setGoGitCustomClient()
	repository, err := git.PlainOpen(projectPath)
	if err != nil {
		return nil, fmt.Errorf(".git folder was not found in the following path: %s. git error:\n%s", projectPath, err.Error())
	}
	basicAuth := toBasicAuth(token, username)
	templates, err := loadCustomTemplates(g.CommitMessageTemplate, g.BranchNameTemplate, g.PullRequestTitleTemplate)
	if err != nil {
		return nil, err
	}
	return &GitManager{repository: repository, dryRunRepoPath: clonedRepoPath, remoteName: remoteName, auth: basicAuth, dryRun: dryRun, customTemplates: templates, git: g}, nil
}

func (gm *GitManager) CheckoutLocalBranch(branchName string) error {
	err := gm.createBranchAndCheckout(branchName, false)
	if err != nil {
		err = fmt.Errorf("'git checkout %s' failed with error: %s", branchName, err.Error())
	}
	log.Debug("Running git checkout to local branch:", branchName)
	return err
}

func (gm *GitManager) Clone(destinationPath, branchName string) error {
	if gm.dryRun {
		// "Clone" the repository from the testdata folder
		return gm.dryRunClone(destinationPath)
	}
	gitRemoteUrl, err := gm.getRemoteUrl()
	if err != nil {
		return err
	}
	transport.UnsupportedCapabilities = []capability.Capability{
		capability.ThinPack,
	}
	if branchName == "" {
		log.Debug("Since no branch name was set, assuming 'master' as the default branch")
		branchName = "master"
	}
	log.Debug(fmt.Sprintf("Cloning repository with these details:\nClone url: %s remote name: %s, branch: %s", gitRemoteUrl, gm.remoteName, getFullBranchName(branchName)))
	cloneOptions := &git.CloneOptions{
		URL:           gitRemoteUrl,
		Auth:          gm.auth,
		RemoteName:    gm.remoteName,
		ReferenceName: getFullBranchName(branchName),
	}
	repo, err := git.PlainClone(destinationPath, false, cloneOptions)
	if err != nil {
		return fmt.Errorf("'git clone %s from %s' failed with error: %s", branchName, gitRemoteUrl, err.Error())
	}
	gm.repository = repo
	log.Debug(fmt.Sprintf("Project cloned from %s to %s", gitRemoteUrl, destinationPath))
	return nil
}

func (gm *GitManager) getRemoteUrl() (string, error) {
	// Gets the remote repo url from the current .git dir
	gitRemote, err := gm.repository.Remote(gm.remoteName)
	if err != nil {
		return "", fmt.Errorf("'git remote %s' failed with error: %s", gm.remoteName, err.Error())
	}
	if len(gitRemote.Config().URLs) < 1 {
		return "", errors.New("failed to find git remote URL")
	}
	remoteUrl := gitRemote.Config().URLs[0]
	if strings.HasPrefix(remoteUrl, "https://") {
		return remoteUrl, nil
	}
	// Handle SSH clone urls
	return gm.generateHTTPSCloneUrl()
}

func (gm *GitManager) CreateBranchAndCheckout(branchName string) error {
	log.Debug("Creating branch", branchName, "...")
	err := gm.createBranchAndCheckout(branchName, true)
	if err != nil {
		// Don't fail on dryRuns as we operate on local repositories,branch could be existing.
		if gm.dryRun {
			return nil
		}
		err = fmt.Errorf("git create and checkout failed with error: %s", err.Error())
	}
	return err
}

func (gm *GitManager) createBranchAndCheckout(branchName string, create bool) error {
	checkoutConfig := &git.CheckoutOptions{
		Create: create,
		Branch: getFullBranchName(branchName),
		Force:  true,
	}
	worktree, err := gm.repository.Worktree()
	if err != nil {
		return err
	}
	return worktree.Checkout(checkoutConfig)
}

func (gm *GitManager) AddAllAndCommit(commitMessage string) error {
	log.Debug("Running git add all and commit...")
	err := gm.addAll()
	if err != nil {
		return err
	}
	return gm.commit(commitMessage)
}

func (gm *GitManager) addAll() error {
	worktree, err := gm.repository.Worktree()
	if err != nil {
		return err
	}

	// AddWithOptions doesn't exclude files in .gitignore, so we add their contents as exclusions explicitly.
	ignorePatterns, err := gitignore.ReadPatterns(worktree.Filesystem, nil)
	if err != nil {
		return err
	}
	worktree.Excludes = append(worktree.Excludes, ignorePatterns...)
	status, err := worktree.Status()
	if err != nil {
		return err
	}

	err = worktree.AddWithOptions(&git.AddOptions{All: true})
	if err != nil {
		return fmt.Errorf("git add failed with error: %s", err.Error())
	}
	// go-git add all using AddWithOptions doesn't include deleted files, that's why we need to double-check
	for fileName, fileStatus := range status {
		if fileStatus.Worktree == git.Deleted {
			_, err = worktree.Add(fileName)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (gm *GitManager) commit(commitMessage string) error {
	worktree, err := gm.repository.Worktree()
	if err != nil {
		return err
	}
	_, err = worktree.Commit(commitMessage, &git.CommitOptions{
		Author: &object.Signature{
			Name:  frogbotAuthorName,
			Email: gm.git.EmailAuthor,
			When:  time.Now(),
		},
	})
	if err != nil {
		err = fmt.Errorf("git commit failed with error: %s", err.Error())
	}
	return err
}

func (gm *GitManager) BranchExistsInRemote(branchName string) (bool, error) {
	if gm.dryRun {
		return false, nil
	}
	remote, err := gm.repository.Remote(gm.remoteName)
	if err != nil {
		return false, errorutils.CheckError(err)
	}
	refList, err := remote.List(&git.ListOptions{Auth: gm.auth})
	if err != nil {
		return false, errorutils.CheckError(err)
	}
	refName := plumbing.NewBranchReferenceName(branchName)
	for _, ref := range refList {
		if refName.String() == ref.Name().String() {
			return true, nil
		}
	}
	return false, nil
}

func (gm *GitManager) Push(force bool, branchName string) error {
	log.Debug("Pushing branch:", branchName, "...")
	if gm.dryRun {
		// On dry run do not push to any remote
		return nil
	}
	// Pushing to remote
	if err := gm.repository.Push(&git.PushOptions{
		RemoteName: gm.remoteName,
		Auth:       gm.auth,
		Force:      force,
		RefSpecs:   []config.RefSpec{config.RefSpec(fmt.Sprintf(refFormat, branchName))},
	}); err != nil {
		return fmt.Errorf("git push failed with error: %s", err.Error())
	}
	return nil
}

// IsClean returns true if all the files are in Unmodified status.
func (gm *GitManager) IsClean() (bool, error) {
	worktree, err := gm.repository.Worktree()
	if err != nil {
		return false, err
	}
	status, err := worktree.Status()
	if err != nil {
		return false, err
	}

	return status.IsClean(), nil
}

func (gm *GitManager) GenerateCommitMessage(impactedPackage string, fixVersion string) string {
	template := gm.customTemplates.commitMessageTemplate
	if template == "" {
		template = CommitMessageTemplate
	}
	return formatStringWithPlaceHolders(template, impactedPackage, fixVersion, "", true)
}

func (gm *GitManager) GenerateAggregatedCommitMessage(tech coreutils.Technology) string {
	template := gm.customTemplates.commitMessageTemplate
	if template == "" {
		template = GetAggregatedPullRequestTitle(tech)
	}
	return formatStringWithPlaceHolders(template, "", "", "", true)
}

func formatStringWithPlaceHolders(str, impactedPackage, fixVersion, hash string, allowSpaces bool) string {
	replacements := []struct {
		placeholder string
		value       string
	}{
		{PackagePlaceHolder, impactedPackage},
		{FixVersionPlaceHolder, fixVersion},
		{BranchHashPlaceHolder, hash},
	}
	for _, r := range replacements {
		str = strings.Replace(str, r.placeholder, r.value, 1)
	}
	if !allowSpaces {
		str = strings.ReplaceAll(str, " ", "_")
	}
	return str
}

func (gm *GitManager) GenerateFixBranchName(branch string, impactedPackage string, fixVersion string) (string, error) {
	hash, err := Md5Hash("frogbot", branch, impactedPackage, fixVersion)
	if err != nil {
		return "", err
	}
	// Package names in Maven usually contain colons, which are not allowed in a branch name
	fixedPackageName := strings.ReplaceAll(impactedPackage, ":", "_")
	branchFormat := gm.customTemplates.branchNameTemplate
	if branchFormat == "" {
		branchFormat = BranchNameTemplate
	}
	return formatStringWithPlaceHolders(branchFormat, fixedPackageName, fixVersion, hash, false), nil
}

func (gm *GitManager) GeneratePullRequestTitle(impactedPackage string, version string) string {
	template := PullRequestTitleTemplate
	pullRequestFormat := gm.customTemplates.pullRequestTitleTemplate
	if pullRequestFormat != "" {
		template = pullRequestFormat
	}
	return formatStringWithPlaceHolders(template, impactedPackage, version, "", true)
}

// GenerateAggregatedFixBranchName Generating a consistent branch name to enable branch updates
// and to ensure that there is only one Frogbot branch in aggregated mode.
func (gm *GitManager) GenerateAggregatedFixBranchName(tech coreutils.Technology) (fixBranchName string, err error) {
	branchFormat := gm.customTemplates.branchNameTemplate
	if branchFormat == "" {
		branchFormat = AggregatedBranchNameTemplate
	}
	return formatStringWithPlaceHolders(branchFormat, "", "", tech.ToString(), false), nil
}

// dryRunClone clones an existing repository from our testdata folder into the destination folder for testing purposes.
// We should call this function when the current working directory is the repository we want to clone.
func (gm *GitManager) dryRunClone(destination string) error {
	if gm.SkipClone {
		return nil
	}
	baseWd, err := os.Getwd()
	if err != nil {
		return err
	}
	// Copy all the current directory content to the destination path
	// In order to avoid an endless loop when copying into the current directory, exclude the target folder.
	exclude := []string{filepath.Base(destination)}
	if err = fileutils.CopyDir(baseWd, destination, true, exclude); err != nil {
		return err
	}
	// Set the git repository to the new destination .git folder
	repo, err := git.PlainOpen(destination)
	if err != nil {
		return err
	}
	gm.repository = repo
	return nil
}

// Construct HTTPS clone url from the provided git info.
// Frogbot already has an access token with sufficient permissions to clone with HTTPS,
// in case we encounter SSH clone url, we generate HTTPS url instead.
func (gm *GitManager) generateHTTPSCloneUrl() (url string, err error) {
	switch gm.git.GitProvider {
	case vcsutils.GitHub:
		return fmt.Sprintf(githubHttpsFormat, gm.git.APIEndpoint, gm.git.RepoOwner, gm.git.RepoName), nil
	case vcsutils.GitLab:
		return fmt.Sprintf(gitLabHttpsFormat, gm.git.APIEndpoint, gm.git.RepoOwner, gm.git.RepoName), nil
	case vcsutils.BitbucketServer:
		return fmt.Sprintf(bitbucketServerHttpsFormat, gm.git.APIEndpoint, gm.git.RepoOwner, gm.git.RepoName), nil
	case vcsutils.AzureRepos:
		azureEndpointWithoutHttps := strings.Join(strings.Split(gm.git.APIEndpoint, "https://")[1:], "")
		return fmt.Sprintf(azureDevopsHttpsFormat, gm.git.RepoOwner, azureEndpointWithoutHttps, gm.git.Project, gm.git.RepoName), nil
	default:
		return "", fmt.Errorf("unsupported version control provider: %s", gm.git.GitProvider.String())
	}
}

func (gm *GitManager) CheckoutRemoteBranch(branchName string) error {
	var checkoutConfig *git.CheckoutOptions
	if gm.dryRun {
		// On dry runs we mimic remote as local branches.
		checkoutConfig = &git.CheckoutOptions{
			Branch: plumbing.NewBranchReferenceName(branchName),
			Force:  true,
		}
	} else {
		checkoutConfig = &git.CheckoutOptions{
			Branch: plumbing.NewRemoteReferenceName(gm.remoteName, branchName),
			Force:  true,
		}
	}
	log.Debug("Running git checkout to remote branch:", branchName)
	worktree, err := gm.repository.Worktree()
	if err != nil {
		return err
	}
	return worktree.Checkout(checkoutConfig)
}

func toBasicAuth(token, username string) *githttp.BasicAuth {
	// The username can be anything except for an empty string
	if username == "" {
		username = "username"
	}
	// Bitbucket server username starts with ~ prefix as the project key. We need to trim it for the authentication
	username = strings.TrimPrefix(username, "~")
	return &githttp.BasicAuth{
		Username: username,
		Password: token,
	}
}

// getFullBranchName returns the full branch name (for example: refs/heads/master)
// The input branchName can be a short name (master) or a full name (refs/heads/master)
func getFullBranchName(branchName string) plumbing.ReferenceName {
	return plumbing.NewBranchReferenceName(plumbing.ReferenceName(branchName).Short())
}

func loadCustomTemplates(commitMessageTemplate, branchNameTemplate, pullRequestTitleTemplate string) (CustomTemplates, error) {
	template := CustomTemplates{
		commitMessageTemplate:    commitMessageTemplate,
		branchNameTemplate:       branchNameTemplate,
		pullRequestTitleTemplate: pullRequestTitleTemplate,
	}
	err := validateBranchName(template.branchNameTemplate)
	if err != nil {
		return CustomTemplates{}, err
	}
	return template, nil
}

func setGoGitCustomClient() {
	log.Debug("Setting timeout for go-git to", goGitTimeoutSeconds, "seconds ...")
	customClient := &http.Client{
		Timeout: goGitTimeoutSeconds * time.Second,
	}

	client.InstallProtocol("http", githttp.NewClient(customClient))
	client.InstallProtocol("https", githttp.NewClient(customClient))
}
