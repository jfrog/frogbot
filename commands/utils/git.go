package utils

import (
	"fmt"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing/transport/client"
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

	// Aggregate branches name should always be the same name.
	// We use a const to replace in the branch template ${BRANCH_NAME_HASH}
	constAggregatedHash = "0"
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

// InitGitManager initializes the GitManager.
// If the repository has not been cloned yet, it clones the repository using the provided Git information.
// During dry runs, it emulates the operation by changing the directory to the cloned repository path.
func InitGitManager(dryRun bool, testFolderPath string, gitInfo *Git) (gm *GitManager, err error) {
	setGoGitCustomClient()
	// Check git preconditions are met before running
	repository, valid := isValidGitRepository(dryRun)
	// Attempt to clone the repository based on the Git info.
	if !valid {
		repository, err = CloneRepositoryAndChDir(dryRun, gitInfo)
		if err != nil {
			return nil, fmt.Errorf("failed to clone repository: %s", err.Error())
		}
	}
	templates, err := loadCustomTemplates(gitInfo.CommitMessageTemplate, gitInfo.BranchNameTemplate, gitInfo.PullRequestTitleTemplate)
	if err != nil {
		return
	}
	return &GitManager{repository: repository, dryRunRepoPath: testFolderPath, remoteName: "origin", auth: toBasicAuth(gitInfo.Token, gitInfo.Username), dryRun: dryRun, customTemplates: templates, git: gitInfo}, nil
}

// CloneRepositoryAndChDir clones the repository provided from the git info.
func CloneRepositoryAndChDir(dryRun bool, gitInfo *Git) (repository *git.Repository, err error) {
	baseWd, err := os.Getwd()
	if err != nil {
		return
	}
	expectedWorkingDir := filepath.Join(baseWd, gitInfo.RepoName)
	if dryRun {
		// Used for testings
		repository, err = gitInfo.dryRunClone(expectedWorkingDir)
		if err != nil {
			return nil, err
		}
	} else {
		// Clone using HTTPS clone urls
		log.Info("Cloning repository...")
		cloneUrl, err := gitInfo.generateHTTPSCloneUrl()
		if err != nil {
			return nil, err
		}
		cloneOptions := &git.CloneOptions{
			URL:  cloneUrl,
			Auth: toBasicAuth(gitInfo.Token, gitInfo.Username),
		}
		repository, err = git.PlainClone(expectedWorkingDir, false, cloneOptions)
		if err != nil {
			return nil, err
		}
	}
	return repository, os.Chdir(expectedWorkingDir)
}

func (gm *GitManager) CheckoutLocalBranch(branchName string) error {
	err := gm.createBranchAndCheckout(branchName, false)
	if err != nil {
		err = fmt.Errorf("'git checkout %s' failed with error: %s", branchName, err.Error())
	}
	log.Debug("Running git checkout to local branch:", branchName)
	return err
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

func (gm *GitManager) AddAllAndCommit(commitMessage string) error {
	log.Debug("Running git add all and commit...")
	err := gm.addAll()
	if err != nil {
		return err
	}
	return gm.commit(commitMessage)
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

func (gm *GitManager) GenerateAggregatedCommitMessage() string {
	template := gm.customTemplates.commitMessageTemplate
	if template == "" {
		template = AggregatedPullRequestTitleTemplate
	}
	return formatStringWithPlaceHolders(template, "", "", "", true)
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
func (gm *GitManager) GenerateAggregatedFixBranchName() (fixBranchName string, err error) {
	branchFormat := gm.customTemplates.branchNameTemplate
	if branchFormat == "" {
		branchFormat = AggregatedBranchNameTemplate
	}
	return formatStringWithPlaceHolders(branchFormat, "", "", constAggregatedHash, false), nil
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
	if err = worktree.Checkout(checkoutConfig); err != nil {
		return fmt.Errorf("checkout to remote branch failed with error: %s", err.Error())
	}
	return nil
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
			Email: frogbotAuthorEmail,
			When:  time.Now(),
		},
	})
	if err != nil {
		err = fmt.Errorf("git commit failed with error: %s", err.Error())
	}
	return err
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

// Ensures that two mandatory conditions are met:
// 1. The current working directory is set to the root of the .git directory.
// 2. Remote URLs are in the HTTPS format and not SSH.
// In the case of SSH urls, we convert to HTTPS and clone the repository.
func isValidGitRepository(dryRun bool) (repository *git.Repository, valid bool) {
	repository, err := git.PlainOpen(".")
	if err != nil {
		return
	}
	// Don't check remotes on dryRuns.
	if dryRun {
		valid = true
		return
	}
	// Verify HTTPS clone urls and not SSH
	gitRemote, err := repository.Remote("origin")
	if err != nil {
		return
	}
	if len(gitRemote.Config().URLs) < 1 {
		return
	}
	remoteUrl := gitRemote.Config().URLs[0]
	if !strings.HasPrefix(remoteUrl, "https") {
		return
	}
	return repository, true
}

// Dry clones used for testings to use predefined test folders.
// Copies from testFolderPath to the current working dir, and replace git folders to .git
func (g *Git) dryRunClone(testFolderPath string) (repository *git.Repository, err error) {
	err = os.Chdir(testFolderPath)
	if err != nil {
		return
	}
	if err = prepareTestGitFolder(testFolderPath); err != nil {
		return
	}
	return git.PlainOpen(".")
}

func prepareTestGitFolder(testFolderPath string) (err error) {
	exists, err := fileutils.IsDirExists(testFolderPath, false)
	if err != nil {
		return
	}
	if exists {
		err = fileutils.CopyDir(filepath.Join(testFolderPath, "git"), filepath.Join(testFolderPath, ".git"), true, []string{})
		if err != nil {
			return
		}
		err = fileutils.RemoveTempDir(filepath.Join(testFolderPath, "git"))
		if err != nil {
			return
		}
	}
	return
}
