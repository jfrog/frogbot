package utils

import (
	"errors"
	"fmt"
	"github.com/go-git/go-git/v5/plumbing/protocol/packp/capability"
	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"os"
	"strings"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/format/gitignore"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
)

type GitManager struct {
	// repository represents a git repository as a .git dir.
	repository *git.Repository
	// remoteName is name of the Git remote server
	remoteName string
	// The authentication struct consisting a username/password
	auth *http.BasicAuth
	// dryRun is used for testing purposes, mocking part of the git commands that requires networking
	dryRun bool
	// When dryRun is enabled, dryRunRepoPath specifies the repository local path to clone
	dryRunRepoPath string
	// Custom naming formats
	customFormats CustomFormats
}

type CustomFormats struct {
	// new commit message prefix
	commitTitleFormat string
	// new branch name prefix
	branchNameFormat string
	// new pullRequestTitleFormat title prefix
	pullRequestTitleFormat string
}

func NewGitManager(dryRun bool, clonedRepoPath, projectPath, remoteName, token, username string, g *Git) (*GitManager, error) {
	repository, err := git.PlainOpen(projectPath)
	if err != nil {
		return nil, err
	}
	basicAuth := toBasicAuth(token, username)
	formats, err := loadCustomFormats(g.CustomFormats)
	if err != nil {
		return nil, err
	}
	return &GitManager{repository: repository, dryRunRepoPath: clonedRepoPath, remoteName: remoteName, auth: basicAuth, dryRun: dryRun, customFormats: formats}, nil

}

func (gm *GitManager) Checkout(branchName string) error {
	err := gm.createBranchAndCheckout(branchName, false)
	if err != nil {
		err = fmt.Errorf("'git checkout %s' failed with error: %s", branchName, err.Error())
	}
	return err
}

func (gm *GitManager) Clone(destinationPath, branchName string) error {
	if gm.dryRun {
		// "Clone" the repository from the testdata folder
		return gm.dryRunClone(destinationPath)
	}
	// Gets the remote repo url from the current .git dir
	gitRemote, err := gm.repository.Remote(gm.remoteName)
	if err != nil {
		return fmt.Errorf("'git remote %s' failed with error: %s", gm.remoteName, err.Error())
	}
	if len(gitRemote.Config().URLs) < 1 {
		return errors.New("failed to find git remote URL")
	}
	repoURL := gitRemote.Config().URLs[0]

	transport.UnsupportedCapabilities = []capability.Capability{
		capability.ThinPack,
	}
	if branchName == "" {
		log.Debug("Since no branch name was set, assuming 'master' as the default branch")
		branchName = "master"
	}
	log.Info(fmt.Sprintf("Cloning repository with these details:\nClone url: %s remote name: %s, branch: %s", repoURL, gm.remoteName, getFullBranchName(branchName)))
	cloneOptions := &git.CloneOptions{
		URL:           repoURL,
		Auth:          gm.auth,
		RemoteName:    gm.remoteName,
		ReferenceName: getFullBranchName(branchName),
	}
	repo, err := git.PlainClone(destinationPath, false, cloneOptions)
	if err != nil {
		return fmt.Errorf("'git clone %s from %s' failed with error: %s", branchName, repoURL, err.Error())
	}
	gm.repository = repo
	log.Debug(fmt.Sprintf("Project cloned from %s to %s", repoURL, destinationPath))
	return nil
}

func (gm *GitManager) CreateBranchAndCheckout(branchName string) error {
	err := gm.createBranchAndCheckout(branchName, true)
	if err != nil {
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
			Name:  "JFrog-Frogbot",
			Email: "eco-system+frogbot@jfrog.com",
			When:  time.Now(),
		},
	})
	if err != nil {
		err = fmt.Errorf("git commit failed with error: %s", err.Error())
	}
	return err
}

func (gm *GitManager) BranchExistsInRemote(branchName string) (bool, error) {
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

func (gm *GitManager) Push() error {
	if gm.dryRun {
		// On dry run do not push to any remote
		return nil
	}
	// Pushing to remote
	err := gm.repository.Push(&git.PushOptions{
		RemoteName: gm.remoteName,
		Auth:       gm.auth,
	})
	if err != nil {
		err = fmt.Errorf("git push failed with error: %s", err.Error())
	}
	return err
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

func (gm *GitManager) GenerateCommitTitle(impactedPackage string, version string) string {
	format := gm.customFormats.commitTitleFormat
	if format == "" {
		format = CommitTitleFormat
	}
	return formatStringWithPlaceHolders(format, impactedPackage, version, true)
}

func formatStringWithPlaceHolders(format, impactedPackage, fixVersion string, allowSpaces bool) string {
	str := strings.Replace(strings.Replace(format, PackagePlaceHolder, impactedPackage, 1), FixVersionPlaceHolder, fixVersion, 1)
	if allowSpaces {
		return str
	} else {
		return strings.ReplaceAll(str, " ", "_")
	}
}

func (gm *GitManager) GenerateFixBranchName(branch string, impactedPackage string, version string) (string, error) {
	uniqueString, err := Md5Hash("frogbot", branch, impactedPackage, version)
	if err != nil {
		return "", err
	}
	// Package names in Maven usually contain colons, which are not allowed in a branch name
	fixedPackageName := strings.ReplaceAll(impactedPackage, ":", "_")
	branchFormat := gm.customFormats.branchNameFormat
	if branchFormat == "" {
		branchFormat = NewBranchesFormat
	}
	// Unique string is not optional
	branchName := formatStringWithPlaceHolders(branchFormat, fixedPackageName, version, false)
	return branchName + "-" + uniqueString, nil
}

func (gm *GitManager) GeneratePullRequestTitle(impactedPackage string, version string) string {
	format := PullRequestFormat
	pullRequestFormat := gm.customFormats.pullRequestTitleFormat
	if pullRequestFormat != "" {
		format = pullRequestFormat
	}
	return formatStringWithPlaceHolders(format, impactedPackage, version, true)
}

// dryRunClone clones an existing repository from our testdata folder into the destination folder for testing purposes.
// We should call this function when the current working directory is the repository we want to clone.
func (gm *GitManager) dryRunClone(destination string) error {
	baseWd, err := os.Getwd()
	if err != nil {
		return err
	}
	// Copy all the current directory content to the destination path
	err = fileutils.CopyDir(baseWd, destination, true, nil)
	if err != nil {
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

func toBasicAuth(token, username string) *http.BasicAuth {
	// The username can be anything except for an empty string
	if username == "" {
		username = "username"
	}
	// Bitbucket server username starts with ~ prefix as the project key. We need to trim it for the authentication
	username = strings.TrimPrefix(username, "~")
	return &http.BasicAuth{
		Username: username,
		Password: token,
	}
}

// getFullBranchName returns the full branch name (for example: refs/heads/master)
// The input branchName can be a short name (master) or a full name (refs/heads/master)
func getFullBranchName(branchName string) plumbing.ReferenceName {
	return plumbing.NewBranchReferenceName(plumbing.ReferenceName(branchName).Short())
}

func loadCustomFormats(formatsArray map[string]string) (CustomFormats, error) {
	format := CustomFormats{
		commitTitleFormat:      formatsArray["commitTitle"],
		branchNameFormat:       formatsArray["branchName"],
		pullRequestTitleFormat: formatsArray["pullRequestTitle"],
	}
	err := IsValidBranchFormat(format.branchNameFormat)
	if err != nil {
		return CustomFormats{}, err
	}
	return format, nil
}
