package utils

import (
	"errors"
	"fmt"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/format/gitignore"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	clientLog "github.com/jfrog/jfrog-client-go/utils/log"
)

type GitManager struct {
	repository *git.Repository
	remoteName string
	auth       *http.BasicAuth
}

func NewGitManager(projectPath, remoteName, token string) (*GitManager, error) {
	repository, err := git.PlainOpen(projectPath)
	if err != nil {
		return nil, err
	}
	basicAuth := createBasicAuth(token)
	return &GitManager{repository: repository, remoteName: remoteName, auth: basicAuth}, nil
}

func (gm *GitManager) Checkout(branchName string) error {
	err := gm.createBranchAndCheckout(branchName, false)
	if err != nil {
		err = fmt.Errorf("'git checkout %s' failed with error: %s", branchName, err.Error())
	}
	return err
}

func (gm *GitManager) Clone(destinationPath, branchName string) error {
	// Gets the remote repo url from the current .git dir
	gitRemote, err := gm.repository.Remote(gm.remoteName)
	if err != nil {
		return fmt.Errorf("'git remote %s' failed with error: %s", gm.remoteName, err.Error())
	}
	if len(gitRemote.Config().URLs) < 1 {
		return errors.New("failed to find git remote URL")
	}
	repoURL := gitRemote.Config().URLs[0]

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
	clientLog.Debug(fmt.Sprintf("Project cloned from %s to %s", repoURL, destinationPath))
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

	err = worktree.AddWithOptions(&git.AddOptions{All: true})
	if err != nil {
		err = fmt.Errorf("git commit failed with error: %s", err.Error())
	}
	return err
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

func (gm *GitManager) BranchExistsOnRemote(branchName string) (bool, error) {
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

func createBasicAuth(token string) *http.BasicAuth {
	return &http.BasicAuth{
		// The username can be anything except for an empty string
		Username: "username",
		Password: token,
	}
}

// getFullBranchName returns the full branch name (for example: refs/heads/master)
// The input branchName can be a short name (master) or a full name (refs/heads/master)
func getFullBranchName(branchName string) plumbing.ReferenceName {
	return plumbing.NewBranchReferenceName(plumbing.ReferenceName(branchName).Short())
}
