package utils

import (
	"fmt"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	"time"
)

type GitManager struct {
	repository *git.Repository
	remoteName string
}

func NewGitManager(projectPath, remoteName string) (*GitManager, error) {
	repository, err := git.PlainOpen(projectPath)
	if err != nil {
		return nil, err
	}
	return &GitManager{repository: repository, remoteName: remoteName}, nil
}

func (gm *GitManager) Checkout(branchName string) error {
	err := gm.createBranchAndCheckout(branchName, false)
	if err != nil {
		err = fmt.Errorf("'git checkout %s' failed with error: %s", branchName, err.Error())
	}
	return err
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
		Branch: plumbing.NewBranchReferenceName(branchName),
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
	refList, err := remote.List(&git.ListOptions{})
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

func (gm *GitManager) Push(token string) error {
	// Pushing to remote
	err := gm.repository.Push(&git.PushOptions{
		RemoteName: gm.remoteName,
		Auth: &http.BasicAuth{
			Username: "username", // The username can be anything except an empty string
			Password: token,
		},
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
