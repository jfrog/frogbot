package utils

import (
	"fmt"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	"strings"
	"time"
)

type GitManager struct {
	repository *git.Repository
	remoteName string
}

func NewGitManager(projectPath, remoteName string) (*GitManager, error) {
	repository, err := git.PlainOpen(projectPath)
	if errorutils.CheckError(err) != nil {
		return nil, err
	}
	return &GitManager{repository: repository, remoteName: remoteName}, nil
}

func (gm *GitManager) CreateBranch(branchName string) error {
	return gm.repository.CreateBranch(&config.Branch{Name: branchName, Remote: gm.remoteName})
}

func (gm *GitManager) Checkout(branchName string) error {
	worktree, err := gm.repository.Worktree()
	if err != nil {
		return err
	}
	return worktree.Checkout(&git.CheckoutOptions{
		Branch: plumbing.ReferenceName("refs/heads/" + branchName),
	})
}

func (gm *GitManager) AddAll() error {
	worktree, err := gm.repository.Worktree()
	if err != nil {
		return err
	}
	return worktree.AddWithOptions(&git.AddOptions{All: true})
}

func (gm *GitManager) Commit(commitMessage string) error {
	worktree, err := gm.repository.Worktree()
	if err != nil {
		return err
	}
	commit, err := worktree.Commit(commitMessage, &git.CommitOptions{
		Author: &object.Signature{
			Name:  "sverdlov93",
			Email: "sverdlov93@gmail.com",
			When:  time.Now(),
		},
	})
	_, err = gm.repository.CommitObject(commit)
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
	refPrefix := "refs/heads/"
	for _, ref := range refList {
		refName := ref.Name().String()
		if !strings.HasPrefix(refName, refPrefix) {
			continue
		}
		branch := refName[len(refPrefix):]
		if branchName == branch {
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
	return errorutils.CheckError(err)
}
