package utils

import (
	"github.com/jfrog/jfrog-client-go/utils"
)

type gitManager struct {
	manager utils.GitManager
}

func NewGitManager(dotGitPath string) *gitManager {
	return &gitManager{manager: *utils.NewGitManager(dotGitPath)}
}

func (m *gitManager) CreateBranch(branch string) (string, string, error) {
	return m.manager.ExecGit("branch", branch)
}

func (m *gitManager) Checkout(branch string) (string, string, error) {
	return m.manager.ExecGit("checkout", branch)
}

func (m *gitManager) Add(fileName string) (string, string, error) {
	return m.manager.ExecGit("add", fileName)
}

func (m *gitManager) AddAll() (string, string, error) {
	return m.manager.ExecGit("add", "-A")
}

func (m *gitManager) Commit(commitMessage string) (string, string, error) {
	return m.manager.ExecGit("commit", "-m", commitMessage)
}

func (m *gitManager) Push(remote, branch string) (string, string, error) {
	return m.manager.ExecGit("push", remote, branch)
}
