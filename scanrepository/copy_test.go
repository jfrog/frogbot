package scanrepository

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/go-git/go-git/v5"
	"github.com/jfrog/frogbot/v3/utils"
	"github.com/stretchr/testify/require"
)

func TestCopyRepositoryPreservesSymlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating symbolic links requires additional privileges on Windows")
	}
	source, destination := t.TempDir(), t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(source, "docs"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(source, "README.md"), []byte("README"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(source, "run.sh"), []byte("#!/bin/sh\n"), 0755))
	links := map[string]string{
		"docs/index.md": "../README.md",
		"docs-link":     "docs",
		"missing-link":  "missing",
		"absolute-link": filepath.Join(source, "README.md"),
	}
	for name, target := range links {
		require.NoError(t, os.Symlink(target, filepath.Join(source, name)))
	}

	require.NoError(t, copyRepository(source, destination))

	for name, target := range links {
		info, err := os.Lstat(filepath.Join(destination, name))
		require.NoError(t, err)
		require.NotZero(t, info.Mode()&os.ModeSymlink, name)
		actual, err := os.Readlink(filepath.Join(destination, name))
		require.NoError(t, err)
		require.Equal(t, target, actual)
	}
	contents, err := os.ReadFile(filepath.Join(destination, "README.md"))
	require.NoError(t, err)
	require.Equal(t, "README", string(contents))
	info, err := os.Stat(filepath.Join(destination, "run.sh"))
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0755), info.Mode().Perm())
}

func TestSwitchToTempWorkingDirPreservesTrackedSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating symbolic links requires additional privileges on Windows")
	}
	source := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(source, "docs"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(source, "README.md"), []byte("README"), 0644))
	require.NoError(t, os.Symlink("../README.md", filepath.Join(source, "docs", "index.md")))
	repository, err := git.PlainInit(source, false)
	require.NoError(t, err)
	tree, err := repository.Worktree()
	require.NoError(t, err)
	_, err = tree.Add("docs/index.md")
	require.NoError(t, err)
	t.Chdir(source)
	cmd := ScanRepositoryCmd{
		dryRun:         true,
		dryRunRepoPath: t.TempDir(),
		scanDetails:    &utils.ScanDetails{Git: &utils.Git{RepoName: "repository"}},
		gitManager:     utils.NewGitManager(),
	}
	destination, restore, err := cmd.switchToTempWorkingDir()
	if restore != nil {
		t.Cleanup(func() { require.NoError(t, restore()) })
	}
	require.NoError(t, err)
	link, err := os.Readlink(filepath.Join(destination, "docs", "index.md"))
	require.NoError(t, err)
	require.Equal(t, "../README.md", link)
	copied, err := git.PlainOpen(destination)
	require.NoError(t, err)
	copiedTree, err := copied.Worktree()
	require.NoError(t, err)
	status, err := copiedTree.Status()
	require.NoError(t, err)
	require.Equal(t, git.Unmodified, status.File("docs/index.md").Worktree)
}
