package autopr

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/golang/mock/gomock"
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/jfrog-client-go/xsc/services"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jfrog/frogbot/v3/testdata"
	"github.com/jfrog/frogbot/v3/utils"
	securitypkgupdaters "github.com/jfrog/jfrog-cli-security/remediation/sca/packageupdaters"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
)

type fakeAutoPrGitManager struct {
	calls            []string
	branchExists     bool
	clean            bool
	fixBranchName    string
	commitMessage    string
	pullRequestTitle string
}

func (f *fakeAutoPrGitManager) GenerateFixBranchName(_, _, _ string) (string, error) {
	f.calls = append(f.calls, "generate-branch")
	return f.fixBranchName, nil
}

func (f *fakeAutoPrGitManager) BranchExistsInRemote(string) (bool, error) {
	f.calls = append(f.calls, "check-remote")
	return f.branchExists, nil
}

func (f *fakeAutoPrGitManager) IsClean() (bool, error) {
	f.calls = append(f.calls, "check-clean")
	return f.clean, nil
}

func (f *fakeAutoPrGitManager) CreateBranchAndCheckout(string, bool) error {
	f.calls = append(f.calls, "create-branch")
	return nil
}

func (f *fakeAutoPrGitManager) GenerateCommitMessage(_, _ string) string {
	return f.commitMessage
}

func (f *fakeAutoPrGitManager) AddTrackedAndCommit(_, _ string) error {
	f.calls = append(f.calls, "commit")
	return nil
}

func (f *fakeAutoPrGitManager) Push(bool, string) error {
	f.calls = append(f.calls, "push")
	return nil
}

func (f *fakeAutoPrGitManager) GeneratePullRequestTitle(_, _ string) string {
	return f.pullRequestTitle
}

func TestRun_HappyPathUpdatesManifestAndLockAndPreservesUntrackedFiles(t *testing.T) {
	workspaceDir := createCleanTestRepository(t, map[string]string{
		"package.json":      `{"dependencies":{"example":"1.0.0"}}`,
		"package-lock.json": `{"packages":{}}`,
	})
	t.Chdir(workspaceDir)
	setAutoPrInputs(t)

	gitManager := &fakeAutoPrGitManager{
		clean:            true,
		fixBranchName:    "frogbot-example-fix",
		commitMessage:    "Upgrade example to 1.0.1",
		pullRequestTitle: "Upgrade example",
	}
	pullRequestCreated := false
	cmd := &AutoPrCmd{
		newGitManager: func(utils.Repository) (autoPrGitManager, error) {
			return gitManager, nil
		},
		findDescriptorPaths: func(_, _, _ string) ([]string, techutils.Technology, bool, error) {
			return []string{"package.json"}, techutils.Npm, true, nil
		},
		runUpdater: func(_, _, _ string, _ techutils.Technology, _ bool, _ []string) error {
			require.NoError(t, os.WriteFile(filepath.Join(workspaceDir, "package.json"), []byte("manifest changed"), 0o600))
			require.NoError(t, os.WriteFile(filepath.Join(workspaceDir, "package-lock.json"), []byte("lock changed"), 0o600))
			return os.WriteFile(filepath.Join(workspaceDir, "updater.tmp"), []byte("preserve"), 0o600)
		},
		createPullRequest: func(utils.Repository, string, string, string, string, []string) error {
			pullRequestCreated = true
			return nil
		},
	}
	repository := testAutoPrRepository()

	require.NoError(t, cmd.Run(repository, nil))
	assert.Equal(t, "manifest changed", readTestFile(t, filepath.Join(workspaceDir, "package.json")))
	assert.Equal(t, "lock changed", readTestFile(t, filepath.Join(workspaceDir, "package-lock.json")))
	assert.Equal(t, "preserve", readTestFile(t, filepath.Join(workspaceDir, "updater.tmp")))
	assert.True(t, pullRequestCreated)
	assert.Equal(t, []string{"generate-branch", "check-remote", "check-clean", "create-branch", "commit", "push"}, gitManager.calls)
}

func TestRun_ComponentBranches(t *testing.T) {
	tests := []struct {
		name     string
		paths    []string
		direct   bool
		wantSkip bool
		wantErr  string
	}{
		{name: "component not found", wantSkip: true},
		{name: "transitive dependency", paths: []string{"package.json"}, wantSkip: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			workspaceDir := createCleanTestRepository(t, map[string]string{"package.json": "{}"})
			t.Chdir(workspaceDir)
			setAutoPrInputs(t)
			gitManager := &fakeAutoPrGitManager{clean: true, fixBranchName: "fix"}
			cmd := &AutoPrCmd{
				newGitManager: func(utils.Repository) (autoPrGitManager, error) { return gitManager, nil },
				findDescriptorPaths: func(_, _, _ string) ([]string, techutils.Technology, bool, error) {
					return tc.paths, techutils.Npm, tc.direct, nil
				},
			}

			err := cmd.Run(testAutoPrRepository(), nil)
			if tc.wantSkip {
				var skipped *ErrAutoPrSkipped
				require.ErrorAs(t, err, &skipped)
			} else {
				require.ErrorContains(t, err, tc.wantErr)
			}
			assert.NotContains(t, gitManager.calls, "create-branch")
		})
	}
}

func TestRun_UnsupportedTechnologyFinishesWithoutError(t *testing.T) {
	workspaceDir := createCleanTestRepository(t, map[string]string{"Cargo.lock": ""})
	t.Chdir(workspaceDir)
	setAutoPrInputs(t)
	gitManager := &fakeAutoPrGitManager{clean: true, fixBranchName: "fix"}
	cmd := &AutoPrCmd{
		newGitManager: func(utils.Repository) (autoPrGitManager, error) { return gitManager, nil },
		findDescriptorPaths: func(_, _, _ string) ([]string, techutils.Technology, bool, error) {
			return []string{"Cargo.lock"}, techutils.Cargo, true, nil
		},
	}

	require.NoError(t, cmd.Run(testAutoPrRepository(), nil))
	assert.NotContains(t, gitManager.calls, "create-branch")
}

func TestInitializeGitManager_WithNilConfigProfileAndConfiguredRemote(t *testing.T) {
	workspaceDir := t.TempDir()
	repo, err := git.PlainInit(workspaceDir, false)
	require.NoError(t, err)
	_, err = repo.CreateRemote(&config.RemoteConfig{
		Name: "origin",
		URLs: []string{"https://github.com/owner/repo.git"},
	})
	require.NoError(t, err)
	t.Chdir(workspaceDir)

	repository := utils.Repository{Params: utils.Params{
		Git: utils.Git{
			RepoOwner:          "owner",
			RepoName:           "repo",
			Branches:           []string{"main"},
			RepositoryCloneUrl: "https://github.com/owner/repo.git",
		},
	}}

	gitManager, err := (&AutoPrCmd{}).initializeGitManager(repository)
	require.NoError(t, err)
	assert.NotNil(t, gitManager)
}

func createCleanTestRepository(t *testing.T, files map[string]string) string {
	t.Helper()
	workspaceDir := t.TempDir()
	repo, err := git.PlainInit(workspaceDir, false)
	require.NoError(t, err)
	worktree, err := repo.Worktree()
	require.NoError(t, err)
	for name, contents := range files {
		require.NoError(t, os.WriteFile(filepath.Join(workspaceDir, name), []byte(contents), 0o600))
		_, err = worktree.Add(name)
		require.NoError(t, err)
	}
	_, err = worktree.Commit("initial", &git.CommitOptions{Author: &object.Signature{Name: "test", Email: "test@example.com"}})
	require.NoError(t, err)
	return workspaceDir
}

func setAutoPrInputs(t *testing.T) {
	t.Helper()
	t.Setenv(componentNameEnv, "example")
	t.Setenv(affectedVersionEnv, "1.0.0")
	t.Setenv(fixVersionEnv, "1.0.1")
}

func testAutoPrRepository() utils.Repository {
	return utils.Repository{Params: utils.Params{
		ConfigProfile: &services.ConfigProfile{},
		Git:           utils.Git{RepoOwner: "owner", RepoName: "repo", Branches: []string{"master"}},
	}}
}

func readTestFile(t *testing.T, path string) string {
	t.Helper()
	contents, err := os.ReadFile(path)
	require.NoError(t, err)
	return string(contents)
}

func TestRun_RemoteFixBranchExistsDoesNotMutateWorkspace(t *testing.T) {
	workspaceDir := t.TempDir()
	repo, err := git.PlainInit(workspaceDir, false)
	require.NoError(t, err)
	worktree, err := repo.Worktree()
	require.NoError(t, err)

	trackedPath := filepath.Join(workspaceDir, "README.md")
	require.NoError(t, os.WriteFile(trackedPath, []byte("original"), 0o600))
	_, err = worktree.Add("README.md")
	require.NoError(t, err)
	_, err = worktree.Commit("initial", &git.CommitOptions{Author: &object.Signature{Name: "test", Email: "test@example.com"}})
	require.NoError(t, err)

	untrackedPath := filepath.Join(workspaceDir, "local-notes.txt")
	require.NoError(t, os.WriteFile(untrackedPath, []byte("keep me"), 0o600))
	t.Chdir(workspaceDir)
	t.Setenv(componentNameEnv, "example")
	t.Setenv(affectedVersionEnv, "1.0.0")
	t.Setenv(fixVersionEnv, "1.0.1")

	cmd := &AutoPrCmd{newGitManager: func(utils.Repository) (autoPrGitManager, error) {
		return &fakeAutoPrGitManager{branchExists: true, fixBranchName: "fix"}, nil
	}}
	repository := utils.Repository{Params: utils.Params{
		ConfigProfile: &services.ConfigProfile{},
		Git:           utils.Git{Branches: []string{"master"}},
	}}

	err = cmd.Run(repository, nil)
	var skipped *ErrAutoPrSkipped
	require.ErrorAs(t, err, &skipped)

	contents, readErr := os.ReadFile(untrackedPath)
	require.NoError(t, readErr)
	assert.Equal(t, "keep me", string(contents))
	head, headErr := repo.Head()
	require.NoError(t, headErr)
	assert.Equal(t, "master", head.Name().Short())
}

func TestRun_DirtyWorktreeFailsBeforeDependencyAnalysis(t *testing.T) {
	workspaceDir := t.TempDir()
	repo, err := git.PlainInit(workspaceDir, false)
	require.NoError(t, err)
	worktree, err := repo.Worktree()
	require.NoError(t, err)

	trackedPath := filepath.Join(workspaceDir, "README.md")
	require.NoError(t, os.WriteFile(trackedPath, []byte("original"), 0o600))
	_, err = worktree.Add("README.md")
	require.NoError(t, err)
	_, err = worktree.Commit("initial", &git.CommitOptions{Author: &object.Signature{Name: "test", Email: "test@example.com"}})
	require.NoError(t, err)

	untrackedPath := filepath.Join(workspaceDir, "local-notes.txt")
	require.NoError(t, os.WriteFile(untrackedPath, []byte("keep me"), 0o600))
	t.Chdir(workspaceDir)
	t.Setenv(componentNameEnv, "example")
	t.Setenv(affectedVersionEnv, "1.0.0")
	t.Setenv(fixVersionEnv, "1.0.1")

	cmd := &AutoPrCmd{newGitManager: func(utils.Repository) (autoPrGitManager, error) {
		return &fakeAutoPrGitManager{clean: false, fixBranchName: "fix"}, nil
	}}
	repository := utils.Repository{Params: utils.Params{
		ConfigProfile: &services.ConfigProfile{},
		Git:           utils.Git{Branches: []string{"master"}},
	}}

	err = cmd.Run(repository, nil)
	require.EqualError(t, err, "auto-pr requires a clean worktree; commit, stash, or remove local changes before running it")
	contents, readErr := os.ReadFile(untrackedPath)
	require.NoError(t, readErr)
	assert.Equal(t, "keep me", string(contents))
}

func TestValidateInputs(t *testing.T) {
	tests := []struct {
		name            string
		componentName   string
		affectedVersion string
		fixVersion      string
		expectError     bool
		errorContains   []string
		errorMissing    []string
	}{
		{
			name:            "all present",
			componentName:   "com.example:lib",
			affectedVersion: "1.0.0",
			fixVersion:      "1.0.1",
		},
		{
			name:          "missing all",
			expectError:   true,
			errorContains: []string{componentNameEnv, affectedVersionEnv, fixVersionEnv},
		},
		{
			name:            "missing fix version only",
			componentName:   "com.example:lib",
			affectedVersion: "1.0.0",
			expectError:     true,
			errorContains:   []string{fixVersionEnv},
			errorMissing:    []string{componentNameEnv},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateInputs(tc.componentName, tc.affectedVersion, tc.fixVersion)
			if tc.expectError {
				require.Error(t, err)
				for _, s := range tc.errorContains {
					assert.Contains(t, err.Error(), s)
				}
				for _, s := range tc.errorMissing {
					assert.NotContains(t, err.Error(), s)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestBuildPRBody(t *testing.T) {
	tests := []struct {
		name        string
		commitHash  string
		contains    []string
		notContains []string
	}{
		{
			name:     "no commit hash",
			contains: []string{"com.example:lib", "1.0.0", "Frogbot"},
		},
		{
			name:       "with commit hash",
			commitHash: "abc123",
			contains:   []string{"abc123"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.commitHash != "" {
				t.Setenv(commitHashEnv, tc.commitHash)
			} else {
				t.Setenv(commitHashEnv, "")
			}
			body, extraComments := buildPRBody(utils.Repository{}, "com.example:lib", "1.0.0", "1.0.1", techutils.Maven, []string{"pom.xml"})
			assert.Empty(t, extraComments)
			for _, s := range tc.contains {
				assert.Contains(t, body, s)
			}
			for _, s := range tc.notContains {
				assert.NotContains(t, body, s)
			}
		})
	}

}

func TestCreatePullRequestWithComments_PostsOverflowComments(t *testing.T) {
	client := testdata.NewMockVcsClient(gomock.NewController(t))
	repository := testAutoPrRepository()

	client.EXPECT().
		CreatePullRequestDetailed(gomock.Any(), "owner", "repo", "fix", "master", "title", "body").
		Return(vcsclient.CreatedPullRequestInfo{Number: 42}, nil)
	client.EXPECT().
		AddPullRequestComment(gomock.Any(), "owner", "repo", "overflow", 42).
		Return(nil)

	require.NoError(t, createPullRequestWithComments(
		client, repository, "fix", "master", "title", "body", []string{"overflow"}))
}

// TestRunUpdater_UnsupportedTech ensures runUpdater surfaces a clear error for technologies
// GetCompatiblePackageUpdater does not recognize (Yarn is not in the compatible set).
func TestRunUpdater_UnsupportedTech(t *testing.T) {
	err := runUpdater("some-pkg", "1.0.0", "1.0.1", techutils.Cargo, true, []string{"package.json"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported technology")
}

// TestGetCompatiblePackageUpdater_SupportedSet documents the technologies routed through the
// shared factory. Docker must be included so auto-pr can fix container images.
func TestGetCompatiblePackageUpdater_SupportedSet(t *testing.T) {
	techs := []techutils.Technology{
		techutils.Maven,
		techutils.Npm,
		techutils.Pnpm,
		techutils.Go,
		techutils.Pip,
		techutils.Docker,
	}
	for _, tech := range techs {
		t.Run(tech.String(), func(t *testing.T) {
			updater, supported := securitypkgupdaters.GetCompatiblePackageUpdater(&securitypkgupdaters.FixDetails{Technology: tech})
			require.True(t, supported)
			require.NotNil(t, updater)
		})
	}
}

func TestBuildFixDetails(t *testing.T) {
	paths := []string{"pom.xml", "module/pom.xml"}
	details := buildFixDetails("com.example:lib", "1.0.0", "1.0.1", techutils.Maven, true, paths)

	assert.Equal(t, "com.example:lib", details.ImpactedDependencyName)
	assert.Equal(t, "1.0.0", details.ImpactedDependencyVersion)
	assert.Equal(t, "1.0.1", details.SuggestedFixedVersion)
	assert.True(t, details.IsDirectDependency)
	assert.Equal(t, techutils.Maven, details.Technology)
	require.Len(t, details.Components, 1)
	require.Len(t, details.Components[0].Evidences, 2)
	assert.Equal(t, "pom.xml", details.Components[0].Evidences[0].File)
	assert.Equal(t, "module/pom.xml", details.Components[0].Evidences[1].File)

	transitive := buildFixDetails("com.example:lib", "1.0.0", "1.0.1", techutils.Maven, false, paths)
	assert.False(t, transitive.IsDirectDependency)
}
