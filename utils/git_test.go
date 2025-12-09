package utils

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/jfrog/froggit-go/vcsutils"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/tests"
	"github.com/stretchr/testify/assert"
)

func TestGitManager_GenerateCommitMessage(t *testing.T) {
	testCases := []struct {
		gitManager      GitManager
		impactedPackage string
		fixVersion      VulnerabilityDetails
		expected        string
		description     string
	}{
		{
			gitManager:      GitManager{customTemplates: CustomTemplates{commitMessageTemplate: "<type>: bump ${IMPACTED_PACKAGE}"}},
			impactedPackage: "mquery",
			fixVersion:      VulnerabilityDetails{SuggestedFixedVersion: "3.4.5"},
			expected:        "<type>: bump mquery",
			description:     "Custom prefix",
		},
		{
			gitManager:      GitManager{customTemplates: CustomTemplates{commitMessageTemplate: "<type>[scope]: Upgrade package ${IMPACTED_PACKAGE} to ${FIX_VERSION}"}},
			impactedPackage: "mquery", fixVersion: VulnerabilityDetails{SuggestedFixedVersion: "3.4.5"},
			expected:    "<type>[scope]: Upgrade package mquery to 3.4.5",
			description: "Default template",
		}, {
			gitManager:      GitManager{customTemplates: CustomTemplates{commitMessageTemplate: ""}},
			impactedPackage: "mquery", fixVersion: VulnerabilityDetails{SuggestedFixedVersion: "3.4.5"},
			expected:    "Upgrade mquery to 3.4.5",
			description: "Default template",
		},
		// Test template without $
		{
			gitManager:      GitManager{customTemplates: CustomTemplates{commitMessageTemplate: "<type>[scope]: Upgrade package {IMPACTED_PACKAGE} to {FIX_VERSION}"}},
			impactedPackage: "mquery", fixVersion: VulnerabilityDetails{SuggestedFixedVersion: "3.4.5"},
			expected:    "<type>[scope]: Upgrade package mquery to 3.4.5",
			description: "Default template",
		},
		{
			gitManager:      GitManager{customTemplates: CustomTemplates{commitMessageTemplate: "<type>[scope]: Upgrade package ${IMPACTED_PACKAGE} to {FIX_VERSION}"}},
			impactedPackage: "mquery", fixVersion: VulnerabilityDetails{SuggestedFixedVersion: "3.4.5"},
			expected:    "<type>[scope]: Upgrade package mquery to 3.4.5",
			description: "Default template",
		},
	}
	for _, test := range testCases {
		t.Run(test.expected, func(t *testing.T) {
			commitMessage := test.gitManager.GenerateCommitMessage(test.impactedPackage, test.fixVersion.SuggestedFixedVersion)
			assert.Equal(t, test.expected, commitMessage)
		})
	}
}

func TestGitManager_GenerateFixBranchName(t *testing.T) {
	testCases := []struct {
		gitManager      GitManager
		impactedPackage string
		fixVersion      VulnerabilityDetails
		expected        string
		description     string
	}{
		{
			gitManager:      GitManager{customTemplates: CustomTemplates{branchNameTemplate: "[Feature]-${IMPACTED_PACKAGE}-${BRANCH_NAME_HASH}"}},
			impactedPackage: "mquery",
			fixVersion:      VulnerabilityDetails{SuggestedFixedVersion: "3.4.5"},
			expected:        "[Feature]-mquery-41b1f45136b25e3624b15999bd57a476",
			description:     "Custom template",
		},
		{
			gitManager:      GitManager{customTemplates: CustomTemplates{branchNameTemplate: ""}},
			impactedPackage: "mquery",
			fixVersion:      VulnerabilityDetails{SuggestedFixedVersion: "3.4.5"},
			expected:        "frogbot-mquery-41b1f45136b25e3624b15999bd57a476",
			description:     "No template",
		}, {
			gitManager:      GitManager{customTemplates: CustomTemplates{branchNameTemplate: "just-a-branch-${BRANCH_NAME_HASH}"}},
			impactedPackage: "mquery",
			fixVersion:      VulnerabilityDetails{SuggestedFixedVersion: "3.4.5"},
			expected:        "just-a-branch-41b1f45136b25e3624b15999bd57a476",
			description:     "Custom template without inputs",
		},
	}
	for _, test := range testCases {
		t.Run(test.expected, func(t *testing.T) {
			commitMessage, err := test.gitManager.GenerateFixBranchName("md5Branch", test.impactedPackage, test.fixVersion.SuggestedFixedVersion)
			assert.NoError(t, err)
			assert.Equal(t, test.expected, commitMessage)
		})
	}
}

func TestGitManager_GeneratePullRequestTitle(t *testing.T) {
	testCases := []struct {
		gitManager      GitManager
		impactedPackage string
		fixVersion      VulnerabilityDetails
		expected        string
		description     string
	}{
		{
			gitManager:      GitManager{customTemplates: CustomTemplates{pullRequestTitleTemplate: "[CustomPR] update ${IMPACTED_PACKAGE} to ${FIX_VERSION}"}},
			impactedPackage: "mquery",
			fixVersion:      VulnerabilityDetails{SuggestedFixedVersion: "3.4.5"},
			expected:        "[CustomPR] update mquery to 3.4.5",
			description:     "Custom template",
		},
		{
			gitManager:      GitManager{customTemplates: CustomTemplates{pullRequestTitleTemplate: "[CustomPR] update ${IMPACTED_PACKAGE}"}},
			impactedPackage: "mquery",
			fixVersion:      VulnerabilityDetails{SuggestedFixedVersion: "3.4.5"},
			expected:        "[CustomPR] update mquery",
			description:     "Custom template one var",
		},
		{
			gitManager:      GitManager{customTemplates: CustomTemplates{pullRequestTitleTemplate: ""}},
			impactedPackage: "mquery",
			fixVersion:      VulnerabilityDetails{SuggestedFixedVersion: "3.4.5"},
			expected:        "[🐸 Frogbot] Update version of mquery to 3.4.5",
			description:     "No prefix",
		},
	}
	for _, test := range testCases {
		t.Run(test.expected, func(t *testing.T) {
			titleOutput := test.gitManager.GeneratePullRequestTitle(test.impactedPackage, test.fixVersion.SuggestedFixedVersion)
			assert.Equal(t, test.expected, titleOutput)
		})
	}
}

func TestGitManager_GenerateAggregatedFixBranchName(t *testing.T) {
	testCases := []struct {
		gitManager GitManager
		baseBranch string
		expected   string
		desc       string
	}{
		{
			expected:   "frogbot-update-e4e1fa318f12b3bed84b13ae5c293108-dependencies-main",
			baseBranch: "main",
			desc:       "No template",
			gitManager: GitManager{},
		}, {
			expected:   "frogbot-update-144734671657efb7f0d252bd99ca25d8-dependencies-v2",
			baseBranch: "v2",
			desc:       "No template",
			gitManager: GitManager{},
		},
		{
			expected:   "[feature]-e4e1fa318f12b3bed84b13ae5c293108-main",
			baseBranch: "main",
			desc:       "Custom template hash only",
			gitManager: GitManager{customTemplates: CustomTemplates{branchNameTemplate: "[feature]-${BRANCH_NAME_HASH}"}},
		}, {
			expected:   "[feature]-697bdb58caaed95527fc709da59ca47f-master",
			baseBranch: "master",
			desc:       "Custom template hash only",
			gitManager: GitManager{customTemplates: CustomTemplates{branchNameTemplate: "[feature]-${BRANCH_NAME_HASH}"}},
		},
	}
	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			titleOutput, err := test.gitManager.GenerateAggregatedFixBranchName(test.baseBranch, []techutils.Technology{techutils.Go})
			assert.NoError(t, err)
			assert.Equal(t, test.expected, titleOutput)
		})
	}
}

func TestGitManager_GenerateAggregatedCommitMessage(t *testing.T) {
	testCases := []struct {
		gitManager GitManager
		expected   string
	}{
		{gitManager: GitManager{}, expected: "[🐸 Frogbot] Update Pipenv dependencies"},
		{gitManager: GitManager{customTemplates: CustomTemplates{commitMessageTemplate: "custom_template"}}, expected: "custom_template"},
	}
	for _, test := range testCases {
		t.Run(test.expected, func(t *testing.T) {
			commit := test.gitManager.GenerateAggregatedCommitMessage([]techutils.Technology{techutils.Pipenv})
			assert.Equal(t, commit, test.expected)
		})
	}
}

func TestGitManager_Checkout(t *testing.T) {
	testCases := []struct {
		withLocalChanges bool
	}{
		{
			withLocalChanges: false,
		},
		{
			withLocalChanges: true,
		},
	}

	for _, test := range testCases {
		t.Run(fmt.Sprintf("test branch checkout: local changes:%t", test.withLocalChanges), func(t *testing.T) {
			tmpDir, err := fileutils.CreateTempDir()
			assert.NoError(t, err)
			defer func() {
				assert.NoError(t, fileutils.RemoveTempDir(tmpDir))
			}()
			var restoreWd func() error
			restoreWd, err = Chdir(tmpDir)
			assert.NoError(t, err)
			defer func() {
				assert.NoError(t, restoreWd())
			}()
			gitManager := createFakeDotGit(t, tmpDir)
			// Get the current branch that is set as HEAD
			headRef, err := gitManager.localGitRepository.Head()
			assert.NoError(t, err)
			assert.Equal(t, headRef.Name().Short(), "master")

			if test.withLocalChanges {
				// Create new file in master branch
				tempFilePath := filepath.Join(tmpDir, "myFile.txt")
				var file *os.File
				file, err = os.Create(tempFilePath)
				assert.NoError(t, err)
				assert.NoError(t, file.Close())

				// Create 'dev' branch and checkout
				err = gitManager.CreateBranchAndCheckout("dev", true)
				assert.NoError(t, err)

				// Verify that temp file exist in new branch
				var fileExists bool
				fileExists, err = fileutils.IsFileExists(tempFilePath, false)
				assert.NoError(t, err)
				assert.True(t, fileExists)
			} else {
				// Create 'dev' branch and checkout
				err = gitManager.CreateBranchAndCheckout("dev", false)
				assert.NoError(t, err)
			}

			var currBranch string
			currBranch, err = getCurrentBranch(gitManager.localGitRepository)
			assert.NoError(t, err)
			assert.Equal(t, "dev", currBranch)

			// Checkout back to 'master'
			assert.NoError(t, gitManager.Checkout("master"))
			currBranch, err = getCurrentBranch(gitManager.localGitRepository)
			assert.NoError(t, err)
			assert.Equal(t, "master", currBranch)
		})
	}
}

func createFakeDotGit(t *testing.T, testPath string) *GitManager {
	// Initialize a new in-memory repository
	repo, err := git.PlainInit(testPath, false)
	assert.NoError(t, err)
	// Create a new file and add it to the worktree
	filename := "README.md"
	content := []byte("# My New Repository\n\nThis is a sample repository created using go-git.")
	err = os.WriteFile(filename, content, 0644)
	assert.NoError(t, err)
	worktree, err := repo.Worktree()
	assert.NoError(t, err)
	_, err = worktree.Add(filename)
	assert.NoError(t, err)
	// Commit the changes to the new main branch
	_, err = worktree.Commit("Initial commit", &git.CommitOptions{
		Author: &object.Signature{
			Name:  "Your Name",
			Email: "your@email.com",
		},
	})
	assert.NoError(t, err)
	manager := NewGitManager().SetDryRun(true, testPath)
	manager.localGitRepository = repo
	manager.remoteName = vcsutils.RemoteName
	assert.NoError(t, err)
	return manager
}

func TestGitManager_SetRemoteGitUrl(t *testing.T) {
	testCases := []struct {
		description       string
		dotGitExists      bool
		remoteGitUrl      string
		remoteHttpsGitUrl string
		existingRemoteUrl string
		expectedError     error
		expectedGitUrl    string
	}{
		{
			description:       "DotGit does not exist",
			dotGitExists:      false,
			remoteHttpsGitUrl: "https://example.com/owner/repo.git",
			expectedGitUrl:    "https://example.com/owner/repo.git",
		},
		{
			description:       "DotGit exists, no remote found",
			dotGitExists:      true,
			remoteHttpsGitUrl: "https://example.com/owner/repo.git",
			expectedError:     errors.New("'git remote origin' failed with error: remote not found"),
		},
		{
			description:       "DotGit exists, remote URL exists with HTTPS protocol",
			dotGitExists:      true,
			remoteHttpsGitUrl: "https://example.com/owner/repo.git",
			existingRemoteUrl: "https://example.com/owner/repo.git",
			expectedGitUrl:    "https://example.com/owner/repo.git",
		},
		{
			description:       "DotGit exists, remote URL is not HTTPS",
			dotGitExists:      true,
			remoteHttpsGitUrl: "https://example.com/owner/repo.git",
			existingRemoteUrl: "ssh://example.com/owner/repo.git",
			// Should be updated to the new HTTPS URL
			expectedGitUrl: "https://example.com/owner/repo.git",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			tmpDir, err := fileutils.CreateTempDir()
			assert.NoError(t, err)
			baseDir, err := os.Getwd()
			assert.NoError(t, err)
			restoreFunc := tests.ChangeDirWithCallback(t, baseDir, tmpDir)
			defer restoreFunc()
			gm := NewGitManager().SetDryRun(true, tmpDir)
			if tc.dotGitExists {
				gm = createFakeDotGit(t, tmpDir)
			}
			if tc.existingRemoteUrl != "" {
				_, err = gm.localGitRepository.CreateRemote(&config.RemoteConfig{
					Name: vcsutils.RemoteName,
					URLs: []string{tc.existingRemoteUrl},
				})
				assert.NoError(t, err)
			}
			_, err = gm.SetRemoteGitUrl(tc.remoteHttpsGitUrl)
			if err != nil {
				assert.EqualError(t, tc.expectedError, err.Error())
			} else {
				assert.Nil(t, err)
			}
			assert.Equal(t, tc.expectedGitUrl, gm.remoteGitUrl)
		})
	}
}

func TestGetAggregatedPullRequestTitle(t *testing.T) {
	defaultGm := GitManager{}
	testsCases := []struct {
		tech     []techutils.Technology
		gm       GitManager
		expected string
	}{
		{gm: defaultGm, tech: []techutils.Technology{}, expected: "[🐸 Frogbot] Update dependencies"},
		{gm: defaultGm, tech: []techutils.Technology{techutils.Maven}, expected: "[🐸 Frogbot] Update Maven dependencies"},
		{gm: defaultGm, tech: []techutils.Technology{techutils.Gradle}, expected: "[🐸 Frogbot] Update Gradle dependencies"},
		{gm: defaultGm, tech: []techutils.Technology{techutils.Npm}, expected: "[🐸 Frogbot] Update npm dependencies"},
		{gm: defaultGm, tech: []techutils.Technology{techutils.Yarn}, expected: "[🐸 Frogbot] Update Yarn dependencies"},
		{gm: GitManager{customTemplates: CustomTemplates{pullRequestTitleTemplate: "[Dependencies] My template "}}, tech: []techutils.Technology{techutils.Yarn}, expected: "[Dependencies] My template - Yarn Dependencies"},
		{gm: GitManager{customTemplates: CustomTemplates{pullRequestTitleTemplate: ""}}, tech: []techutils.Technology{techutils.Yarn}, expected: "[🐸 Frogbot] Update Yarn dependencies"},
		{gm: GitManager{customTemplates: CustomTemplates{pullRequestTitleTemplate: "[Feature] %s hello"}}, tech: []techutils.Technology{techutils.Yarn}, expected: "[Feature] hello - Yarn Dependencies"},
		{gm: GitManager{customTemplates: CustomTemplates{pullRequestTitleTemplate: "[Feature] %s %d hello"}}, tech: []techutils.Technology{techutils.Yarn}, expected: "[Feature] hello - Yarn Dependencies"},
		{gm: GitManager{customTemplates: CustomTemplates{pullRequestTitleTemplate: "[Feature] %s %d hello"}}, tech: []techutils.Technology{techutils.Yarn}, expected: "[Feature] hello - Yarn Dependencies"},
		{gm: GitManager{customTemplates: CustomTemplates{pullRequestTitleTemplate: "[Feature] %s %f hello"}}, tech: []techutils.Technology{techutils.Yarn, techutils.Go}, expected: "[Feature] hello - Yarn,Go Dependencies"},
		{gm: GitManager{customTemplates: CustomTemplates{pullRequestTitleTemplate: "[Feature] %s %d hello"}}, tech: []techutils.Technology{techutils.Yarn, techutils.Go, techutils.Npm}, expected: "[Feature] hello - Yarn,Go,npm Dependencies"},
		{gm: GitManager{customTemplates: CustomTemplates{pullRequestTitleTemplate: "[Feature] %s %d hello"}}, tech: []techutils.Technology{}, expected: "[Feature] hello"},
	}
	for _, test := range testsCases {
		t.Run(test.expected, func(t *testing.T) {
			title := test.gm.GenerateAggregatedPullRequestTitle(test.tech)
			assert.Equal(t, test.expected, title)
		})
	}
}

func TestRemoveCredentialsFromUrlIfNeeded(t *testing.T) {
	testsCases := []struct {
		url      string
		expected string
	}{
		{url: "https://example.com/owner/repo.git", expected: "https://example.com/owner/repo.git"},
		{url: "https://<user>:<token>@git.jfrog.info/scm/jfrog/some-service.git", expected: "https://git.jfrog.info/scm/jfrog/some-service.git"},
		{url: "http://example.com/owner/repo.git", expected: "http://example.com/owner/repo.git"},
		{url: "http://<user>:<token>@git.jfrog.info/scm/jfrog/some-service.git", expected: "http://git.jfrog.info/scm/jfrog/some-service.git"},
		{url: "git://example.com/owner/repo.git", expected: "git://example.com/owner/repo.git"},
		{url: "git://<user>:<token>@git.jfrog.info/scm/jfrog/some-service.git", expected: "git://git.jfrog.info/scm/jfrog/some-service.git"},
		{url: "git://<user>:<token>@git.jfrog.info/scm/jfrog/some-service.git", expected: "git://git.jfrog.info/scm/jfrog/some-service.git"},
		{url: "ssh://git@example.com/owner/repo.git", expected: "ssh://git@example.com/owner/repo.git"},
	}

	for _, testcase := range testsCases {
		t.Run("case: "+testcase.url, func(t *testing.T) {
			cleanUrl := removeCredentialsFromUrlIfNeeded(testcase.url)
			assert.Equal(t, testcase.expected, cleanUrl)
		})
	}
}
