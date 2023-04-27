package utils

import (
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestGitManager_GenerateCommitMessage(t *testing.T) {
	tests := []struct {
		gitManager      GitManager
		impactedPackage string
		fixVersion      FixVersionInfo
		expected        string
		description     string
	}{
		{
			gitManager:      GitManager{customTemplates: CustomTemplates{commitMessageTemplate: "<type>: bump ${IMPACTED_PACKAGE}"}},
			impactedPackage: "mquery",
			fixVersion:      FixVersionInfo{FixVersion: "3.4.5"},
			expected:        "<type>: bump mquery",
			description:     "Custom prefix",
		},
		{
			gitManager:      GitManager{customTemplates: CustomTemplates{commitMessageTemplate: "<type>[scope]: Upgrade package ${IMPACTED_PACKAGE} to ${FIX_VERSION}"}},
			impactedPackage: "mquery", fixVersion: FixVersionInfo{FixVersion: "3.4.5"},
			expected:    "<type>[scope]: Upgrade package mquery to 3.4.5",
			description: "Default template",
		}, {
			gitManager:      GitManager{customTemplates: CustomTemplates{commitMessageTemplate: ""}},
			impactedPackage: "mquery", fixVersion: FixVersionInfo{FixVersion: "3.4.5"},
			expected:    "Upgrade mquery to 3.4.5",
			description: "Default template",
		},
	}
	for _, test := range tests {
		t.Run(test.expected, func(t *testing.T) {
			commitMessage := test.gitManager.GenerateCommitMessage(test.impactedPackage, test.fixVersion.FixVersion)
			assert.Equal(t, test.expected, commitMessage)
		})
	}
}

func TestGitManager_GenerateFixBranchName(t *testing.T) {
	tests := []struct {
		gitManager      GitManager
		impactedPackage string
		fixVersion      FixVersionInfo
		expected        string
		description     string
	}{
		{
			gitManager:      GitManager{customTemplates: CustomTemplates{branchNameTemplate: "[Feature]-${IMPACTED_PACKAGE}-${BRANCH_NAME_HASH}"}},
			impactedPackage: "mquery",
			fixVersion:      FixVersionInfo{FixVersion: "3.4.5"},
			expected:        "[Feature]-mquery-41b1f45136b25e3624b15999bd57a476",
			description:     "Custom template",
		},
		{
			gitManager:      GitManager{customTemplates: CustomTemplates{branchNameTemplate: ""}},
			impactedPackage: "mquery",
			fixVersion:      FixVersionInfo{FixVersion: "3.4.5"},
			expected:        "frogbot-mquery-41b1f45136b25e3624b15999bd57a476",
			description:     "No template",
		}, {
			gitManager:      GitManager{customTemplates: CustomTemplates{branchNameTemplate: "just-a-branch-${BRANCH_NAME_HASH}"}},
			impactedPackage: "mquery",
			fixVersion:      FixVersionInfo{FixVersion: "3.4.5"},
			expected:        "just-a-branch-41b1f45136b25e3624b15999bd57a476",
			description:     "Custom template without inputs",
		},
	}
	for _, test := range tests {
		t.Run(test.expected, func(t *testing.T) {
			commitMessage, err := test.gitManager.GenerateFixBranchName("md5Branch", test.impactedPackage, test.fixVersion.FixVersion)
			assert.NoError(t, err)
			assert.Equal(t, test.expected, commitMessage)
		})
	}
}

func TestGitManager_GeneratePullRequestTitle(t *testing.T) {
	tests := []struct {
		gitManager      GitManager
		impactedPackage string
		fixVersion      FixVersionInfo
		expected        string
		description     string
	}{
		{
			gitManager:      GitManager{customTemplates: CustomTemplates{pullRequestTitleTemplate: "[CustomPR] update ${IMPACTED_PACKAGE} to ${FIX_VERSION}"}},
			impactedPackage: "mquery",
			fixVersion:      FixVersionInfo{FixVersion: "3.4.5"},
			expected:        "[CustomPR] update mquery to 3.4.5",
			description:     "Custom template",
		},
		{
			gitManager:      GitManager{customTemplates: CustomTemplates{pullRequestTitleTemplate: "[CustomPR] update ${IMPACTED_PACKAGE}"}},
			impactedPackage: "mquery",
			fixVersion:      FixVersionInfo{FixVersion: "3.4.5"},
			expected:        "[CustomPR] update mquery",
			description:     "Custom template one var",
		},
		{
			gitManager:      GitManager{customTemplates: CustomTemplates{pullRequestTitleTemplate: ""}},
			impactedPackage: "mquery",
			fixVersion:      FixVersionInfo{FixVersion: "3.4.5"},
			expected:        "[🐸 Frogbot] Upgrade mquery to 3.4.5",
			description:     "No prefix",
		},
	}
	for _, test := range tests {
		t.Run(test.expected, func(t *testing.T) {
			titleOutput := test.gitManager.GeneratePullRequestTitle(test.impactedPackage, test.fixVersion.FixVersion)
			assert.Equal(t, test.expected, titleOutput)
		})
	}
}

func TestGitManager_GenerateAggregatedFixBranchName(t *testing.T) {
	tests := []struct {
		fixVersionMapFirst  map[string]*FixVersionInfo
		fixVersionMapSecond map[string]*FixVersionInfo
		gitManager          GitManager
		equal               bool
		desc                string
	}{
		{
			fixVersionMapFirst: map[string]*FixVersionInfo{
				"pkg":  {FixVersion: "1.2.3", PackageType: coreutils.Npm, DirectDependency: false},
				"pkg2": {FixVersion: "1.5.3", PackageType: coreutils.Npm, DirectDependency: false}},
			fixVersionMapSecond: map[string]*FixVersionInfo{
				"pkg":  {FixVersion: "1.2.3", PackageType: coreutils.Npm, DirectDependency: false},
				"pkg2": {FixVersion: "1.5.3", PackageType: coreutils.Npm, DirectDependency: false}},
			equal: true, desc: "should be equal",
			gitManager: GitManager{},
		},
		{
			fixVersionMapFirst: map[string]*FixVersionInfo{
				"pkg":  {FixVersion: "1.2.3", PackageType: coreutils.Npm, DirectDependency: false},
				"pkg2": {FixVersion: "1.5.3", PackageType: coreutils.Npm, DirectDependency: false},
			},
			fixVersionMapSecond: map[string]*FixVersionInfo{
				"pkgOther": {FixVersion: "1.2.3", PackageType: coreutils.Npm, DirectDependency: false},
				"pkg2":     {FixVersion: "1.5.3", PackageType: coreutils.Npm, DirectDependency: false}},
			equal:      false,
			desc:       "should not be equal",
			gitManager: GitManager{},
		},
		{
			fixVersionMapFirst: map[string]*FixVersionInfo{
				"pkg":  {FixVersion: "1.2.3", PackageType: coreutils.Npm, DirectDependency: false},
				"pkg2": {FixVersion: "1.5.3", PackageType: coreutils.Npm, DirectDependency: false},
			},
			fixVersionMapSecond: map[string]*FixVersionInfo{
				"pkgOther": {FixVersion: "1.2.3", PackageType: coreutils.Npm, DirectDependency: false},
				"pkg2":     {FixVersion: "1.5.3", PackageType: coreutils.Npm, DirectDependency: false}},
			equal:      true,
			desc:       "should be equal with template",
			gitManager: GitManager{customTemplates: CustomTemplates{branchNameTemplate: "custom"}},
		},
	}
	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			titleOutput1, err := test.gitManager.GenerateAggregatedFixBranchName(test.fixVersionMapFirst)
			assert.NoError(t, err)
			titleOutput2, err := test.gitManager.GenerateAggregatedFixBranchName(test.fixVersionMapSecond)
			assert.NoError(t, err)
			equal := titleOutput1 == titleOutput2
			assert.Equal(t, test.equal, equal)
		})
	}
}

func TestGitManager_GenerateAggregatedCommitMessage(t *testing.T) {
	tests := []struct {
		gitManager GitManager
		expected   string
	}{
		{gitManager: GitManager{}, expected: AggregatedPullRequestTitleTemplate},
		{gitManager: GitManager{customTemplates: CustomTemplates{commitMessageTemplate: "custom_template"}}, expected: "custom_template"},
	}
	for _, test := range tests {
		t.Run(test.expected, func(t *testing.T) {
			commit := test.gitManager.GenerateAggregatedCommitMessage()
			assert.Equal(t, commit, test.expected)
		})
	}
}
