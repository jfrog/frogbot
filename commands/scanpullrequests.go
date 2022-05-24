package commands

import (
	"context"
	"sort"
	"strings"

	"github.com/jfrog/frogbot/commands/utils"
	"github.com/jfrog/froggit-go/vcsclient"
	clientLog "github.com/jfrog/jfrog-client-go/utils/log"
)

type ScanAllPullRequestsCmd struct {
}

func (cmd ScanAllPullRequestsCmd) Run(params *utils.FrogbotParams, client vcsclient.VcsClient) error {
	return scanAllPullRequests(params, client)
}

// Scan pull requests as follows:
// a. Retrieve all open pull requests
// b. Find the ones that should be scanned (new PRs or PRs with a 're-scan' comment)
// c. Audit the dependencies of the source and the target branches.
// d. Compare the vulnerabilities found in source and target branches, and show only the new vulnerabilities added by the pull request.
func scanAllPullRequests(params *utils.FrogbotParams, client vcsclient.VcsClient) (err error) {
	openPullRequests, err := client.ListOpenPullRequests(context.Background(), params.RepoOwner, params.Repo)
	if err != nil {
		return err
	}
	for _, pr := range openPullRequests {
		shouldScan, e := shouldScanPullRequest(params, client, int(pr.ID))
		if e != nil {
			err = e
			clientLog.Error(e)
		}
		if shouldScan {
			e = downloadAndScanPullRequest(pr, params, client)
			// If error, log it and continue to the next PR.
			if e != nil {
				err = e
				clientLog.Error(e)
			}
		}
	}
	return err
}

func shouldScanPullRequest(params *utils.FrogbotParams, client vcsclient.VcsClient, prID int) (shouldScan bool, err error) {
	pullRequestsComments, err := client.ListPullRequestComments(context.Background(), params.RepoOwner, params.Repo, prID)
	if err != nil {
		return
	}
	// Sort the comment according to time created, the newest comment should be the first one.
	sort.Slice(pullRequestsComments, func(i, j int) bool {
		return pullRequestsComments[i].Created.After(pullRequestsComments[j].Created)
	})

	for _, comment := range pullRequestsComments {
		// If this a 're-scan' request comment
		if isFrogbotRescanComment(comment.Content) {
			return true, nil
		}
		// if this is a Frogbot 'scan results' comment and not 're-scan' request comment, do not scan this pull request.
		if isFrogbotResultComment(comment.Content) {
			return false, nil
		}
	}
	// This is a new pull request, and it therefore should be scanned.
	return true, nil
}

func isFrogbotRescanComment(comment string) bool {
	return strings.ToLower(strings.TrimSpace(comment)) == utils.RescanRequestComment
}

func isFrogbotResultComment(comment string) bool {
	return strings.HasPrefix(comment, utils.GetSimplifiedTitle(utils.NoVulnerabilityBannerSource)) || strings.HasPrefix(comment, utils.GetSimplifiedTitle(utils.VulnerabilitiesBannerSource))
}

func downloadAndScanPullRequest(pr vcsclient.PullRequestInfo, params *utils.FrogbotParams, client vcsclient.VcsClient) error {
	// Download the pull request source ("from") branch
	frogbotParams := &utils.FrogbotParams{
		JFrogEnvParams: params.JFrogEnvParams,
		GitParam: utils.GitParam{
			GitProvider: params.GitProvider,
			Token:       params.Token,
			ApiEndpoint: params.ApiEndpoint,
			RepoOwner:   params.RepoOwner,
			Repo:        pr.Source.Repository,
			BaseBranch:  pr.Source.Name,
		},
	}
	wd, cleanup, err := downloadRepoToTempDir(client, frogbotParams)
	if err != nil {
		return err
	}
	// Cleanup
	defer func() {
		e := cleanup()
		if err == nil {
			err = e
		}
	}()
	restoreDir, err := utils.Chdir(wd)
	if err != nil {
		return err
	}
	defer func() {
		e := restoreDir()
		if err == nil {
			err = e
		}
	}()
	// The target branch (to) will be downloaded as part of the Frogbot scanPullRequest execution
	frogbotParams = &utils.FrogbotParams{
		JFrogEnvParams: params.JFrogEnvParams,
		GitParam: utils.GitParam{
			GitProvider:   params.GitProvider,
			Token:         params.Token,
			ApiEndpoint:   params.ApiEndpoint,
			RepoOwner:     params.RepoOwner,
			Repo:          pr.Target.Repository,
			BaseBranch:    pr.Target.Name,
			PullRequestID: int(pr.ID),
		},
		SimplifiedOutput:   true,
		InstallCommandName: params.InstallCommandName,
		InstallCommandArgs: params.InstallCommandArgs,
	}
	return scanPullRequest(frogbotParams, client)
}
