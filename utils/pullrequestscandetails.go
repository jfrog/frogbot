package utils

import (
	"github.com/jfrog/froggit-go/vcsclient"
)

type PullRequestScanDetails struct {
	*ScanDetails
}

func NewPullRequestScanDetails(client vcsclient.VcsClient, repository *Repository) *PullRequestScanDetails {
	return &PullRequestScanDetails{ScanDetails: newScanDetails(client, repository)}
}

func (prd *PullRequestScanDetails) PullRequestDetails() vcsclient.PullRequestInfo {
	return prd.git.PullRequestDetails
}
