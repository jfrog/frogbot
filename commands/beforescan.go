package commands

import (
	"context"
	"fmt"

	"github.com/jfrog/froggit-go/vcsclient"
	clitool "github.com/urfave/cli/v2"
)

func BeforeScan(c *clitool.Context) error {
	params, client, err := getParamsAndClient(false)
	if err != nil {
		return err
	}

	labelInfo, err := client.GetLabel(context.Background(), params.repoOwner, params.repo, string(labelName))
	if err != nil {
		return err
	}
	if labelInfo == nil {
		err = client.CreateLabel(context.Background(), params.repoOwner, params.repo, vcsclient.LabelInfo{
			Name:        string(labelName),
			Description: string(labelDescription),
			Color:       string(labelColor),
		})
		if err != nil {
			return err
		}
		return &DoNotScan{reason: fmt.Sprintf("Label %s was created. Please label this pull request to trigger an Xray scan.", string(labelName))}
	}

	labels, err := client.ListPullRequestLabels(context.Background(), params.repoOwner, params.repo, params.pullRequestID)
	if err != nil {
		return err
	}
	for _, label := range labels {
		if label == string(labelName) {
			err = client.UnlabelPullRequest(context.Background(), params.repoOwner, params.repo, string(labelName), params.pullRequestID)
			// Trigger scan or return err
			return err
		}
	}
	return &DoNotScan{reason: fmt.Sprintf("Please add %s label to trigger an Xray scan.", string(labelName))}
}
