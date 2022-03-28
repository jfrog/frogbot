package utils

import (
	"fmt"
	"os"

	"github.com/jfrog/froggit-go/vcsclient"
)

var ErrLabelCreated = fmt.Errorf("label '%s' was created. Please label this pull request to trigger an Xray scan", string(LabelName))
var ErrUnlabele = fmt.Errorf("please add the '%s' label to trigger an Xray scan", string(LabelName))

func GetParamsAndClient() (*FrogbotParams, vcsclient.VcsClient, error) {
	params, err := extractParamsFromEnv()
	if err != nil {
		return nil, nil, err
	}
	client, err := vcsclient.NewClientBuilder(params.GitProvider).Token(params.Token).Build()
	return &params, client, err
}

func Chdir(dir string) (func(), error) {
	wd, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	err = os.Chdir(dir)
	if err != nil {
		return nil, err
	}
	return func() {
		e := os.Chdir(wd)
		if err == nil {
			err = e
		}
	}, nil
}
