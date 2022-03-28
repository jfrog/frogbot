package utils

import (
	"fmt"
	"os"
)

var ErrLabelCreated = fmt.Errorf("label '%s' was created. Please label this pull request to trigger an Xray scan", string(LabelName))
var ErrUnlabel = fmt.Errorf("please add the '%s' label to trigger an Xray scan", string(LabelName))

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
