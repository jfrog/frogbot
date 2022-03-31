package utils

import (
	"fmt"
	"os"
)

type errMissingEnv struct {
	variableName string
}

func (m *errMissingEnv) Error() string {
	return fmt.Sprintf("'%s' environment variable is missing", m.variableName)
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
