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

func Chdir(dir string) (cbk func(), err error) {
	wd, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	if err = os.Chdir(dir); err != nil {
		return nil, err
	}
	return func() { err = os.Chdir(wd) }, err
}
