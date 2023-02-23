package main

import (
	"fmt"
	"github.com/go-git/go-git"
	"github.com/google/uuid"
	"github.com/sassoftware/go-rpmutils"
)

func main() {
	fmt.Println("test")
	uuid.New()
	_ = git.Refs{}
	_, _ = rpmutils.ReadRpm(nil)
}
