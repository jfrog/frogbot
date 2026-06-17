package main

import (
	"fmt"
	"github.com/google/uuid"
	"github.com/sassoftware/go-rpmutils"
)

func main() {
	fmt.Println("test")
	uuid.New()
	_, _ = rpmutils.ReadRpm(nil)
}
