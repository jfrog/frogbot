package dependency

import (
	"fmt"
	"golang.org/x/crypto/ssh"
	"rsc.io/quote"
)

func PrintHello(ssha ssh.AuthMethod) {
	fmt.Println(quote.Hello())
	return
}
