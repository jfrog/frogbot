package dependency

import (
	"fmt"
	"golang.org/x/crypto/ssh" // #nosec
	"rsc.io/quote"            // #nosec
)

func PrintHello(ssha ssh.AuthMethod) {
	fmt.Println(quote.Hello()) // #nosec
	return
}
