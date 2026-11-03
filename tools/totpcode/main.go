// Command totpcode prints the current TOTP code for a base32 secret (manual testing helper).
package main

import (
	"fmt"
	"os"
	"time"

	"github.com/serverkeeper/serverkeeper/internal/auth"
)

func main() {
	c, err := auth.TOTPCode(os.Args[1], time.Now())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(c)
}
