package main

import (
	"fmt"
	"os"

	"github.com/effective-security/trustyca/server/app"
)

const (
	rcError   = 1
	rcSuccess = 0
)

func main() {
	rc := rcSuccess

	app := app.NewApp(os.Args[1:])

	err := app.Run(nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %+v\n", err)
		rc = rcError
	}
	app.Close()

	os.Exit(rc)
}
