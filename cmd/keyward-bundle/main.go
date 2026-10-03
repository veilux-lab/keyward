package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/veilux-lab/keyward/internal/appbundle"
)

func main() {
	cli := flag.String("cli", "bin/keyward", "CLI to package")
	app := flag.String("app", "bin/keyward-app", "status app to package")
	out := flag.String("out", "bin/Keyward.app", "output bundle")
	flag.Parse()
	if err := appbundle.Build(*out, *cli, *app); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
