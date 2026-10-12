package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/veilux-lab/keyward/internal/homebrew"
)

func main() {
	version := flag.String("version", "", "release version, such as 0.1.0")
	out := flag.String("out", "bin/homebrew", "release output directory")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: keyward-release -version <version> [-out <directory>]")
		os.Exit(2)
	}
	r, err := homebrew.Prepare(".", *version, *out)
	if err != nil {
		fmt.Fprintln(os.Stderr, "release:", err)
		os.Exit(1)
	}
	fmt.Printf("source commit: %s\narchive: %s\nsha256: %s\nformula: %s\n", r.Revision, r.Archive, r.SHA256, r.Formula)
}
