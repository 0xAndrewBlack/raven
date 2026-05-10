package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/mirkobrombin/Raven/internal/compat"
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: compat <raven.log> [raven.log...]\n")
	}
	flag.Parse()
	if flag.NArg() == 0 {
		flag.Usage()
		os.Exit(2)
	}

	report, err := compat.ParseFiles(flag.Args())
	if err != nil {
		fmt.Fprintf(os.Stderr, "compat: %v\n", err)
		os.Exit(1)
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		fmt.Fprintf(os.Stderr, "compat: %v\n", err)
		os.Exit(1)
	}
}
