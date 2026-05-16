package main

import (
	"fmt"
	"os"

	"github.com/qquuasar/netcheck/internal/check"
	"github.com/qquuasar/netcheck/internal/output"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Println("usage: netcheck <url>")
		fmt.Println("example: netcheck https://example.com")
		os.Exit(1)
	}

	target := os.Args[1]

	result, err := check.Run(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	output.PrintHuman(result)
}
