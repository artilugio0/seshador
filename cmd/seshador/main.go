package main

import (
	"fmt"
	"os"
)

func main() {
	seshadorCmd := newSeshadorCmd()

	if err := seshadorCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
