//go:build !windows

// storii-tray is the Windows tray app. On other systems, use the CLI (storii) or the browser extension.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "storii-tray runs on Windows only; on this system use the storii CLI or the browser extension.")
	os.Exit(1)
}
