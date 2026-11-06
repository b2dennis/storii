package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

const clipboardSeconds = 30

type clipTool struct{ copy, paste []string }

func clipTools() []clipTool {
	switch runtime.GOOS {
	case "darwin":
		return []clipTool{{[]string{"pbcopy"}, []string{"pbpaste"}}}
	case "windows":
		return []clipTool{{[]string{"clip.exe"}, []string{"powershell.exe", "-NoProfile", "-Command", "Get-Clipboard"}}}
	}
	var tools []clipTool
	if os.Getenv("WAYLAND_DISPLAY") != "" {
		tools = append(tools, clipTool{[]string{"wl-copy"}, []string{"wl-paste", "-n"}})
	}
	return append(tools,
		clipTool{[]string{"xclip", "-selection", "clipboard"}, []string{"xclip", "-selection", "clipboard", "-o"}},
		clipTool{[]string{"xsel", "-ib"}, []string{"xsel", "-ob"}})
}

// copyToClipboard copies s with the first tool that works. When clear is set, a detached copy of this program
// empties the clipboard after clipboardSeconds, unless something else was copied in between.
func copyToClipboard(s string, clear bool) error {
	for _, t := range clipTools() {
		if _, err := exec.LookPath(t.copy[0]); err != nil {
			continue
		}
		cmd := exec.Command(t.copy[0], t.copy[1:]...)
		cmd.Stdin = strings.NewReader(s)
		if err := cmd.Run(); err != nil {
			continue
		}
		if clear {
			sum := sha256.Sum256([]byte(s))
			if self, err := os.Executable(); err == nil {
				c := exec.Command(self, "_clear-clipboard", hex.EncodeToString(sum[:]))
				detach(c)
				c.Start()
			}
		}
		return nil
	}
	return errors.New("install wl-clipboard, xclip or xsel, or use --print")
}

func clearClipboardLater(args []string) {
	if len(args) != 1 {
		return
	}
	time.Sleep(clipboardSeconds * time.Second)
	for _, t := range clipTools() {
		out, err := exec.Command(t.paste[0], t.paste[1:]...).Output()
		if err != nil {
			continue
		}
		cur := strings.TrimRight(string(out), "\r\n")
		sum := sha256.Sum256([]byte(cur))
		if hex.EncodeToString(sum[:]) == args[0] {
			cmd := exec.Command(t.copy[0], t.copy[1:]...)
			cmd.Stdin = strings.NewReader("")
			cmd.Run()
		}
		return
	}
}
