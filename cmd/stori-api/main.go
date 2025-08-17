package main

import "github.com/b2dennis/stori/internal/server"

func main() {
	server := server.NewServer()
	server.Run()
}
