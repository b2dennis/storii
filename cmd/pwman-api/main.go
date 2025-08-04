package main

import "b2dennis/pwman-api/internal/server"

func main() {
	server := server.NewServer()
	server.Run()
}
