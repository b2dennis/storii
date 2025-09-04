// The executable for the API server
package main

import "github.com/b2dennis/storii/internal/server"

func main() {
	server := server.NewServer()
	server.Run()
}
