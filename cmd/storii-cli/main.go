package main

import "fmt"

func main() {
	//  1. Check if config file exists -> conf.json
	//  N?
	//    1. Ask for remote (API Address)
	//    2. Validate remote (Ping endpoint)
	//    N? -> 1.
	//    3. Ask for username + password
	//    4. Validate (Login endpoint)
	//    N? -> 3.
	//    5. Save config
	//  2. Evaluate input
	//  storii set {name} {password} -> store password with given name, print confirmation
	//  storii del {name} -> delete password with given name, print confirmation
	//  storii gen {name} -> store generated password with given name, print password
	fmt.Println("Hello, World!")
}
