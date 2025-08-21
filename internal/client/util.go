package client

import (
	"fmt"
	"math/rand"
)

func GeneratePassword(n int) string {
	permittedChars := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890+*%&/()=?!$£{}:;.,-\\")
	retVal := make([]rune, n)
	for i := range n {
		retVal[i] = permittedChars[rand.Intn(len(permittedChars))]
	}

	fmt.Println(string(retVal))

	return string(retVal)
}
