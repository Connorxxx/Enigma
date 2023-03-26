package main

import (
	"fmt"
	"strings"

	"github.com/connorxxx/enigma/mobile"
	"github.com/gofrs/uuid"
)

func main() {
	u, err := uuid.NewV4()
	if err != nil {
		panic("failed to generate UUID " + err.Error())
	}
	uuids := strings.ReplaceAll(u.String(), "-", "")

	key := []byte(uuids)
	s, err := mobile.EncryptWithGCM(key, "hello_world")
	if err != nil {
		panic("Error: " + err.Error())
	}
	o, err := mobile.DecryptbyGCM(key, s)
	if err != nil {
		panic("Error: " + err.Error())
	}
	fmt.Println(uuids)
	fmt.Println(s)
	fmt.Println(o)
}
