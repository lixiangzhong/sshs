package main

import (
	"log"
	"sshs/secureshell"
)

func main() {
	c, err := secureshell.Dial("root", "127.0.0.1:22", secureshell.PasswordAuth("this is password"))
	if err != nil {
		log.Fatal(err)
	}
	err = secureshell.Terminal(c)
	if err != nil {
		log.Println(err)
	}
}
