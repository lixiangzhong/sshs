package main

import (
	"log"

	"github.com/lixiangzhong/sshs/pkg/secureshell"
)

func main() {
	c, err := secureshell.Dial("root", "127.0.0.1:22", secureshell.PasswordAuth("123456"))
	if err != nil {
		log.Fatal(err)
	}
	t, err := secureshell.NewTerminal(c)
	if err != nil {
		log.Println(err)
	}
	log.Println(t.WriteString("ip a"))
	log.Println(t.WriteString("ls"))
	log.Println(t.WriteString("exit"))
	t.Wait()
}
