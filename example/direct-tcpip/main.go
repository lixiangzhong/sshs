package main

import (
	"io"
	"log"
	"net"

	"github.com/lixiangzhong/sshs/pkg/secureshell"
)

func main() {
	l, err := net.Listen("tcp", ":3434")
	if err != nil {
		log.Fatal(err)
	}
	log.Println("listen", l.Addr())
	for {
		lconn, err := l.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		go handleConnIn(lconn)
	}
}

func handleConnIn(lconn net.Conn) {
	defer lconn.Close()
	c, err := secureshell.Dial("root", "127.0.0.1:22", secureshell.PasswordAuth("this is password"))
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()
	rconn, err := c.Dial("tcp", "127.0.0.1:22")
	if err != nil {
		log.Fatal(err)
	}
	defer rconn.Close()
	go io.Copy(lconn, rconn)
	io.Copy(rconn, lconn)
}
