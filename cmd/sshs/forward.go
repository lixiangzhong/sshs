package main

import (
	"io"
	"log"
	"net"

	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/ssh"
)

func ForwardAction(ctx *cli.Context) error {
	client, err := ChooseHost(ctx.Args().Slice()...)
	if err != nil {
		return err
	}
	laddr := ctx.String("laddr")
	raddr := ctx.String("raddr")
	l, err := net.Listen("tcp", laddr)
	if err != nil {
		return cli.Exit(err, 1)
	}
	log.Println("listen", l.Addr())
	defer l.Close()
	for {
		conn, err := l.Accept()
		if err != nil {
			return cli.Exit(err, 1)
		}
		go handleForwordConn(client, conn, raddr)
	}
}

func handleForwordConn(c *ssh.Client, conn net.Conn, raddr string) {
	log.Printf("%v-->[%v<=>%v]-->%v\n", conn.RemoteAddr(), conn.LocalAddr(), c.RemoteAddr(), raddr)
	defer log.Println(conn.RemoteAddr(), "disconnect")
	defer conn.Close()
	rconn, err := c.Dial("tcp", raddr)
	if err != nil {
		log.Println(err)
		return
	}
	defer rconn.Close()
	go func() {
		io.Copy(rconn, conn)
		conn.Close()
		rconn.Close()
	}()
	io.Copy(conn, rconn)
}
