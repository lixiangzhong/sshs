package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/ssh"
)

func clientKeepAlive(c *ssh.Client) {
	tk := time.NewTicker(time.Second * 15)
	defer tk.Stop()
	for range tk.C {
		_, _, err := c.SendRequest("keepalive@openssh.com", false, nil)
		if err != nil {
			fmt.Println(err)
			return
		}
	}
}

func ForwardAction(ctx *cli.Context) error {
	client, err := ChooseHost(ctx.Args().Slice()...)
	if err != nil {
		return err
	}
	go clientKeepAlive(client)
	laddr := ctx.String("laddr")
	raddr := ctx.String("raddr")
	l, err := net.Listen("tcp", laddr)
	if err != nil {
		return cli.Exit(err, 1)
	}
	defer l.Close()
	log.Printf("%v==>[%v]==>%v\n", l.Addr(), client.RemoteAddr(), raddr)
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

func ListenAction(ctx *cli.Context) error {
	client, err := ChooseHost(ctx.Args().Slice()...)
	if err != nil {
		return err
	}
	go clientKeepAlive(client)
	laddr := ctx.String("laddr")
	raddr := ctx.String("raddr")
	ln, err := client.Listen("tcp", raddr)
	if err != nil {
		return err
	}
	log.Printf("%v<==%v\n", laddr, ln.Addr())
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		handleListenConn(conn, laddr)
	}
}

func handleListenConn(rconn net.Conn, laddr string) {
	log.Printf("%v<==%v<==%v\n", laddr, rconn.LocalAddr(), rconn.RemoteAddr())
	defer rconn.Close()
	lconn, err := net.Dial("tcp", laddr)
	if err != nil {
		log.Println(err)
		return
	}
	defer lconn.Close()
	go func() {
		io.Copy(rconn, lconn)
		lconn.Close()
		rconn.Close()
	}()
	io.Copy(lconn, rconn)
}
