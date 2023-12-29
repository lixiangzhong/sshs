package main

import (
	"context"
	"log"
	"net"

	"github.com/armon/go-socks5"
	"github.com/urfave/cli/v2"
)

func Socks5Action(ctx *cli.Context) error {
	client, err := ChooseHost(ctx.Args().Slice()...)
	if err != nil {
		return err
	}
	go clientKeepAlive(client)
	laddr := ctx.String("laddr")
	cnf := socks5.Config{
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return client.Dial(network, addr)
		},
	}
	sserver, err := socks5.New(&cnf)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", laddr)
	if err != nil {
		return err
	}
	log.Println("socks5 server listen on", ln.Addr())
	// log.Println("copy the following command")
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	log.Printf("export https_proxy=socks5://127.0.0.1:%v http_proxy=socks5://127.0.0.1:%v all_proxy=socks5://127.0.0.1:%v", port, port, port)
	return sserver.Serve(ln)
}
