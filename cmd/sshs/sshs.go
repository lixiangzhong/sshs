package main

import (
	"log"
	"os"
	"sshs/secureshell"

	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/ssh"
)

var cfg []Config

func main() {
	log.SetFlags(log.Lshortfile)
	app := &cli.App{
		Name:  "sshs",
		Usage: "make ssh scp easy",
		Action: func(c *cli.Context) error {
			client, err := ChooseHost()
			if err != nil {
				return err
			}
			err = secureshell.Terminal(client)
			if err != nil {
				return cli.Exit(err, 1)
			}
			return nil
		},
		Commands: []*cli.Command{
			{
				Name:    "scp",
				Aliases: []string{"cp"},
				Usage:   "scp file or dir",
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:    "r",
						Aliases: []string{"recursively"},
						Usage:   "scp dir",
						Value:   false,
					},
				},
				Action: func(c *cli.Context) error {
					if c.Args().Len() != 2 {
						return cli.Exit("need 2 args <src> <dst>", 1)
					}
					client, err := ChooseHost()
					if err != nil {
						return err
					}
					sc, err := secureshell.SftpClient(client)
					if err != nil {
						return cli.Exit(err, 1)
					}
					err = secureshell.Scp(sc, c.Bool("r"), c.Args().Get(0), c.Args().Get(1))
					if err != nil {
						return cli.Exit(err, 1)
					}
					return nil
				},
			},
		},
	}
	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

func ChooseHost() (*ssh.Client, error) {
	host := UISelect()
	return secureshell.Dial(host.Username(), host.RemoteAddr(), host.AuthMethod()...)
}
