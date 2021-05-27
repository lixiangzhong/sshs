package main

import (
	"github.com/lixiangzhong/sshs/secureshell"

	"github.com/urfave/cli/v2"
)

func SCPAction(c *cli.Context) error {
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
	src := c.Args().Get(0)
	dst := c.Args().Get(1)
	err = secureshell.Scp(sc, c.Bool("r"), src, dst)
	if err != nil {
		return cli.Exit(err, 1)
	}
	return nil
}
