package main

import (
	"strings"

	"github.com/lixiangzhong/sshs/pkg/secureshell"

	"github.com/urfave/cli/v2"
)

func SCPAction(c *cli.Context) error {
	if c.Args().Len() != 2 {
		return cli.Exit("need 2 args <src> <dst>", 1)
	}
	src := c.Args().Get(0)
	dst := c.Args().Get(1)
	var keywords []string
	if strings.Index(src, ":") > 0 {
		keywords = append(keywords, src[:strings.Index(src, ":")])
		src = src[strings.Index(src, ":"):]
	}
	if strings.Index(dst, ":") > 0 {
		keywords = append(keywords, dst[:strings.Index(dst, ":")])
		dst = dst[strings.Index(dst, ":"):]
	}
	client, err := ChooseHost(keywords...)
	if err != nil {
		return err
	}
	sc, err := secureshell.SftpClient(client)
	if err != nil {
		return cli.Exit(err, 1)
	}
	err = secureshell.Scp(c.Context, sc, c.Bool("gzip"), c.Bool("r"), src, dst)
	if err != nil {
		return cli.Exit(err, 1)
	}
	return nil
}
