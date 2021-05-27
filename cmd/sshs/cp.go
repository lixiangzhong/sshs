package main

import (
	"os"
	"path/filepath"
	"sshs/copy"
	"sshs/secureshell"
	"strings"

	"github.com/spf13/afero"
	"github.com/spf13/afero/sftpfs"
	"github.com/urfave/cli/v2"
)

func SCPAction(c *cli.Context) error {
	if c.Args().Len() != 2 {
		return cli.Exit("need 2 args <src> <dst>", 1)
	}
	workdir, err := os.Getwd()
	if err != nil {
		return cli.Exit(err, 1)
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
	var cp copy.Copy
	if strings.Contains(src, ":") { //remote to local
		src = src[1:]
		cp = copy.New(sftpfs.New(sc), afero.NewOsFs())
		if !filepath.IsAbs(dst) {
			dst = filepath.Join(workdir, dst)
		}
	} else {
		dst = dst[1:]
		cp = copy.New(afero.NewOsFs(), sftpfs.New(sc))
		if !filepath.IsAbs(src) {
			src = filepath.Join(workdir, src)
		}
	}
	if c.Bool("r") { //传输目录
		err = cp.Dir(src, dst, copy.ProgressBar())
	} else {
		err = cp.File(src, dst, copy.ProgressBar())
	}
	if err != nil {
		return cli.Exit(err, 1)
	}
	return nil
}
