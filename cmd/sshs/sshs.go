package main

import (
	"sshs/secureshell"
	"strings"

	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/ssh"
)

func ChooseHost(keyword ...string) (*ssh.Client, error) {
	host, err := UISelect(keyword...)
	if err != nil {
		return nil, err
	}
	return secureshell.Dial(host.Username(), host.RemoteAddr(), host.AuthMethod()...)
}

func UISelect(keyword ...string) (Config, error) {
	cfg, err := LoadConfig(keyword...)
	if err != nil {
		return Config{}, err
	}
	root = cfg
	return uiSelect(nil, cfg)
}

func LoadConfig(keyword ...string) ([]Config, error) {
	cfg, err := loadConfig(configFileList(".sshs.yaml", "sshs.yaml", ".sshw.yaml", "sshw.yaml")...)
	if err != nil {
		return nil, err
	}
	if len(keyword) == 0 {
		return cfg, nil
	}
	var result []Config
	for _, c := range cfg {
		for _, key := range keyword {
			if strings.Contains(c.DisplayName(), key) {
				result = append(result, c)
				break
			}
		}
	}
	return result, nil
}

func TerminalAction(c *cli.Context) error {
	client, err := ChooseHost(c.Args().Slice()...)
	if err != nil {
		return err
	}
	err = secureshell.Terminal(client)
	if err != nil {
		return cli.Exit(err, 1)
	}
	return nil
}

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
	err = secureshell.Scp(sc, c.Bool("r"), c.Args().Get(0), c.Args().Get(1))
	if err != nil {
		return cli.Exit(err, 1)
	}
	return nil
}
