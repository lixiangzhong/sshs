package main

import (
	"github.com/lixiangzhong/sshs/pkg/secureshell"

	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/ssh"
)

func ChooseHost(keyword ...string) (*ssh.Client, error) {
	host, err := UISelect(keyword...)
	if err != nil {
		return nil, err
	}
	jumper := host.Jumper
	var c *ssh.Client
	for jumper != nil {
		if c == nil {
			c, err = secureshell.Dial(jumper.Username(), jumper.RemoteAddr(), jumper.AuthMethod()...)
			if err != nil {
				return nil, err
			}
		} else {
			c, err = secureshell.JumperDial(c, jumper.Username(), jumper.RemoteAddr(), jumper.AuthMethod()...)
			if err != nil {
				return nil, err
			}
		}
		jumper = jumper.Jumper
	}
	if c != nil {
		return secureshell.JumperDial(c, host.Username(), host.RemoteAddr(), host.AuthMethod()...)
	}
	return secureshell.Dial(host.Username(), host.RemoteAddr(), host.AuthMethod()...)
}

func LoadConfig(keyword ...string) ([]Config, error) {
	cfg, err := loadConfig(configFileList(".sshs.yaml", "sshs.yaml", ".sshw.yaml", "sshw.yaml")...)
	if err != nil {
		return nil, err
	}
	if len(keyword) == 0 {
		return cfg, nil
	}
	return filter_unfolding(cfg, "", keyword...), nil
}

func filter_unfolding(c []Config, prefix string, keyword ...string) []Config {
	var result []Config
	for _, v := range c {
		if len(v.Children) > 0 {
			prefix := prefix + "/" + v.Name
			result = append(result, filter_unfolding(v.Children, prefix, keyword...)...)
		} else {
			if containKeyword(v, keyword...) {
				v.Name = prefix + "/" + v.Name
				result = append(result, v)
			}
		}
	}
	return result
}

func TerminalAction(c *cli.Context) error {
	client, err := ChooseHost(c.Args().Slice()...)
	if err != nil {
		return err
	}
	t, err := secureshell.NewTerminal(client)
	if err != nil {
		return cli.Exit(err, 1)
	}
	t.Wait()
	return nil
}
