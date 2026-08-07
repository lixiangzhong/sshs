package main

import (
	"fmt"
	"strings"

	"github.com/lixiangzhong/sshs/pkg/secureshell"

	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/ssh"
	"golang.org/x/net/proxy"
)

func ChooseHost(keyword ...string) (*ssh.Client, error) {
	host, err := UISelect(keyword...)
	if err != nil {
		return nil, err
	}
	return dialThroughJumpers(host, secureshell.Dial)
}

// dialThroughJumpers 逐级穿过 jumper 链并连接目标主机，dial 用于指定拨号方式（交互/非交互）。
func dialThroughJumpers(c Config, dial func(secureshell.Dialer, string, string, ...ssh.AuthMethod) (*ssh.Client, error)) (*ssh.Client, error) {
	jumper := c.Jumper
	dialer := proxy.FromEnvironment()
	for jumper != nil {
		jc, err := dial(dialer, jumper.Username(), jumper.RemoteAddr(), jumper.AuthMethod()...)
		if err != nil {
			return nil, err
		}
		dialer = jc
		jumper = jumper.Jumper
	}
	return dial(dialer, c.Username(), c.RemoteAddr(), c.AuthMethod()...)
}

func LoadConfig(keyword ...string) ([]Config, error) {
	cfg, err := loadConfig(configFileList(configFilenames...)...)
	if err != nil {
		return nil, err
	}
	if len(keyword) == 0 {
		return cfg, nil
	}
	return filter_unfolding(cfg, "", keyword...), nil
}

// hostKeywords 校验并返回主机关键词。urfave/cli v2 不会解析位置参数之后的 flag，
// 混入时 flag 会静默不生效，因此这里显式报错，要求 flags 写在关键词之前。
func hostKeywords(c *cli.Context) ([]string, error) {
	args := c.Args().Slice()
	var keywords []string
	for _, arg := range args {
		if strings.HasPrefix(arg, "-") {
			return nil, fmt.Errorf("flags must appear before host keywords, got %q", arg)
		}
		keywords = append(keywords, arg)
	}
	return keywords, nil
}

func filter_unfolding(c []Config, prefix string, keyword ...string) []Config {
	var result []Config
	for _, v := range c {
		if len(v.Children) > 0 {
			prefix := prefix + "/" + v.Name
			result = append(result, filter_unfolding(v.Children, prefix, keyword...)...)
		} else {
			v.Name = prefix + "/" + v.Name
			if containKeyword(v, keyword...) {
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
