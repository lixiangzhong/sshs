package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/lixiangzhong/sshs/pkg/secureshell"

	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v2"
)

type runConfig struct {
	Hosts   []Config `yaml:"hosts"`
	Scripts []Script `yaml:"scripts"`
}

type Script struct {
	Run      string `yaml:"run"`
	LocalRun string `yaml:"local_run"`
	Scp      struct {
		Src  string `yaml:"src"`
		Dst  string `yaml:"dst"`
		Dir  bool   `yaml:"dir"`
		Gzip bool   `yaml:"gzip"`
	} `yaml:"scp"`
	Sleep time.Duration `yaml:"sleep"`
}

func (s Script) sleepDuration() time.Duration {
	if s.Sleep == 0 {
		return time.Millisecond * 10
	}
	return s.Sleep
}

func RunAction(ctx *cli.Context) error {
	log.SetOutput(os.Stdout)
	log.SetFlags(log.Lshortfile)
	var cfg runConfig
	filename := ctx.String("filename")
	b, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("%v:%v", filename, err)
	}
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return err
	}
	for _, host := range cfg.Hosts {
		func(host Config) {
			fmt.Println(strings.Repeat("↓", 100))
			if host.Name != "" {
				fmt.Println(host.Name)
			}
			fmt.Println("host", host.RemoteAddr())
			defer fmt.Println(strings.Repeat("↑", 100))
			c, err := secureshell.Dial(host.Username(), host.RemoteAddr(), host.AuthMethod()...)
			if err != nil {
				fmt.Println(err)
				return
			}
			fmt.Println(strings.Repeat("#", 100))
			runScripts(ctx.Context, c, cfg.Scripts)
		}(host)

	}
	if len(cfg.Hosts) == 0 {
		c, err := ChooseHost()
		if err != nil {
			return err
		}
		runScripts(ctx.Context, c, cfg.Scripts)
	}
	return nil
}

func runScripts(ctx context.Context, c *ssh.Client, scripts []Script) {
	defer c.Close()
	t, err := secureshell.NewTerminalSession(c)
	if err != nil {
		log.Println(err)
		return
	}
	defer t.Wait()
	defer t.WriteString("exit")
	sclient, err := secureshell.SftpClient(c)
	if err != nil {
		log.Println(err)
		return
	}
	defer sclient.Close()
	for _, v := range scripts {
		switch {
		case v.Scp.Src != "" && v.Scp.Dst != "":
			time.Sleep(time.Second)
			err = secureshell.Scp(ctx, sclient, v.Scp.Gzip, v.Scp.Dir, v.Scp.Src, v.Scp.Dst)
			if err != nil {
				log.Println(err)
				return
			}
		case v.LocalRun != "":
			err := Cmd(ctx, v.LocalRun)
			//todo output
			if err != nil {
				log.Println(err)
				return
			}
		default:
			err = t.WriteString(v.Run)
			if err != nil {
				log.Println(err)
				return
			}
		}
		time.Sleep(v.sleepDuration())
	}
}

func Cmd(ctx context.Context, s string) error {
	args := strings.Fields(s)
	var cmd *exec.Cmd
	switch len(args) {
	case 0:
		return nil
	case 1:
		cmd = exec.CommandContext(ctx, args[0])
	default:
		cmd = exec.CommandContext(ctx, args[0], args[1:]...)
	}
	return cmd.Run()
}
