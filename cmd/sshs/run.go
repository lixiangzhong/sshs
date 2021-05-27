package main

import (
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
		Src string `yaml:"src"`
		Dst string `yaml:"dst"`
		Dir bool   `yaml:"dir"`
	} `yaml:"scp"`
	Sleep time.Duration `yaml:"sleep"`
}

func (s Script) sleepDuration() time.Duration {
	if s.Sleep == 0 {
		return time.Millisecond * 10
	}
	return s.Sleep
}

func RunAction(c *cli.Context) error {
	log.SetFlags(log.Lshortfile)
	var cfg runConfig
	filename := c.String("filename")
	if b, err := os.ReadFile(filename); err != nil {
		return fmt.Errorf("%v:%v", filename, err)
	} else {
		if err := yaml.Unmarshal(b, &cfg); err != nil {
			return err
		}
	}
	for _, host := range cfg.Hosts {
		fmt.Println(strings.Repeat("#", 100))
		fmt.Println("host", host.RemoteAddr())
		fmt.Println(strings.Repeat("#", 100))
		c, err := secureshell.Dial(host.Username(), host.RemoteAddr(), host.AuthMethod()...)
		if err != nil {
			log.Println(err)
			continue
		}
		runScripts(c, cfg.Scripts)
	}
	return nil
}

func runScripts(c *ssh.Client, scripts []Script) {
	defer c.Close()
	t, err := secureshell.NewTerminal(c)
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
			err = secureshell.Scp(sclient, v.Scp.Dir, v.Scp.Src, v.Scp.Dst)
			if err != nil {
				log.Println(err)
				return
			}
		case v.LocalRun != "":
			fmt.Println("local_run:", v.LocalRun)
			err := Cmd(v.LocalRun)
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

func Cmd(s string) error {
	args := strings.Fields(s)
	var cmd *exec.Cmd
	switch len(args) {
	case 0:
		return nil
	case 1:
		cmd = exec.Command(args[0])
	default:
		cmd = exec.Command(args[0], args[1:]...)
	}
	return cmd.Run()
}
