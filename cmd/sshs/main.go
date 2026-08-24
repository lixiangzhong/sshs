package main

import (
	"log"
	"os"

	"github.com/urfave/cli/v2"
)

// version 默认值供本地直接编译使用；发版时由 GoReleaser 通过 -ldflags 注入 tag 版本号
var version = "1.19.0"

func main() {
	log.SetFlags(0)
	app := &cli.App{
		Name:      "sshs",
		Usage:     "make ssh scp easy",
		UsageText: "sshs [flags] [command] [args...]",
		Version:   version,
		Action:    TerminalAction,
		Commands: []*cli.Command{
			{
				Name:      "list",
				Usage:     "list matched hosts (non-interactive)",
				UsageText: "sshs list [host keywords...] [--json]",
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:  "json",
						Usage: "output as json",
						Value: false,
					},
				},
				Action: ListAction,
			},
			{
				Name:      "inspect",
				Usage:     "inspect matched hosts metrics",
				UsageText: "sshs inspect [host keywords...] [--timeout <dur>] [--concurrency <n>] [--json]",
				Flags: []cli.Flag{
					&cli.DurationFlag{
						Name:  "timeout",
						Usage: "per-host timeout (e.g. 10s)",
						Value: inspectTimeoutDefault,
					},
					&cli.IntFlag{
						Name:  "concurrency",
						Usage: "max concurrent hosts",
						Value: inspectConcurrencyDefault,
					},
					&cli.BoolFlag{
						Name:  "json",
						Usage: "output as json",
						Value: false,
					},
				},
				Action: InspectAction,
			},
			{
				Name:      "scp",
				Aliases:   []string{"cp"},
				Usage:     "scp transfer file or dir",
				UsageText: "scp [-r] [-gzip] [-no-progress] [-exclude <pattern>] <src> <dst> (example: scp -r localdir :/remotedir)",
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:    "r",
						Aliases: []string{"recursively"},
						Usage:   "scp dir",
						Value:   false,
					},
					&cli.BoolFlag{
						Name:    "gzip",
						Aliases: []string{"gz"},
						Usage:   "warp dst as gzip writer",
						Value:   false,
					},
					&cli.BoolFlag{
						Name:    "no-progress",
						Aliases: []string{"np"},
						Usage:   "disable progress bar",
						Value:   false,
					},
					&cli.StringSliceFlag{
						Name:  "exclude",
						Usage: "exclude file or directory matching pattern",
						Value: cli.NewStringSlice(".DS_Store"),
					},
				},
				Action: SCPAction,
			},
			{
				Name:      "run",
				Usage:     "run shell file",
				UsageText: "sshs run -f example.yaml",
				Description: `
cat example.yaml

hosts:
  - { host: 192.168.1.1, password: 123456 }
scripts:
  - { run: ifconfig }
  - { scp: { src: '1.txt', dst: ':/root/1.txt' } } #same as => scp 1.txt root@192.168.1.1:/root/1.txt
  - { run: cat 1.txt }
`,
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "f",
						Aliases:  []string{"filename", "file"},
						Usage:    "run file script",
						Required: true,
					},
				},
				Action: RunAction,
			},
			{
				Name:      "exec",
				Aliases:   []string{"cmd"},
				Usage:     "execute remote command",
				UsageText: "sshs exec [--timeout <dur>] [host keywords...] -- <command>",
				Flags: []cli.Flag{
					&cli.DurationFlag{
						Name:    "timeout",
						Aliases: []string{"t"},
						Usage:   "command execution timeout (e.g. 10s, 1m)",
						Value:   0,
					},
				},
				Action:    ExecAction,
			},
			{
				Name:      "forward",
				Usage:     "direct_tcp_ip",
				UsageText: "sshs forward -laddr :1234 -raddr x.x.x.x:port",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:        "laddr",
						Aliases:     []string{"l"},
						Usage:       "listen local address",
						DefaultText: ":0",
					},
					&cli.StringFlag{
						Required: true,
						Name:     "raddr",
						Aliases:  []string{"r"},
						Usage:    "connect to remote address",
					},
				},
				Action: ForwardAction,
			},
			{
				Name:      "listen",
				Usage:     "listen remote forward to local",
				UsageText: "sshs listen -raddr x.x.x.x:port -laddr :80",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Required: true,
						Name:     "laddr",
						Aliases:  []string{"l"},
						Usage:    "forward to local address",
					},
					&cli.StringFlag{
						Name:        "raddr",
						Aliases:     []string{"r"},
						Usage:       "listen remote address",
						DefaultText: ":0",
					},
				},
				Action: ListenAction,
			},
			{
				Name:      "socks5",
				Usage:     "socks5 proxy",
				UsageText: "sshs socks5 -laddr 127.0.0.1:1080",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:        "laddr",
						Aliases:     []string{"l"},
						Usage:       "listen local address",
						DefaultText: "127.0.0.1:0",
					},
				},
				Action: Socks5Action,
			},
			{
				Name:      "edit",
				Usage:     "edit config",
				UsageText: "sshs edit",
				Action:    EditAction,
			},
			{
				Name:      "doctor",
				Usage:     "check sshs config",
				UsageText: "sshs doctor",
				Action:    DoctorAction,
			},
			{
				Name:      "skill",
				Usage:     "show sshs agent skill documentation",
				UsageText: "sshs skill",
				Action:    SkillAction,
			},
		},
	}
	err := app.Run(os.Args)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
}
