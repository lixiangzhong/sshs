package main

import (
	"log"
	"os"

	"github.com/urfave/cli/v2"
)

func main() {
	log.SetFlags(0)
	app := &cli.App{
		Name:      "sshs",
		Usage:     "make ssh scp easy",
		UsageText: "sshs [flags] [command] [args...]",
		Version:   "1.12.0",
		Action:    TerminalAction,
		Commands: []*cli.Command{
			{
				Name:      "scp",
				Aliases:   []string{"cp"},
				Usage:     "scp transfer file or dir",
				UsageText: "scp [-r] <src> <dst> (example: scp -r localdir :/remotedir)",
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
		},
	}
	err := app.Run(os.Args)
	if err != nil {
		log.Println(err)
	}
}
