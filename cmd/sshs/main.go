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
		Version:   "1.0.0",
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
				},
				Action: SCPAction,
			},
		},
	}
	err := app.Run(os.Args)
	if err != nil {
		log.Println(err)
	}
}
