package main

import (
	"errors"
	"os"
	"strings"

	"github.com/urfave/cli/v2"
)

const execCommandSeparator = "--"

func ExecAction(c *cli.Context) error {
	keywords, command, err := parseExecArgs(os.Args, c.Command.Name, c.Command.Aliases...)
	if err != nil {
		return cli.Exit(err, 1)
	}
	client, err := ChooseHostNonInteractive(keywords...)
	if err != nil {
		return cli.Exit(err, 1)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return cli.Exit(err, 1)
	}
	defer session.Close()

	session.Stdout = os.Stdout
	session.Stderr = os.Stderr
	session.Stdin = os.Stdin
	if err := session.Run(command); err != nil {
		return cli.Exit(err, exitCode(err))
	}
	return nil
}

func parseExecArgs(args []string, name string, aliases ...string) ([]string, string, error) {
	commandIndex := findExecCommandIndex(args, append([]string{name}, aliases...))
	if commandIndex < 0 {
		return nil, "", errors.New("missing exec command")
	}
	separatorIndex := -1
	for index := commandIndex + 1; index < len(args); index++ {
		if args[index] == execCommandSeparator {
			separatorIndex = index
			break
		}
	}
	if separatorIndex < 0 {
		return nil, "", errors.New("missing -- before command")
	}
	if separatorIndex == len(args)-1 {
		return nil, "", errors.New("missing command")
	}
	keywords := args[commandIndex+1 : separatorIndex]
	command := strings.Join(args[separatorIndex+1:], " ")
	return keywords, command, nil
}

func findExecCommandIndex(args []string, names []string) int {
	for index, arg := range args {
		for _, name := range names {
			if arg == name {
				return index
			}
		}
	}
	return -1
}

func exitCode(err error) int {
	type exitStatus interface {
		ExitStatus() int
	}
	var status exitStatus
	if errors.As(err, &status) {
		return status.ExitStatus()
	}
	return 1
}
