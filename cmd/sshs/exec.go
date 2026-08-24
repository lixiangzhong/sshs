package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/urfave/cli/v2"
)

const execCommandSeparator = "--"

func ExecAction(c *cli.Context) error {
	keywords, command, err := parseExecArgs(c.Args().Slice(), c.Command.Name, c.Command.Aliases...)
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

	timeout := c.Duration("timeout")
	if timeout > 0 {
		ctx, cancel := context.WithTimeout(c.Context, timeout)
		defer cancel()

		done := make(chan struct{})
		defer close(done)

		go func() {
			select {
			case <-ctx.Done():
				session.Close()
				client.Close()
			case <-done:
			}
		}()

		if err := session.Run(command); err != nil {
			if ctx.Err() == context.DeadlineExceeded {
				return cli.Exit(fmt.Sprintf("command timed out after %v", timeout), 1)
			}
			return cli.Exit(err, exitCode(err))
		}
		return nil
	}

	if err := session.Run(command); err != nil {
		return cli.Exit(err, exitCode(err))
	}
	return nil
}

func parseExecArgs(args []string, name string, aliases ...string) ([]string, string, error) {
	commandIndex := findExecCommandIndex(args, append([]string{name}, aliases...))
	var searchArgs []string
	if commandIndex >= 0 {
		searchArgs = args[commandIndex+1:]
	} else {
		searchArgs = args
	}

	separatorIndex := -1
	for index, arg := range searchArgs {
		if arg == execCommandSeparator {
			separatorIndex = index
			break
		}
	}
	if separatorIndex < 0 {
		return nil, "", errors.New("missing -- before command")
	}
	if separatorIndex == len(searchArgs)-1 {
		return nil, "", errors.New("missing command")
	}

	rawKeywords := searchArgs[:separatorIndex]
	var keywords []string
	for _, kw := range rawKeywords {
		if strings.HasPrefix(kw, "-") {
			return nil, "", fmt.Errorf("flags must appear before host keywords, got %q", kw)
		}
		keywords = append(keywords, kw)
	}

	command := strings.Join(searchArgs[separatorIndex+1:], " ")
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
