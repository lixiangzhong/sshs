package main

import (
	_ "embed"
	"fmt"
	"io"
	"os"

	"github.com/urfave/cli/v2"
)

//go:embed SKILL.md
var skillContent string

func SkillAction(c *cli.Context) error {
	writer := skillWriter(c)
	fmt.Fprint(writer, skillContent)
	return nil
}

func skillWriter(c *cli.Context) io.Writer {
	if c == nil || c.App == nil || c.App.Writer == nil {
		return os.Stdout
	}
	return c.App.Writer
}
