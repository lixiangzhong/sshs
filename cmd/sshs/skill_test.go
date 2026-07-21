package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/urfave/cli/v2"
)

func TestSkillAction(t *testing.T) {
	var buf bytes.Buffer
	app := &cli.App{
		Writer: &buf,
	}
	ctx := cli.NewContext(app, nil, nil)
	err := SkillAction(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "sshs 使用助手") {
		t.Fatalf("output does not contain expected header: %s", output)
	}
}
