package main

import (
	"flag"
	"testing"

	"github.com/urfave/cli/v2"
)

func TestHostKeywords(t *testing.T) {
	cmd := &cli.Command{
		Name: "inspect",
		Flags: []cli.Flag{
			&cli.DurationFlag{Name: "timeout"},
			&cli.IntFlag{Name: "concurrency"},
			&cli.BoolFlag{Name: "json"},
		},
	}
	app := &cli.App{Commands: []*cli.Command{cmd}}

	run := func(argv ...string) ([]string, error) {
		fs := flag.NewFlagSet("inspect", flag.ContinueOnError)
		for _, f := range cmd.Flags {
			_ = f.Apply(fs)
		}
		ctx := cli.NewContext(app, fs, nil)
		ctx.Command = cmd
		_ = fs.Parse(argv)
		return hostKeywords(ctx)
	}

	tests := []struct {
		name    string
		argv    []string
		want    []string
		wantErr bool
	}{
		{"flags first", []string{"--json", "--timeout", "5s", "prod", "db"}, []string{"prod", "db"}, false},
		{"no flags", []string{"prod"}, []string{"prod"}, false},
		{"bare flag only", []string{"--json"}, nil, false},
		{"flag after keyword", []string{"prod", "--json"}, nil, true},
		{"value flag after keyword", []string{"prod", "--timeout", "5s"}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := run(tt.argv...)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("got %v, want %v", got, tt.want)
				}
			}
		})
	}
}
