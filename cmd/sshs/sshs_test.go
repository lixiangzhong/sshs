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

func TestExactMatch(t *testing.T) {
	c1 := Config{Name: "/prod/web-1", Host: "10.0.0.1", Port: 22}
	c2 := Config{Name: "/prod/web-10", Host: "10.0.0.10", Port: 22}
	c3 := Config{Name: "/dev/web-1", Host: "10.0.1.1", Port: 2222}

	if !isExactMatch(c1, "web-1") {
		t.Fatalf("expected exact match for web-1")
	}
	if isExactMatch(c2, "web-1") {
		t.Fatalf("expected no exact match for web-1 on web-10")
	}
	if !isExactMatch(c1, "prod/web-1") {
		t.Fatalf("expected exact match for prod/web-1")
	}
	if !isExactMatch(c1, "/prod/web-1") {
		t.Fatalf("expected exact match for /prod/web-1")
	}
	if !isExactMatch(c1, "prod", "web-1") {
		t.Fatalf("expected exact match for prod web-1")
	}
	if !isExactMatch(c1, "10.0.0.1") {
		t.Fatalf("expected exact match for host IP")
	}
	if !isExactMatch(c3, "10.0.1.1:2222") {
		t.Fatalf("expected exact match for remote addr")
	}
}

func TestSelectSingleHost(t *testing.T) {
	c1 := Config{Name: "/prod/web-1", Host: "10.0.0.1"}
	c2 := Config{Name: "/prod/web-10", Host: "10.0.0.10"}
	c3 := Config{Name: "/dev/web-1", Host: "10.0.1.1"}

	// 0 台
	if _, err := selectSingleHost(nil, "web"); err == nil || err.Error() != "no host matched" {
		t.Fatalf("expected 'no host matched', got %v", err)
	}

	// 1 台
	got, err := selectSingleHost([]Config{c1}, "web-1")
	if err != nil || got.Name != c1.Name {
		t.Fatalf("expected %v, got %v, err=%v", c1.Name, got.Name, err)
	}

	// 模糊匹配多台，但完全匹配只有 1 台
	got, err = selectSingleHost([]Config{c1, c2}, "web-1")
	if err != nil || got.Name != c1.Name {
		t.Fatalf("expected exact match to pick %v, got %v, err=%v", c1.Name, got.Name, err)
	}

	// 模糊匹配多台，且完全匹配也有多台
	_, err = selectSingleHost([]Config{c1, c3}, "web-1")
	if err == nil {
		t.Fatal("expected error for multiple exact matches")
	}
	expectedErr := "multiple hosts matched: [prod/web-1, dev/web-1], please specify exact name"
	if err.Error() != expectedErr {
		t.Fatalf("got err %q, want %q", err.Error(), expectedErr)
	}

	// 模糊匹配多台，无完全匹配
	_, err = selectSingleHost([]Config{c1, c2}, "web")
	if err == nil {
		t.Fatal("expected error for multiple fuzzy matches")
	}
	expectedFuzzyErr := "multiple hosts matched: [prod/web-1, prod/web-10], please specify exact name"
	if err.Error() != expectedFuzzyErr {
		t.Fatalf("got err %q, want %q", err.Error(), expectedFuzzyErr)
	}
}
