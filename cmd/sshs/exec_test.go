package main

import "testing"

func Test_parseExecArgs(t *testing.T) {
	tests := []struct {
		name         string
		args         []string
		keywords     []string
		command      string
		wantErr      bool
		commandName  string
		commandAlias []string
	}{
		{
			name:        "command without keywords",
			args:        []string{"sshs", "exec", "--", "uptime"},
			commandName: "exec",
			keywords:    []string{},
			command:     "uptime",
		},
		{
			name:        "command with keywords",
			args:        []string{"sshs", "exec", "prod", "db", "--", "uname", "-a"},
			commandName: "exec",
			keywords:    []string{"prod", "db"},
			command:     "uname -a",
		},
		{
			name:         "alias command",
			args:         []string{"sshs", "cmd", "prod", "--", "pwd"},
			commandName:  "exec",
			commandAlias: []string{"cmd"},
			keywords:     []string{"prod"},
			command:      "pwd",
		},
		{
			name:        "missing separator",
			args:        []string{"sshs", "exec", "uptime"},
			commandName: "exec",
			wantErr:     true,
		},
		{
			name:        "missing command",
			args:        []string{"sshs", "exec", "--"},
			commandName: "exec",
			wantErr:     true,
		},
		{
			name:        "sliced context args without command name",
			args:        []string{"prod", "--", "uptime"},
			commandName: "exec",
			keywords:    []string{"prod"},
			command:     "uptime",
		},
		{
			name:        "misplaced flag after keyword",
			args:        []string{"prod", "-t", "--", "uptime"},
			commandName: "exec",
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keywords, command, err := parseExecArgs(tt.args, tt.commandName, tt.commandAlias...)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if command != tt.command {
				t.Fatalf("command = %q, want %q", command, tt.command)
			}
			if len(keywords) != len(tt.keywords) {
				t.Fatalf("keywords = %v, want %v", keywords, tt.keywords)
			}
			for index := range keywords {
				if keywords[index] != tt.keywords[index] {
					t.Fatalf("keywords = %v, want %v", keywords, tt.keywords)
				}
			}
		})
	}
}
