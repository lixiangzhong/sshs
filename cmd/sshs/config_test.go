package main

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/urfave/cli/v2"
)

func Test_configFileList(t *testing.T) {
	list := configFileList("1", "2")
	t.Log(list)
}

func Test_loadConfigFileReturnsMatchedPath(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing.yaml")
	filename := filepath.Join(dir, "sshs.yaml")
	err := os.WriteFile(filename, []byte("- name: prod\n  host: 10.0.0.1\n"), 0600)
	if err != nil {
		t.Fatal(err)
	}

	cfg, configPath, err := loadConfigFile(missing, filename)
	if err != nil {
		t.Fatal(err)
	}
	if configPath != filename {
		t.Fatalf("config path = %q, want %q", configPath, filename)
	}
	if len(cfg) != 1 || cfg[0].Host != "10.0.0.1" {
		t.Fatalf("unexpected config: %#v", cfg)
	}
}

func Test_checkDoctorIssuesDetectsDuplicateHost(t *testing.T) {
	cfg := []Config{
		{Name: "prod", Children: []Config{
			{Name: "web-1", Host: "10.0.0.1"},
			{Name: "web-2", Host: "10.0.0.1", Port: 22},
			{Name: "db", Host: "10.0.0.1", Port: 2222},
		}},
	}

	issues := checkDoctorIssues(cfg)
	if len(issues) != 1 {
		t.Fatalf("issues count = %d, want 1: %#v", len(issues), issues)
	}
	if !strings.Contains(issues[0].Message, "10.0.0.1:22") {
		t.Fatalf("issue message should include duplicate host: %q", issues[0].Message)
	}
	if !strings.Contains(issues[0].Message, "prod/web-1") || !strings.Contains(issues[0].Message, "prod/web-2") {
		t.Fatalf("issue message should include duplicate config names: %q", issues[0].Message)
	}
}

func Test_loadSortedHosts(t *testing.T) {
	dir := t.TempDir()
	configFile := filepath.Join(dir, "sshs.yaml")
	content := `- name: web-b
  host: 10.0.0.2
- name: web-a
  host: 10.0.0.1
`
	if err := os.WriteFile(configFile, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	oldFilenames := configFilenames
	configFilenames = []string{configFile}
	defer func() { configFilenames = oldFilenames }()

	app := &cli.App{}
	set := flag.NewFlagSet("test", flag.ContinueOnError)
	c := cli.NewContext(app, set, nil)

	hosts, err := loadSortedHosts(c)
	if err != nil {
		t.Fatalf("loadSortedHosts failed: %v", err)
	}
	if len(hosts) != 2 {
		t.Fatalf("hosts count = %d, want 2", len(hosts))
	}
	if hosts[0].Name != "/web-a" || hosts[1].Name != "/web-b" {
		t.Fatalf("hosts not sorted: %v", hosts)
	}
}
