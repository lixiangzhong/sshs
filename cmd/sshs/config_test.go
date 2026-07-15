package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
