package main

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lixiangzhong/sshs/pkg/secureshell"
	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/ssh"
)

func Test_configFileList(t *testing.T) {
	list := configFileList("1", "2")
	t.Log(list)
}

func Test_PasswordValueFallsBackToKeyringDefaultPassword(t *testing.T) {
	mock := &mockKeyring{data: make(map[string]string)}
	oldKeyring := activeKeyring
	activeKeyring = mock
	defer func() { activeKeyring = oldKeyring }()

	c := &Config{Name: "web", Host: "10.0.0.1"}
	got, err := c.PasswordValue()
	if err != nil || got != "" {
		t.Fatalf("PasswordValue() = %q, %v, want empty when default password not in keyring", got, err)
	}

	mock.data["sshs/default-password"] = "keyring-fallback-pass"
	got, err = c.PasswordValue()
	if err != nil || got != "keyring-fallback-pass" {
		t.Fatalf("PasswordValue() = %q, %v, want keyring default fallback", got, err)
	}
	auth, err := c.AuthMethod()
	if err != nil || len(auth) != 1 {
		t.Fatalf("AuthMethod() count = %d, err = %v, want 1 with keyring default", len(auth), err)
	}

	c.Password = "cfg-pass"
	got, err = c.PasswordValue()
	if err != nil || got != "cfg-pass" {
		t.Fatalf("PasswordValue() = %q, %v, want config value to take precedence", got, err)
	}
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

func Test_HasPassword(t *testing.T) {
	mock := &mockKeyring{data: make(map[string]string)}
	oldKeyring := activeKeyring
	activeKeyring = mock
	defer func() { activeKeyring = oldKeyring }()

	c := Config{Name: "web"}
	if c.HasPassword() {
		t.Fatal("HasPassword() = true, want false")
	}

	c.Password = "plain-pass"
	if !c.HasPassword() {
		t.Fatal("HasPassword() = false, want true for plain password")
	}

	c.Password = "ENC(v1:dummy)"
	if !c.HasPassword() {
		t.Fatal("HasPassword() = false, want true for encrypted password")
	}

	c.Password = ""
	mock.data["sshs/default-password"] = "keyring-pass"
	if !c.HasPassword() {
		t.Fatal("HasPassword() = false, want true for keyring default fallback")
	}
}

func Test_PasswordValueDecryptsEncrypted(t *testing.T) {
	setCachedMasterKey("")
	mock := &mockKeyring{data: map[string]string{"sshs/master-key": "master-secret"}}
	oldKeyring := activeKeyring
	activeKeyring = mock
	defer func() { activeKeyring = oldKeyring }()

	plain := "my-database-pwd"
	encrypted, err := EncryptPassword(plain, "master-secret")
	if err != nil {
		t.Fatalf("EncryptPassword failed: %v", err)
	}

	c := &Config{Name: "db", Password: encrypted}
	got, err := c.PasswordValue()
	if err != nil || got != plain {
		t.Fatalf("PasswordValue() = %q, %v, want %q", got, err, plain)
	}

	auth, err := c.AuthMethod()
	if err != nil || len(auth) != 1 {
		t.Fatalf("AuthMethod() = %v, %v, want 1 auth method", auth, err)
	}
	setCachedMasterKey("")
}

func Test_FailFastOnDecryptionError(t *testing.T) {
	setCachedMasterKey("")
	mock := &mockKeyring{data: map[string]string{"sshs/master-key": "wrong-master-key"}}
	oldKeyring := activeKeyring
	activeKeyring = mock
	defer func() { activeKeyring = oldKeyring }()

	// 使用 correct-key 加密
	encrypted, err := EncryptPassword("real-secret", "correct-key")
	if err != nil {
		t.Fatal(err)
	}

	c := Config{
		Name:     "node-fail-fast",
		Host:     "192.168.99.99",
		Password: encrypted,
	}

	// 1. PasswordValue 必须直接返回错误
	_, err = c.PasswordValue()
	if err == nil {
		t.Fatal("expected PasswordValue to return error on decryption failure")
	}

	// 2. AuthMethod 必须直接返回错误
	_, err = c.AuthMethod()
	if err == nil {
		t.Fatal("expected AuthMethod to return error on decryption failure")
	}

	// 3. dialThroughJumpers 必须在拨号前被拦截，mock dialer 绝不应被调用！
	dialCalled := false
	mockDial := func(dialer secureshell.Dialer, username, host string, authmethod ...ssh.AuthMethod) (*ssh.Client, error) {
		dialCalled = true
		return nil, nil
	}

	_, err = dialThroughJumpers(c, mockDial)
	if err == nil {
		t.Fatal("expected dialThroughJumpers to return error")
	}
	if dialCalled {
		t.Fatal("FAIL-FAST VIOLATION: dialer was called despite decryption error!")
	}
	setCachedMasterKey("")
}

