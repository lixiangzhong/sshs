package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func generateTestEd25519Key(t *testing.T) []byte {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	b, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	return pem.EncodeToMemory(b)
}

func Test_checkDoctorIssuesPortValidity(t *testing.T) {
	cfg := []Config{
		{Name: "valid-node", Host: "10.0.0.1", Port: 2222},
		{Name: "negative-port", Host: "10.0.0.2", Port: -1},
		{Name: "overflow-port", Host: "10.0.0.3", Port: 70000},
	}

	issues := checkDoctorIssues(cfg)
	if len(issues) != 2 {
		t.Fatalf("expected 2 port issues, got %d: %#v", len(issues), issues)
	}

	hasNegative := false
	hasOverflow := false
	for _, issue := range issues {
		if strings.Contains(issue.Message, "negative-port") && strings.Contains(issue.Message, "invalid port -1") {
			hasNegative = true
		}
		if strings.Contains(issue.Message, "overflow-port") && strings.Contains(issue.Message, "invalid port 70000") {
			hasOverflow = true
		}
	}

	if !hasNegative || !hasOverflow {
		t.Fatalf("missing expected port error messages: %#v", issues)
	}
}

func Test_checkDoctorIssuesKeyPath(t *testing.T) {
	dir := t.TempDir()

	// 1. 存在且权限合规的有效私钥
	validKeyPath := filepath.Join(dir, "id_ed25519_valid")
	keyData := generateTestEd25519Key(t)
	if err := os.WriteFile(validKeyPath, keyData, 0600); err != nil {
		t.Fatal(err)
	}

	// 2. 文件不存在
	missingKeyPath := filepath.Join(dir, "id_nonexistent")

	// 3. 路径为目录
	dirKeyPath := filepath.Join(dir, "key_dir")
	if err := os.Mkdir(dirKeyPath, 0700); err != nil {
		t.Fatal(err)
	}

	// 4. 内容损坏
	corruptKeyPath := filepath.Join(dir, "id_corrupt")
	if err := os.WriteFile(corruptKeyPath, []byte("-----BEGIN OPENSSH PRIVATE KEY-----\ncorrupt\n-----END OPENSSH PRIVATE KEY-----\n"), 0600); err != nil {
		t.Fatal(err)
	}

	cfg := []Config{
		{Name: "valid", Host: "10.0.0.1", KeyPath: validKeyPath},
		{Name: "missing", Host: "10.0.0.2", KeyPath: missingKeyPath},
		{Name: "isdir", Host: "10.0.0.3", KeyPath: dirKeyPath},
		{Name: "corrupt", Host: "10.0.0.4", KeyPath: corruptKeyPath},
	}

	issues := checkDoctorIssues(cfg)

	foundMissing := false
	foundIsDir := false
	foundCorrupt := false
	for _, issue := range issues {
		if strings.Contains(issue.Message, "missing") && strings.Contains(issue.Message, "not found") {
			foundMissing = true
		}
		if strings.Contains(issue.Message, "isdir") && strings.Contains(issue.Message, "is a directory") {
			foundIsDir = true
		}
		if strings.Contains(issue.Message, "corrupt") && strings.Contains(issue.Message, "failed to parse private key") {
			foundCorrupt = true
		}
	}

	if !foundMissing || !foundIsDir || !foundCorrupt {
		t.Fatalf("failed to detect expected keypath issues: %#v", issues)
	}
}

func Test_checkDoctorIssuesKeyPathPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file permissions check not applicable on windows")
	}

	dir := t.TempDir()
	openKeyPath := filepath.Join(dir, "id_open")
	keyData := generateTestEd25519Key(t)
	if err := os.WriteFile(openKeyPath, keyData, 0644); err != nil {
		t.Fatal(err)
	}

	cfg := []Config{
		{Name: "open-perm", Host: "10.0.0.1", KeyPath: openKeyPath},
	}

	issues := checkDoctorIssues(cfg)
	foundOpen := false
	for _, issue := range issues {
		if strings.Contains(issue.Message, "open-perm") && strings.Contains(issue.Message, "permissions") && strings.Contains(issue.Message, "too open") {
			foundOpen = true
		}
	}
	if !foundOpen {
		t.Fatalf("expected permissions too open issue, got: %#v", issues)
	}
}

func Test_checkDoctorIssuesEncryptedPassword(t *testing.T) {
	setCachedMasterKey("")
	mock := &mockKeyring{data: make(map[string]string)}
	oldKeyring := activeKeyring
	activeKeyring = mock
	defer func() { activeKeyring = oldKeyring }()

	masterKey := "doctor-test-master-key"
	mock.data["sshs/master-key"] = masterKey

	validEnc, err := EncryptPassword("secret123", masterKey)
	if err != nil {
		t.Fatal(err)
	}

	cfg := []Config{
		{Name: "valid-enc", Host: "10.0.0.1", Password: validEnc},
		{Name: "corrupt-enc", Host: "10.0.0.2", Password: "ENC(v1:invalid-base64-payload)"},
	}

	issues := checkDoctorIssues(cfg)
	if len(issues) != 1 {
		t.Fatalf("expected 1 issue for corrupt ciphertext, got %d: %#v", len(issues), issues)
	}
	if !strings.Contains(issues[0].Message, "corrupt-enc") || !strings.Contains(issues[0].Message, "failed to decrypt password") {
		t.Fatalf("unexpected issue message: %s", issues[0].Message)
	}

	// 当钥匙串中未找到 master-key 时
	delete(mock.data, "sshs/master-key")
	setCachedMasterKey("")
	issuesNoKey := checkDoctorIssues([]Config{{Name: "no-key", Host: "10.0.0.3", Password: validEnc}})
	if len(issuesNoKey) != 1 || !strings.Contains(issuesNoKey[0].Message, "master key not found in keyring") {
		t.Fatalf("expected master key missing issue, got: %#v", issuesNoKey)
	}
}

func Test_checkDoctorIssuesJumperValidation(t *testing.T) {
	// 1. Jumper 端口非法
	cfgBadPort := []Config{
		{
			Name: "target",
			Host: "10.0.0.1",
			Jumper: &Config{
				Host: "192.168.1.1",
				Port: 99999,
			},
		},
	}
	issues := checkDoctorIssues(cfgBadPort)
	if len(issues) != 1 || !strings.Contains(issues[0].Message, "invalid port 99999") {
		t.Fatalf("expected jumper invalid port issue, got: %#v", issues)
	}

	// 2. Jumper 循环引用
	cfgCycle := []Config{
		{
			Name: "node-a",
			Host: "10.0.0.1",
			Port: 22,
			Jumper: &Config{
				Host: "10.0.0.2",
				Port: 22,
				Jumper: &Config{
					Host: "10.0.0.1",
					Port: 22,
				},
			},
		},
	}
	issuesCycle := checkDoctorIssues(cfgCycle)
	if len(issuesCycle) != 1 || !strings.Contains(issuesCycle[0].Message, "circular jumper reference") {
		t.Fatalf("expected circular jumper issue, got: %#v", issuesCycle)
	}
}
