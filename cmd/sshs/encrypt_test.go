package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/urfave/cli/v2"
)

func Test_EncryptAndDecryptYAMLPreservesFormattingAndComments(t *testing.T) {
	masterKey := "super-master-key-99"

	originalYAML := `- { name: server1, host: 10.10.0.1, password: 123456 } # 默认 user: root, port: 22
- { name: server2, host: 10.10.0.2, port: 2222, user: root, password: "my-quote-pass" }
- {
    name: server3,
    host: 10.10.0.3,
    password: 'single-quote-pass',
    jumper: { host: 10.10.0.1, password: jumper-pass },
  } # 使用跳板机
- name: group1
  children:
    - { name: server4, host: 10.10.0.4, password: pass4 }
`

	// 1. 加密
	encryptedYAML, count, err := EncryptPasswordInYAML([]byte(originalYAML), masterKey)
	if err != nil {
		t.Fatalf("EncryptPasswordInYAML failed: %v", err)
	}
	if count != 5 {
		t.Fatalf("encrypted count = %d, want 5", count)
	}

	encryptedStr := string(encryptedYAML)
	// 验证明文密码均已被替换
	for _, plain := range []string{"123456", "my-quote-pass", "single-quote-pass", "jumper-pass", "pass4"} {
		if strings.Contains(encryptedStr, plain) {
			t.Fatalf("encrypted YAML still contains plaintext %q", plain)
		}
	}

	// 验证注释和格式完整保留
	if !strings.Contains(encryptedStr, "# 默认 user: root, port: 22") {
		t.Fatal("comment for server1 lost")
	}
	if !strings.Contains(encryptedStr, "# 使用跳板机") {
		t.Fatal("comment for server3 lost")
	}
	if !strings.Contains(encryptedStr, "jumper: {host: 10.10.0.1, password: ") {
		t.Fatal("jumper inline structure broken")
	}

	// 2. 再次执行加密，应跳过已加密字段 (count == 0)
	_, recount, err := EncryptPasswordInYAML(encryptedYAML, masterKey)
	if err != nil {
		t.Fatalf("second EncryptPasswordInYAML failed: %v", err)
	}
	if recount != 0 {
		t.Fatalf("second encryption count = %d, want 0", recount)
	}

	// 3. 解密还原
	decryptedYAML, decCount, err := DecryptPasswordInYAML(encryptedYAML, masterKey)
	if err != nil {
		t.Fatalf("DecryptPasswordInYAML failed: %v", err)
	}
	if decCount != 5 {
		t.Fatalf("decrypted count = %d, want 5", decCount)
	}

	decryptedStr := string(decryptedYAML)
	for _, plain := range []string{"123456", "my-quote-pass", "single-quote-pass", "jumper-pass", "pass4"} {
		if !strings.Contains(decryptedStr, plain) {
			t.Fatalf("decrypted YAML missing plain text %q", plain)
		}
	}
}

func Test_MasterKeyAction(t *testing.T) {
	origExiter := cli.OsExiter
	cli.OsExiter = func(code int) {}
	defer func() { cli.OsExiter = origExiter }()

	setCachedMasterKey("")
	mock := &mockKeyring{data: map[string]string{"sshs/master-key": "integration-test-key"}}
	oldKeyring := activeKeyring
	activeKeyring = mock
	defer func() { activeKeyring = oldKeyring }()

	dir := t.TempDir()
	configFile := filepath.Join(dir, ".sshs.yaml")
	sample := `- name: node1
  host: 192.168.1.1
  password: "raw-password-123"
`
	if err := os.WriteFile(configFile, []byte(sample), 0600); err != nil {
		t.Fatal(err)
	}

	oldConfigFilenames := configFilenames
	configFilenames = []string{configFile}
	defer func() { configFilenames = oldConfigFilenames }()

	app := newApp()

	// 1. 运行任意命令（如 list），由 AfterAction 自动完成全量加密落盘
	if err := app.Run([]string{"sshs", "list"}); err != nil {
		t.Fatalf("app.Run(list) failed: %v", err)
	}

	encryptedContent, err := os.ReadFile(configFile)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encryptedContent), "raw-password-123") {
		t.Fatal("config still contains plain password after AfterAction")
	}
	if !strings.Contains(string(encryptedContent), "ENC(v1:") {
		t.Fatal("config does not contain ENC(v1:) after AfterAction")
	}

	var outBuf strings.Builder
	app.Writer = &outBuf

	// 2. 测试 sshs master-key status / set / delete
	outBuf.Reset()
	if err := app.Run([]string{"sshs", "master-key", "status"}); err != nil {
		t.Fatalf("master-key status failed: %v", err)
	}
	if !strings.Contains(outBuf.String(), "is configured") {
		t.Fatalf("master-key status output unexpected: %s", outBuf.String())
	}

	if err := app.Run([]string{"sshs", "master-key", "set", "new-manual-key"}); err != nil {
		t.Fatalf("master-key set failed: %v", err)
	}
	if mock.data["sshs/master-key"] != "new-manual-key" {
		t.Fatalf("mock keyring not updated, got %q", mock.data["sshs/master-key"])
	}

	if err := app.Run([]string{"sshs", "master-key", "delete"}); err != nil {
		t.Fatalf("master-key delete failed: %v", err)
	}
	if _, ok := mock.data["sshs/master-key"]; ok {
		t.Fatal("mock keyring key not deleted")
	}

	setCachedMasterKey("")
}

func Test_BeforeAction(t *testing.T) {
	setCachedMasterKey("")
	mock := &mockKeyring{data: make(map[string]string)}
	oldKeyring := activeKeyring
	activeKeyring = mock
	defer func() { activeKeyring = oldKeyring }()

	dir := t.TempDir()
	configFile := filepath.Join(dir, ".sshs.yaml")
	sample := `- name: node1
  host: 192.168.1.1
  password: "ENC(v1:sample)"
`
	if err := os.WriteFile(configFile, []byte(sample), 0600); err != nil {
		t.Fatal(err)
	}

	oldConfigFilenames := configFilenames
	configFilenames = []string{configFile}
	defer func() { configFilenames = oldConfigFilenames }()

	app := newApp()

	// 1. 模拟终端手动输入设置主密码
	oldTerminalCheck := stdinTerminalCheck
	oldPasswordReader := terminalPasswordReader
	defer func() {
		stdinTerminalCheck = oldTerminalCheck
		terminalPasswordReader = oldPasswordReader
	}()

	stdinTerminalCheck = func(fd int) bool { return true }
	terminalPasswordReader = func(fd int) ([]byte, error) {
		return []byte("universal-hook-key"), nil
	}

	// 首次运行任何 subcommand（例如 list），在 Before 钩子中强制完成主密码初始化并存入钥匙串
	if err := app.Run([]string{"sshs", "list"}); err != nil {
		t.Fatalf("app.Run(list) failed during first initialization: %v", err)
	}

	if mock.data["sshs/master-key"] != "universal-hook-key" {
		t.Fatalf("master key not saved through before hook, got %q", mock.data["sshs/master-key"])
	}

	// 2. 初始化完成后，再次运行任何子命令（例如 doctor），直接无感通过
	if err := app.Run([]string{"sshs", "doctor"}); err != nil {
		t.Fatalf("app.Run(doctor) should pass silently after initialization: %v", err)
	}

	setCachedMasterKey("")
}

func Test_AfterActionAutoEncryptsPlaintext(t *testing.T) {
	setCachedMasterKey("")
	mock := &mockKeyring{data: map[string]string{"sshs/master-key": "auto-encrypt-key"}}
	oldKeyring := activeKeyring
	activeKeyring = mock
	defer func() { activeKeyring = oldKeyring }()

	dir := t.TempDir()
	configFile := filepath.Join(dir, ".sshs.yaml")
	sample := `- name: node1
  host: 192.168.1.1
  password: "unencrypted-secret"
`
	if err := os.WriteFile(configFile, []byte(sample), 0600); err != nil {
		t.Fatal(err)
	}

	oldConfigFilenames := configFilenames
	configFilenames = []string{configFile}
	defer func() { configFilenames = oldConfigFilenames }()

	app := newApp()

	// 运行任意命令（如 list），命令结束后 AfterAction 应自动将明文密码加密存盘
	if err := app.Run([]string{"sshs", "list"}); err != nil {
		t.Fatalf("app.Run(list) failed: %v", err)
	}

	updated, err := os.ReadFile(configFile)
	if err != nil {
		t.Fatal(err)
	}
	content := string(updated)
	if strings.Contains(content, "unencrypted-secret") {
		t.Fatalf("config file still contains plaintext password after AfterAction execution: %s", content)
	}
	if !strings.Contains(content, "ENC(v1:") {
		t.Fatalf("config file was not encrypted by AfterAction: %s", content)
	}

	// 再次运行命令，已全部为密文，应静默通过
	if err := app.Run([]string{"sshs", "list"}); err != nil {
		t.Fatalf("second app.Run(list) failed: %v", err)
	}

	setCachedMasterKey("")
}

