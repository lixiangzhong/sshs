package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/urfave/cli/v2"
)

func Test_EditActionShowsDecryptedAndSavesEncrypted(t *testing.T) {
	setCachedMasterKey("")
	mock := &mockKeyring{data: map[string]string{"sshs/master-key": "edit-test-master-key"}}
	oldKeyring := activeKeyring
	activeKeyring = mock
	defer func() { activeKeyring = oldKeyring }()

	dir := t.TempDir()
	configFile := filepath.Join(dir, ".sshs.yaml")

	// 初始文件包含 ENC(v1:...) 加密密码
	encPass, err := EncryptPassword("secret-edit-pass-1", "edit-test-master-key")
	if err != nil {
		t.Fatal(err)
	}

	initialYAML := fmt.Sprintf(`- name: server1
  host: 10.0.0.1
  password: %q
`, encPass)

	if err := os.WriteFile(configFile, []byte(initialYAML), 0600); err != nil {
		t.Fatal(err)
	}

	oldConfigFilenames := configFilenames
	configFilenames = []string{configFile}
	defer func() { configFilenames = oldConfigFilenames }()

	// 模拟终端手动输入 Master Key
	oldTerminalCheck := stdinTerminalCheck
	oldPasswordReader := terminalPasswordReader
	defer func() {
		stdinTerminalCheck = oldTerminalCheck
		terminalPasswordReader = oldPasswordReader
	}()

	stdinTerminalCheck = func(fd int) bool { return true }
	terminalPasswordReader = func(fd int) ([]byte, error) {
		return []byte("edit-test-master-key"), nil
	}

	// 构造 mock editor 脚本：
	// 1. 检查传递给编辑器的临时文件，必须包含已解密的明文 "secret-edit-pass-1"，绝不能包含 "ENC(v1:"；
	// 2. 向文件末尾追加新主机，且密码为纯明文 "secret-edit-pass-2"；
	// 3. 正常退出。
	mockEditorScript := filepath.Join(dir, "mock_editor.sh")
	scriptContent := `#!/bin/sh
set -e
TARGET="$1"

# 检查明文已解密
if ! grep -q "secret-edit-pass-1" "$TARGET"; then
  echo "Error: decrypted plaintext not found in temp file" >&2
  exit 1
fi
if grep -q "ENC(v1:" "$TARGET"; then
  echo "Error: temp file still contains ciphertext" >&2
  exit 1
fi

# 模拟用户追加带有明文密码的新节点
cat << 'EOF' >> "$TARGET"
- name: server2
  host: 10.0.0.2
  password: "secret-edit-pass-2"
EOF
`
	if err := os.WriteFile(mockEditorScript, []byte(scriptContent), 0755); err != nil {
		t.Fatal(err)
	}

	oldEditor := os.Getenv("EDITOR")
	os.Setenv("EDITOR", mockEditorScript)
	defer func() {
		if oldEditor == "" {
			os.Unsetenv("EDITOR")
		} else {
			os.Setenv("EDITOR", oldEditor)
		}
	}()

	app := newApp()
	if err := app.Run([]string{"sshs", "edit"}); err != nil {
		t.Fatalf("app.Run(edit) failed: %v", err)
	}

	// 验证磁盘上的配置文件：
	// 1. 两个主机的明文密码均已被加密，文件中不得出现任何明文密码
	finalBytes, err := os.ReadFile(configFile)
	if err != nil {
		t.Fatal(err)
	}
	finalContent := string(finalBytes)

	if strings.Contains(finalContent, "secret-edit-pass-1") {
		t.Fatalf("config file still contains plaintext pass1: %s", finalContent)
	}
	if strings.Contains(finalContent, "secret-edit-pass-2") {
		t.Fatalf("config file still contains plaintext pass2: %s", finalContent)
	}
	if !strings.Contains(finalContent, "server1") || !strings.Contains(finalContent, "server2") {
		t.Fatalf("config file missing hosts: %s", finalContent)
	}

	// 2. 解密验证两个密码值均正确无误
	decryptedYAML, count, err := DecryptPasswordInYAML(finalBytes, "edit-test-master-key")
	if err != nil {
		t.Fatalf("DecryptPasswordInYAML failed: %v", err)
	}
	if count != 2 {
		t.Fatalf("decrypted password count = %d, want 2", count)
	}
	decStr := string(decryptedYAML)
	if !strings.Contains(decStr, "secret-edit-pass-1") || !strings.Contains(decStr, "secret-edit-pass-2") {
		t.Fatalf("decrypted content does not match expected plaintexts: %s", decStr)
	}

	setCachedMasterKey("")
}

func Test_EditActionFailsWithWrongMasterKey(t *testing.T) {
	origExiter := cli.OsExiter
	cli.OsExiter = func(code int) {}
	defer func() { cli.OsExiter = origExiter }()

	setCachedMasterKey("")
	mock := &mockKeyring{data: map[string]string{"sshs/master-key": "correct-key"}}
	oldKeyring := activeKeyring
	activeKeyring = mock
	defer func() { activeKeyring = oldKeyring }()

	dir := t.TempDir()
	configFile := filepath.Join(dir, ".sshs.yaml")

	encPass, err := EncryptPassword("my-real-secret", "correct-key")
	if err != nil {
		t.Fatal(err)
	}
	initialYAML := fmt.Sprintf(`- name: server1
  host: 10.0.0.1
  password: %q
`, encPass)

	if err := os.WriteFile(configFile, []byte(initialYAML), 0600); err != nil {
		t.Fatal(err)
	}

	oldConfigFilenames := configFilenames
	configFilenames = []string{configFile}
	defer func() { configFilenames = oldConfigFilenames }()

	// 模拟手动输入了错误密码
	oldTerminalCheck := stdinTerminalCheck
	oldPasswordReader := terminalPasswordReader
	defer func() {
		stdinTerminalCheck = oldTerminalCheck
		terminalPasswordReader = oldPasswordReader
	}()

	stdinTerminalCheck = func(fd int) bool { return true }
	terminalPasswordReader = func(fd int) ([]byte, error) {
		return []byte("wrong-password-input"), nil
	}

	editorCalled := false
	mockEditorScript := filepath.Join(dir, "mock_editor.sh")
	if err := os.WriteFile(mockEditorScript, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}
	oldEditor := os.Getenv("EDITOR")
	os.Setenv("EDITOR", mockEditorScript)
	defer func() {
		if oldEditor == "" {
			os.Unsetenv("EDITOR")
		} else {
			os.Setenv("EDITOR", oldEditor)
		}
	}()

	app := newApp()
	err = app.Run([]string{"sshs", "edit"})
	if err == nil {
		t.Fatal("expected error when entering wrong master key for edit action")
	}
	if editorCalled {
		t.Fatal("editor should NOT be called when master password is wrong")
	}

	setCachedMasterKey("")
}

func Test_EditPassesSecurityFlagsToVim(t *testing.T) {
	dir := t.TempDir()
	mockVim := filepath.Join(dir, "mock_vim")
	script := `#!/bin/sh
set -e
has_n=0
has_i=0
for arg in "$@"; do
  if [ "$arg" = "-n" ]; then has_n=1; fi
  if [ "$arg" = "-i" ]; then has_i=1; fi
done
if [ $has_n -ne 1 ] || [ $has_i -ne 1 ]; then
  echo "missing security flags: $@" >&2
  exit 1
fi
exit 0
`
	if err := os.WriteFile(mockVim, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}

	oldEditor := os.Getenv("EDITOR")
	os.Setenv("EDITOR", mockVim)
	defer func() {
		if oldEditor == "" {
			os.Unsetenv("EDITOR")
		} else {
			os.Setenv("EDITOR", oldEditor)
		}
	}()

	_, err := Edit([]byte("test: content\n"))
	if err != nil {
		t.Fatalf("Edit failed when verifying security flags: %v", err)
	}
}
