package main

import (
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// unavailableKeyring 模拟没有系统钥匙串的环境（无 Secret Service 的 Linux 服务器/容器）。
type unavailableKeyring struct{}

func (unavailableKeyring) Get(string, string) (string, error) {
	return "", errors.New("keyring unavailable")
}

func (unavailableKeyring) Set(string, string, string) error {
	return errors.New("keyring unavailable")
}

func (unavailableKeyring) Delete(string, string) error {
	return errors.New("keyring unavailable")
}

// TestMain 隔离主密码文件路径与主密码环境变量，避免单测读写真实用户配置。
func TestMain(m *testing.M) {
	flag.Parse()

	testRoot, err := os.MkdirTemp("", "sshs-master-key-test-*")
	if err != nil {
		panic(err)
	}
	os.Unsetenv(masterKeyEnv)
	masterKeyFileResolver = func() (string, error) {
		return filepath.Join(testRoot, "sshs", "master-key"), nil
	}

	code := m.Run()
	os.RemoveAll(testRoot)
	os.Exit(code)
}

// isolateMasterKeyState 替换钥匙串后端并重置进程内主密码缓存，测试结束后恢复。
func isolateMasterKeyState(t *testing.T, provider KeyringProvider) {
	t.Helper()
	oldProvider := activeKeyring
	activeKeyring = provider
	setCachedMasterKey("")
	t.Cleanup(func() {
		activeKeyring = oldProvider
		setCachedMasterKey("")
	})
}

// Test_SaveMasterKeyFallsBackToFile 验证钥匙串不可用时主密码落盘为 0600 文件并可读回。
func Test_SaveMasterKeyFallsBackToFile(t *testing.T) {
	isolateMasterKeyState(t, unavailableKeyring{})
	path := filepath.Join(t.TempDir(), "nested", "master-key")
	t.Setenv(masterKeyFileEnv, path)

	source, location, err := SaveMasterKey("file-master-key-123")
	if err != nil {
		t.Fatalf("SaveMasterKey failed: %v", err)
	}
	if source != masterKeySourceFile || location != path {
		t.Fatalf("SaveMasterKey() = (%q, %q), want file backend at %q", source, location, path)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat master key file: %v", err)
	}
	if perm := info.Mode().Perm(); perm != keyFilePerm {
		t.Fatalf("master key file mode = %#o, want %#o", perm, keyFilePerm)
	}

	key, gotSource := LoadMasterKey()
	if key != "file-master-key-123" || gotSource != masterKeySourceFile {
		t.Fatalf("LoadMasterKey() = (%q, %q), want file backend key", key, gotSource)
	}
}

// Test_LoadMasterKeyPrecedence 验证解析顺序：环境变量 → 系统钥匙串 → 主密码文件。
func Test_LoadMasterKeyPrecedence(t *testing.T) {
	mock := &mockKeyring{data: map[string]string{"sshs/master-key": "keyring-key"}}
	isolateMasterKeyState(t, mock)

	path := filepath.Join(t.TempDir(), "master-key")
	t.Setenv(masterKeyFileEnv, path)
	if err := os.WriteFile(path, []byte("file-key\n"), keyFilePerm); err != nil {
		t.Fatal(err)
	}

	if key, source := LoadMasterKey(); key != "keyring-key" || source != masterKeySourceKeyring {
		t.Fatalf("LoadMasterKey() = (%q, %q), want keyring to win over file", key, source)
	}

	t.Setenv(masterKeyEnv, "env-key")
	if key, source := LoadMasterKey(); key != "env-key" || source != masterKeySourceEnv {
		t.Fatalf("LoadMasterKey() = (%q, %q), want env to win over keyring", key, source)
	}

	// 自动加密只认可持久化来源，必须忽略环境变量。
	if key, source := loadPersistedMasterKey(); key != "keyring-key" || source != masterKeySourceKeyring {
		t.Fatalf("loadPersistedMasterKey() = (%q, %q), want to ignore env key", key, source)
	}
}

// Test_EnsureMasterKeyNonInteractiveSkips 验证无 TTY 且无主密码时不阻塞命令执行。
func Test_EnsureMasterKeyNonInteractiveSkips(t *testing.T) {
	isolateMasterKeyState(t, unavailableKeyring{})

	oldCheck := stdinTerminalCheck
	stdinTerminalCheck = func(int) bool { return false }
	t.Cleanup(func() { stdinTerminalCheck = oldCheck })

	if err := EnsureMasterKey(); err != nil {
		t.Fatalf("EnsureMasterKey() in non-interactive env = %v, want nil", err)
	}
	if getCachedMasterKey() != "" {
		t.Fatalf("cached master key = %q, want empty", getCachedMasterKey())
	}
}

// Test_ResolveMasterKeyNonInteractiveError 验证真正需要解密且无 TTY 时给出明确操作指引。
func Test_ResolveMasterKeyNonInteractiveError(t *testing.T) {
	isolateMasterKeyState(t, unavailableKeyring{})

	oldCheck := stdinTerminalCheck
	stdinTerminalCheck = func(int) bool { return false }
	t.Cleanup(func() { stdinTerminalCheck = oldCheck })

	_, err := ResolveMasterKey()
	if err == nil {
		t.Fatal("ResolveMasterKey() expected error, got nil")
	}
	if !strings.Contains(err.Error(), "sshs master-key set") {
		t.Fatalf("ResolveMasterKey() error should guide to 'sshs master-key set', got: %v", err)
	}
}

// Test_AutoEncryptSkipsEnvInjectedMasterKey 验证仅通过环境变量注入主密码时不会改写配置文件，
// 避免临时主密码把配置加密成其他环境无法解密的内容。
func Test_AutoEncryptSkipsEnvInjectedMasterKey(t *testing.T) {
	isolateMasterKeyState(t, &mockKeyring{data: map[string]string{}})
	t.Setenv(masterKeyEnv, "env-only-master-key")

	dir := t.TempDir()
	configFile := filepath.Join(dir, ".sshs.yaml")
	sample := "- name: node1\n  host: 192.168.1.1\n  password: \"plain-secret\"\n"
	if err := os.WriteFile(configFile, []byte(sample), 0600); err != nil {
		t.Fatal(err)
	}

	oldConfigFilenames := configFilenames
	configFilenames = []string{configFile}
	t.Cleanup(func() { configFilenames = oldConfigFilenames })

	app := newApp()
	var out strings.Builder
	app.Writer = &out
	if err := app.Run([]string{"sshs", "list"}); err != nil {
		t.Fatalf("app.Run(list) failed: %v", err)
	}

	updated, err := os.ReadFile(configFile)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(updated), "ENC(v1:") {
		t.Fatalf("config was encrypted with env-only master key: %s", updated)
	}
	if !strings.Contains(string(updated), "plain-secret") {
		t.Fatalf("config should keep plaintext password: %s", updated)
	}
}

// Test_MasterKeyActionSetFromStdinPipe 验证非交互场景可通过管道设置主密码并写入文件后端。
func Test_MasterKeyActionSetFromStdinPipe(t *testing.T) {
	isolateMasterKeyState(t, unavailableKeyring{})
	path := filepath.Join(t.TempDir(), "master-key")
	t.Setenv(masterKeyFileEnv, path)

	oldStdin := os.Stdin
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdin = reader
	t.Cleanup(func() { os.Stdin = oldStdin })
	if _, err := writer.WriteString("piped-master-key\n"); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	app := newApp()
	var out strings.Builder
	app.Writer = &out
	if err := app.Run([]string{"sshs", "master-key", "set"}); err != nil {
		t.Fatalf("master-key set from stdin failed: %v", err)
	}
	if !strings.Contains(out.String(), "saved to file") {
		t.Fatalf("unexpected set output: %s", out.String())
	}

	key, source := LoadMasterKey()
	if key != "piped-master-key" || source != masterKeySourceFile {
		t.Fatalf("LoadMasterKey() = (%q, %q), want piped key from file backend", key, source)
	}

	out.Reset()
	if err := app.Run([]string{"sshs", "master-key", "status"}); err != nil {
		t.Fatalf("master-key status failed: %v", err)
	}
	if !strings.Contains(out.String(), "is configured in file") {
		t.Fatalf("status should report file backend, got: %s", out.String())
	}
}

// Test_DeleteMasterKeyRemovesKeyringAndFile 验证删除主密码时钥匙串与文件后端都会被清理。
func Test_DeleteMasterKeyRemovesKeyringAndFile(t *testing.T) {
	mock := &mockKeyring{data: map[string]string{"sshs/master-key": "keyring-key"}}
	isolateMasterKeyState(t, mock)

	path := filepath.Join(t.TempDir(), "master-key")
	t.Setenv(masterKeyFileEnv, path)
	if err := os.WriteFile(path, []byte("file-key\n"), keyFilePerm); err != nil {
		t.Fatal(err)
	}

	if err := DeleteMasterKey(); err != nil {
		t.Fatalf("DeleteMasterKey failed: %v", err)
	}
	if _, ok := mock.data["sshs/master-key"]; ok {
		t.Fatal("keyring master key was not removed")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("master key file was not removed: %v", err)
	}
}

// Test_CheckMasterKeyBackendFilePermissions 验证 doctor 能发现主密码文件权限过宽。
func Test_CheckMasterKeyBackendFilePermissions(t *testing.T) {
	isolateMasterKeyState(t, &mockKeyring{data: map[string]string{}})

	path := filepath.Join(t.TempDir(), "master-key")
	t.Setenv(masterKeyFileEnv, path)
	if err := os.WriteFile(path, []byte("file-key\n"), keyFilePerm); err != nil {
		t.Fatal(err)
	}

	if issues := checkMasterKeyBackend(); len(issues) != 0 {
		t.Fatalf("expected no issue for 0600 master key file, got: %#v", issues)
	}

	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	issues := checkMasterKeyBackend()
	if len(issues) != 1 || !strings.Contains(issues[0].Message, "too open") {
		t.Fatalf("expected permissions too open issue, got: %#v", issues)
	}
}
