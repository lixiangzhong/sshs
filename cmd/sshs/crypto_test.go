package main

import (
	"errors"
	"testing"
)

func Test_EncryptAndDecryptPassword(t *testing.T) {
	masterKey := "my-strong-master-key-123"
	testCases := []string{
		"simplepass",
		"123456",
		"P@ssw0rd!#%^&*()_+-=[]{}|;:,.<>?",
		"包含中文与特殊字符的密码 🔑 888",
		"",
	}

	for _, plain := range testCases {
		encrypted, err := EncryptPassword(plain, masterKey)
		if err != nil {
			t.Fatalf("EncryptPassword(%q) failed: %v", plain, err)
		}
		if !IsEncrypted(encrypted) {
			t.Fatalf("IsEncrypted(%q) = false, want true", encrypted)
		}

		decrypted, err := DecryptPassword(encrypted, masterKey)
		if err != nil {
			t.Fatalf("DecryptPassword(%q) failed: %v", encrypted, err)
		}
		if decrypted != plain {
			t.Fatalf("DecryptPassword() = %q, want %q", decrypted, plain)
		}
	}
}

func Test_DecryptWithWrongMasterKeyFails(t *testing.T) {
	plain := "secret-server-pass"
	encrypted, err := EncryptPassword(plain, "correct-key")
	if err != nil {
		t.Fatalf("EncryptPassword failed: %v", err)
	}

	_, err = DecryptPassword(encrypted, "wrong-key")
	if err == nil {
		t.Fatal("DecryptPassword with wrong master key expected error, got nil")
	}
}

func Test_DecryptCorruptedCiphertextFails(t *testing.T) {
	masterKey := "test-key"
	encrypted, err := EncryptPassword("mypass", masterKey)
	if err != nil {
		t.Fatalf("EncryptPassword failed: %v", err)
	}

	// 破坏密文内容
	corrupted := encrypted[:len(encrypted)-3] + "ab)"
	_, err = DecryptPassword(corrupted, masterKey)
	if err == nil {
		t.Fatal("DecryptPassword with corrupted ciphertext expected error, got nil")
	}
}

func Test_IsEncrypted(t *testing.T) {
	if !IsEncrypted("ENC(v1:dGVzdA)") {
		t.Fatal("IsEncrypted failed for valid prefix")
	}
	if IsEncrypted("plain-password") {
		t.Fatal("IsEncrypted returned true for plain text")
	}
	if IsEncrypted("ENC(") {
		t.Fatal("IsEncrypted returned true for incomplete prefix")
	}
}

type mockKeyring struct {
	data map[string]string
}

func (m *mockKeyring) Get(service, account string) (string, error) {
	if val, ok := m.data[service+"/"+account]; ok && val != "" {
		return val, nil
	}
	return "", errors.New("secret not found in keyring")
}

func (m *mockKeyring) Set(service, account, password string) error {
	if m.data == nil {
		m.data = make(map[string]string)
	}
	m.data[service+"/"+account] = password
	return nil
}

func (m *mockKeyring) Delete(service, account string) error {
	delete(m.data, service+"/"+account)
	return nil
}

func Test_ResolveMasterKeyFromKeyring(t *testing.T) {
	setCachedMasterKey("")
	mock := &mockKeyring{data: map[string]string{"sshs/master-key": "keyring-pass-123"}}
	oldKeyring := activeKeyring
	activeKeyring = mock
	defer func() { activeKeyring = oldKeyring }()

	key, err := ResolveMasterKey(false)
	if err != nil {
		t.Fatalf("ResolveMasterKey failed: %v", err)
	}
	if key != "keyring-pass-123" {
		t.Fatalf("ResolveMasterKey() = %q, want 'keyring-pass-123'", key)
	}

	// 验证进程缓存已生效
	mock.data = nil
	cached, err := ResolveMasterKey(false)
	if err != nil {
		t.Fatalf("ResolveMasterKey cached failed: %v", err)
	}
	if cached != "keyring-pass-123" {
		t.Fatalf("ResolveMasterKey() cached = %q, want 'keyring-pass-123'", cached)
	}
	setCachedMasterKey("")
}

func Test_SetAndGetKeyringMasterKey(t *testing.T) {
	setCachedMasterKey("")
	mock := &mockKeyring{data: make(map[string]string)}
	oldKeyring := activeKeyring
	activeKeyring = mock
	defer func() { activeKeyring = oldKeyring }()

	if err := SetKeyringMasterKey("my-new-master-key"); err != nil {
		t.Fatalf("SetKeyringMasterKey failed: %v", err)
	}

	got, err := GetKeyringMasterKey()
	if err != nil {
		t.Fatalf("GetKeyringMasterKey failed: %v", err)
	}
	if got != "my-new-master-key" {
		t.Fatalf("GetKeyringMasterKey() = %q, want 'my-new-master-key'", got)
	}

	if err := DeleteKeyringMasterKey(); err != nil {
		t.Fatalf("DeleteKeyringMasterKey failed: %v", err)
	}

	_, err = GetKeyringMasterKey()
	if err == nil {
		t.Fatal("GetKeyringMasterKey expected error after delete, got nil")
	}
}

func Test_EnsureMasterKey(t *testing.T) {
	setCachedMasterKey("")
	mock := &mockKeyring{data: make(map[string]string)}
	oldKeyring := activeKeyring
	activeKeyring = mock
	defer func() { activeKeyring = oldKeyring }()

	// 1. 钥匙串为空：强制要求终端输入并自动存入钥匙串
	oldTerminalCheck := stdinTerminalCheck
	oldPasswordReader := terminalPasswordReader
	defer func() {
		stdinTerminalCheck = oldTerminalCheck
		terminalPasswordReader = oldPasswordReader
	}()

	stdinTerminalCheck = func(fd int) bool { return true }
	terminalPasswordReader = func(fd int) ([]byte, error) {
		return []byte("new-setup-key"), nil
	}

	if err := EnsureMasterKey(); err != nil {
		t.Fatalf("EnsureMasterKey interactive setup failed: %v", err)
	}

	if mock.data["sshs/master-key"] != "new-setup-key" {
		t.Fatalf("master key not saved to keyring, got: %q", mock.data["sshs/master-key"])
	}

	// 2. 再次运行：keyring 已有，直接无感放行
	if err := EnsureMasterKey(); err != nil {
		t.Fatalf("EnsureMasterKey should pass silently when keyring has key: %v", err)
	}

	setCachedMasterKey("")
}
