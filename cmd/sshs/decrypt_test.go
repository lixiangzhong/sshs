package main

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/urfave/cli/v2"
)

func Test_DecryptCommandIsHiddenInHelp(t *testing.T) {
	app := newApp()
	var decryptCmd *cli.Command
	for _, cmd := range app.Commands {
		if cmd.Name == "dec" {
			decryptCmd = cmd
			break
		}
	}
	if decryptCmd == nil {
		t.Fatal("dec command not found in app.Commands")
	}
	if !decryptCmd.Hidden {
		t.Fatal("expected dec command to be hidden (Hidden == true)")
	}

	var buf bytes.Buffer
	app.Writer = &buf
	if err := app.Run([]string{"sshs", "--help"}); err != nil {
		t.Fatalf("app.Run --help failed: %v", err)
	}
	if strings.Contains(buf.String(), "   dec") {
		t.Fatalf("help text should NOT contain 'dec' command listing, got:\n%s", buf.String())
	}
}

func Test_DecryptActionSingleCiphertext(t *testing.T) {
	masterKey := "my-secret-master-key"
	mock := &mockKeyring{data: map[string]string{"sshs/master-key": masterKey}}
	oldKeyring := activeKeyring
	activeKeyring = mock
	defer func() { activeKeyring = oldKeyring }()
	setCachedMasterKey(masterKey)
	defer setCachedMasterKey("")

	plainPass := "secret-hello-world-pass"
	encPass, err := EncryptPassword(plainPass, masterKey)
	if err != nil {
		t.Fatal(err)
	}

	origPrompt := decryptPromptMasterKey
	origReader := decryptStdinReader
	origExiter := cli.OsExiter
	defer func() {
		decryptPromptMasterKey = origPrompt
		decryptStdinReader = origReader
		cli.OsExiter = origExiter
	}()
	cli.OsExiter = func(int) {}

	// 模拟手动输入正确的主密码
	promptCalled := false
	decryptPromptMasterKey = func() (string, error) {
		promptCalled = true
		return masterKey, nil
	}
	decryptStdinReader = func() io.Reader {
		return strings.NewReader(encPass + "\n")
	}

	app := newApp()
	var outBuf bytes.Buffer
	app.Writer = &outBuf

	if err := app.Run([]string{"sshs", "dec"}); err != nil {
		t.Fatalf("app.Run dec failed: %v", err)
	}

	if !promptCalled {
		t.Fatal("expected manual master password prompt to be called")
	}
	got := strings.TrimSpace(outBuf.String())
	if got != plainPass {
		t.Fatalf("expected plain %q, got %q", plainPass, got)
	}

	// 验证别名 decrypt 也正常工作
	outBuf.Reset()
	decryptStdinReader = func() io.Reader {
		return strings.NewReader(encPass + "\n")
	}
	if err := app.Run([]string{"sshs", "decrypt"}); err != nil {
		t.Fatalf("app.Run decrypt (alias) failed: %v", err)
	}
	got = strings.TrimSpace(outBuf.String())
	if got != plainPass {
		t.Fatalf("expected plain %q from alias, got %q", plainPass, got)
	}
}

func Test_DecryptActionYAML(t *testing.T) {
	masterKey := "yaml-master-key"
	mock := &mockKeyring{data: map[string]string{"sshs/master-key": masterKey}}
	oldKeyring := activeKeyring
	activeKeyring = mock
	defer func() { activeKeyring = oldKeyring }()
	setCachedMasterKey(masterKey)
	defer setCachedMasterKey("")

	p1 := "pass-one-111"
	p2 := "pass-two-222"
	enc1, _ := EncryptPassword(p1, masterKey)
	enc2, _ := EncryptPassword(p2, masterKey)

	yamlInput := fmt.Sprintf(`- name: server1
  host: 192.168.1.1
  password: %q
- name: server2
  host: 192.168.1.2
  password: %q
`, enc1, enc2)

	origPrompt := decryptPromptMasterKey
	origReader := decryptStdinReader
	origExiter := cli.OsExiter
	defer func() {
		decryptPromptMasterKey = origPrompt
		decryptStdinReader = origReader
		cli.OsExiter = origExiter
	}()
	cli.OsExiter = func(int) {}

	// 模拟手动输入正确主密码
	decryptPromptMasterKey = func() (string, error) {
		return masterKey, nil
	}
	decryptStdinReader = func() io.Reader {
		return strings.NewReader(yamlInput)
	}

	app := newApp()
	var outBuf bytes.Buffer
	app.Writer = &outBuf

	if err := app.Run([]string{"sshs", "dec"}); err != nil {
		t.Fatalf("app.Run dec failed: %v", err)
	}

	outStr := outBuf.String()
	if !strings.Contains(outStr, p1) || !strings.Contains(outStr, p2) {
		t.Fatalf("decrypted yaml should contain plain passwords, got:\n%s", outStr)
	}
	if strings.Contains(outStr, "ENC(v1:") {
		t.Fatalf("decrypted yaml should not contain ciphertexts, got:\n%s", outStr)
	}
}

func Test_DecryptActionPlainContentPassthrough(t *testing.T) {
	plainInput := "hello: world\nnumber: 12345\n"

	promptCalled := false
	origPrompt := decryptPromptMasterKey
	origReader := decryptStdinReader
	origExiter := cli.OsExiter
	defer func() {
		decryptPromptMasterKey = origPrompt
		decryptStdinReader = origReader
		cli.OsExiter = origExiter
	}()
	cli.OsExiter = func(int) {}

	decryptPromptMasterKey = func() (string, error) {
		promptCalled = true
		return "key", nil
	}
	decryptStdinReader = func() io.Reader {
		return strings.NewReader(plainInput)
	}

	app := newApp()
	var outBuf bytes.Buffer
	app.Writer = &outBuf

	if err := app.Run([]string{"sshs", "dec"}); err != nil {
		t.Fatalf("app.Run dec failed: %v", err)
	}

	if promptCalled {
		t.Fatal("prompt should NOT be called when input has no encrypted data")
	}
	if outBuf.String() != plainInput {
		t.Fatalf("expected plain passthrough %q, got %q", plainInput, outBuf.String())
	}
}

func Test_DecryptActionWrongMasterKeyFails(t *testing.T) {
	masterKey := "correct-master-key"
	mock := &mockKeyring{data: map[string]string{"sshs/master-key": masterKey}}
	oldKeyring := activeKeyring
	activeKeyring = mock
	defer func() { activeKeyring = oldKeyring }()
	setCachedMasterKey(masterKey)
	defer setCachedMasterKey("")

	encPass, err := EncryptPassword("secret", masterKey)
	if err != nil {
		t.Fatal(err)
	}

	origPrompt := decryptPromptMasterKey
	origReader := decryptStdinReader
	origExiter := cli.OsExiter
	defer func() {
		decryptPromptMasterKey = origPrompt
		decryptStdinReader = origReader
		cli.OsExiter = origExiter
	}()
	cli.OsExiter = func(int) {}

	// 手动输入错误密码
	decryptPromptMasterKey = func() (string, error) {
		return "wrong-master-key", nil
	}
	decryptStdinReader = func() io.Reader {
		return strings.NewReader(encPass + "\n")
	}

	app := newApp()
	err = app.Run([]string{"sshs", "dec"})
	if err == nil {
		t.Fatal("expected error on wrong master key, got nil")
	}
	if !strings.Contains(err.Error(), "master password incorrect") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func Test_DecryptActionEmptyInputFails(t *testing.T) {
	origReader := decryptStdinReader
	origExiter := cli.OsExiter
	defer func() {
		decryptStdinReader = origReader
		cli.OsExiter = origExiter
	}()
	cli.OsExiter = func(int) {}

	decryptStdinReader = func() io.Reader {
		return strings.NewReader("")
	}

	app := newApp()
	err := app.Run([]string{"sshs", "dec"})
	if err == nil {
		t.Fatal("expected error on empty stdin, got nil")
	}
	if !strings.Contains(err.Error(), "empty input") {
		t.Fatalf("unexpected error message: %v", err)
	}
}
