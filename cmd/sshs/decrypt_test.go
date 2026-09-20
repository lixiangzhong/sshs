package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
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
	masterKey := "test-plain-passthrough-key"
	mock := &mockKeyring{data: map[string]string{"sshs/master-key": masterKey}}
	oldKeyring := activeKeyring
	activeKeyring = mock
	defer func() { activeKeyring = oldKeyring }()
	setCachedMasterKey(masterKey)
	defer setCachedMasterKey("")

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
		return masterKey, nil
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

	if !promptCalled {
		t.Fatal("prompt SHOULD be called to verify master password first")
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
	masterKey := "empty-input-master-key"
	mock := &mockKeyring{data: map[string]string{"sshs/master-key": masterKey}}
	oldKeyring := activeKeyring
	activeKeyring = mock
	defer func() { activeKeyring = oldKeyring }()
	setCachedMasterKey(masterKey)
	defer setCachedMasterKey("")

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
		return masterKey, nil
	}
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

func Test_DecryptActionInteractivePrompt(t *testing.T) {
	masterKey := "interactive-master-key"
	mock := &mockKeyring{data: map[string]string{"sshs/master-key": masterKey}}
	oldKeyring := activeKeyring
	activeKeyring = mock
	defer func() { activeKeyring = oldKeyring }()
	setCachedMasterKey(masterKey)
	defer setCachedMasterKey("")

	plainPass := "my-interactive-secret"
	encPass, err := EncryptPassword(plainPass, masterKey)
	if err != nil {
		t.Fatal(err)
	}

	origPrompt := decryptPromptMasterKey
	origCipherPrompt := decryptPromptCiphertext
	origReader := decryptStdinReader
	origHasStdin := decryptHasStdin
	origExiter := cli.OsExiter
	defer func() {
		decryptPromptMasterKey = origPrompt
		decryptPromptCiphertext = origCipherPrompt
		decryptStdinReader = origReader
		decryptHasStdin = origHasStdin
		cli.OsExiter = origExiter
	}()
	cli.OsExiter = func(int) {}

	masterKeyPromptCalled := false
	ciphertextPromptCalled := false

	decryptPromptMasterKey = func() (string, error) {
		masterKeyPromptCalled = true
		return masterKey, nil
	}
	decryptPromptCiphertext = func() (string, error) {
		ciphertextPromptCalled = true
		return encPass, nil
	}
	decryptStdinReader = func() io.Reader {
		return os.Stdin
	}
	decryptHasStdin = func() bool {
		return false
	}

	app := newApp()
	var outBuf bytes.Buffer
	app.Writer = &outBuf

	if err := app.Run([]string{"sshs", "decrypt"}); err != nil {
		t.Fatalf("app.Run decrypt failed: %v", err)
	}

	if !masterKeyPromptCalled {
		t.Fatal("expected master key prompt to be called first")
	}
	if !ciphertextPromptCalled {
		t.Fatal("expected ciphertext prompt to be called when there is no stdin")
	}
	got := strings.TrimSpace(outBuf.String())
	if got != plainPass {
		t.Fatalf("expected decrypted plain %q, got %q", plainPass, got)
	}
}

func Test_DecryptActionArgument(t *testing.T) {
	masterKey := "arg-master-key"
	mock := &mockKeyring{data: map[string]string{"sshs/master-key": masterKey}}
	oldKeyring := activeKeyring
	activeKeyring = mock
	defer func() { activeKeyring = oldKeyring }()
	setCachedMasterKey(masterKey)
	defer setCachedMasterKey("")

	plainPass := "arg-secret-pass"
	encPass, err := EncryptPassword(plainPass, masterKey)
	if err != nil {
		t.Fatal(err)
	}

	origPrompt := decryptPromptMasterKey
	origCipherPrompt := decryptPromptCiphertext
	origReader := decryptStdinReader
	origHasStdin := decryptHasStdin
	origExiter := cli.OsExiter
	defer func() {
		decryptPromptMasterKey = origPrompt
		decryptPromptCiphertext = origCipherPrompt
		decryptStdinReader = origReader
		decryptHasStdin = origHasStdin
		cli.OsExiter = origExiter
	}()
	cli.OsExiter = func(int) {}

	decryptPromptMasterKey = func() (string, error) {
		return masterKey, nil
	}
	cipherPromptCalled := false
	decryptPromptCiphertext = func() (string, error) {
		cipherPromptCalled = true
		return "", nil
	}
	decryptStdinReader = func() io.Reader {
		return os.Stdin
	}
	decryptHasStdin = func() bool {
		return false
	}

	app := newApp()
	var outBuf bytes.Buffer
	app.Writer = &outBuf

	if err := app.Run([]string{"sshs", "dec", encPass}); err != nil {
		t.Fatalf("app.Run dec with arg failed: %v", err)
	}

	if cipherPromptCalled {
		t.Fatal("ciphertext prompt should NOT be called when argument is provided")
	}
	got := strings.TrimSpace(outBuf.String())
	if got != plainPass {
		t.Fatalf("expected decrypted plain %q, got %q", plainPass, got)
	}
}

func Test_DecryptActionInteractiveEmptyCiphertextFails(t *testing.T) {
	masterKey := "empty-interactive-master-key"
	mock := &mockKeyring{data: map[string]string{"sshs/master-key": masterKey}}
	oldKeyring := activeKeyring
	activeKeyring = mock
	defer func() { activeKeyring = oldKeyring }()
	setCachedMasterKey(masterKey)
	defer setCachedMasterKey("")

	origPrompt := decryptPromptMasterKey
	origCipherPrompt := decryptPromptCiphertext
	origReader := decryptStdinReader
	origHasStdin := decryptHasStdin
	origExiter := cli.OsExiter
	defer func() {
		decryptPromptMasterKey = origPrompt
		decryptPromptCiphertext = origCipherPrompt
		decryptStdinReader = origReader
		decryptHasStdin = origHasStdin
		cli.OsExiter = origExiter
	}()
	cli.OsExiter = func(int) {}

	decryptPromptMasterKey = func() (string, error) {
		return masterKey, nil
	}
	decryptPromptCiphertext = func() (string, error) {
		return "", errors.New("encrypted password cannot be empty")
	}
	decryptStdinReader = func() io.Reader {
		return os.Stdin
	}
	decryptHasStdin = func() bool {
		return false
	}

	app := newApp()
	err := app.Run([]string{"sshs", "decrypt"})
	if err == nil {
		t.Fatal("expected error on empty interactive ciphertext, got nil")
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Fatalf("unexpected error message: %v", err)
	}
}
