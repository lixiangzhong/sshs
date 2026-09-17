package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/urfave/cli/v2"
	"golang.org/x/term"
)

var (
	decryptPromptMasterKey = promptMasterKeyFromTTY
	decryptStdinReader     = func() io.Reader { return os.Stdin }
)

// promptMasterKeyFromTTY 强制从终端控制设备 (/dev/tty) 手动读取主密码。
// 提示信息打印到 os.Stderr，避免污染 stdout 的解密数据；
// 读取采用无回显模式，绝不将主密码显式暴露。
func promptMasterKeyFromTTY() (string, error) {
	// 1. 优先尝试打开控制终端 /dev/tty (Unix/macOS)
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err == nil {
		defer tty.Close()
		ttyFd := int(tty.Fd())
		if term.IsTerminal(ttyFd) {
			fmt.Fprint(os.Stderr, "Enter Master Password: ")
			passBytes, err := term.ReadPassword(ttyFd)
			fmt.Fprintln(os.Stderr)
			if err != nil {
				return "", fmt.Errorf("read master password: %w", err)
			}
			pass := strings.TrimSpace(string(passBytes))
			if pass == "" {
				return "", errors.New("master password cannot be empty")
			}
			return pass, nil
		}
	}

	// 2. 如果 /dev/tty 不可用，且 stdin 是终端，则直接从 stdin 读
	stdinFd := int(os.Stdin.Fd())
	if term.IsTerminal(stdinFd) {
		return PromptMasterKeyManual()
	}

	return "", errors.New("interactive terminal (/dev/tty) required to input master password")
}

// DecryptContent 解密输入内容：
// - 若输入为单个密文（如 ENC(v1:...)），解密并返回明文字符串；
// - 若输入为 YAML 内容，使用 AST 扫描替换其中的 ENC(v1:...) 密码；
// - 若未包含任何 ENC(v1:...) 密文，直接返回原内容。
func DecryptContent(data []byte, masterKey string) ([]byte, error) {
	trimmed := strings.TrimSpace(string(data))
	unquoted := strings.Trim(trimmed, `"'`)
	if IsEncrypted(unquoted) {
		plain, err := DecryptPassword(unquoted, masterKey)
		if err != nil {
			return nil, err
		}
		return []byte(plain), nil
	}

	if !strings.Contains(string(data), encPrefix) {
		return data, nil
	}

	decrypted, _, err := DecryptPasswordInYAML(data, masterKey)
	if err != nil {
		return nil, err
	}
	return decrypted, nil
}

// DecryptAction 是 `sshs dec`（及别名 `decrypt`）子命令的处理函数。
// 从 stdin 中读取待解密数据，强制在控制终端手动输入 Master Password 认证，
// 解密后将明文输出至 stdout。
func DecryptAction(c *cli.Context) error {
	reader := decryptStdinReader()
	data, err := io.ReadAll(reader)
	if err != nil {
		return cli.Exit(fmt.Sprintf("read stdin: %v", err), 1)
	}

	if len(data) == 0 {
		return cli.Exit("error: empty input from stdin", 1)
	}

	// 若未包含任何加密内容，直接透传原内容至 stdout
	if !strings.Contains(string(data), encPrefix) {
		out := c.App.Writer
		if out == nil {
			out = os.Stdout
		}
		_, err = out.Write(data)
		return err
	}

	// 强制要求人工在终端手动输入 Master Key
	masterKey, err := decryptPromptMasterKey()
	if err != nil {
		return cli.Exit(err.Error(), 1)
	}

	// 若系统钥匙串已存储 Master Key，先核对输入的口令是否匹配
	if ringKey, err := GetKeyringMasterKey(); err == nil && ringKey != "" {
		if masterKey != ringKey {
			return cli.Exit("master password incorrect", 1)
		}
	}

	decrypted, err := DecryptContent(data, masterKey)
	if err != nil {
		return cli.Exit(fmt.Sprintf("decryption failed: %v", err), 1)
	}

	if len(decrypted) > 0 && !bytes.HasSuffix(decrypted, []byte("\n")) {
		decrypted = append(decrypted, '\n')
	}

	out := c.App.Writer
	if out == nil {
		out = os.Stdout
	}
	if _, err := out.Write(decrypted); err != nil {
		return cli.Exit(fmt.Sprintf("write output: %v", err), 1)
	}

	return nil
}
