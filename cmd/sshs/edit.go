package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/urfave/cli/v2"
)

func EditAction(c *cli.Context) error {
	configPath, err := findTargetConfigFile(c)
	if err != nil {
		return cli.Exit(fmt.Sprintf("find config file: %v", err), 1)
	}

	b, err := os.ReadFile(configPath)
	if err != nil {
		return cli.Exit(fmt.Sprintf("read config file: %v", err), 1)
	}

	info, err := os.Stat(configPath)
	if err != nil {
		return cli.Exit(fmt.Sprintf("stat config file: %v", err), 1)
	}

	// 1. edit 强制要求人工在终端手动输入 Master Key 认证身份
	masterKey, err := PromptMasterKeyManual()
	if err != nil {
		return cli.Exit(err.Error(), 1)
	}
	setCachedMasterKey(masterKey)

	// 2. 若配置中包含密文，使用手动输入的 Master Key 解密；若口令错误直接拦截退出
	editContent := b
	if strings.Contains(string(b), "ENC(v1:") {
		decrypted, _, err := DecryptPasswordInYAML(b, masterKey)
		if err != nil {
			return cli.Exit(fmt.Sprintf("failed to decrypt config: %v", err), 1)
		}
		editContent = decrypted
	}

	// 3. 调起终端编辑器供用户直观编辑
	edited, err := Edit(editContent)
	if err != nil {
		return err
	}

	// 4. 用户保存退出后，立即使用该 Master Key 将所有明文密码重新全量加密
	toWrite := edited
	if encrypted, _, err := EncryptPasswordInYAML(edited, masterKey); err == nil {
		toWrite = encrypted
	}

	// 4. 原子安全写入磁盘目标配置文件
	if err := writeConfigFileAtomic(configPath, toWrite, info.Mode()); err != nil {
		return cli.Exit(fmt.Sprintf("write config file: %v", err), 1)
	}
	return nil
}

func Edit(b []byte) ([]byte, error) {
	editor := os.Getenv("EDITOR")
	if editor == "" {
		// 检查vim是否存在
		_, err := exec.LookPath("vim")
		if err == nil {
			editor = "vim"
		} else {
			editor = "vi"
		}
	}

	tempDir := os.TempDir()
	tempFile, err := os.CreateTemp(tempDir, "sshs-edit-*.yaml")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tempFile.Name())

	// 权限严格控制为 0600，仅限当前用户读写
	if err := tempFile.Chmod(0600); err != nil {
		tempFile.Close()
		return nil, err
	}

	if _, err := tempFile.Write(b); err != nil {
		tempFile.Close()
		return nil, err
	}
	if err := tempFile.Close(); err != nil {
		return nil, err
	}

	cmd := exec.Command(editor, tempFile.Name())
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return nil, err
	}

	return os.ReadFile(tempFile.Name())
}
