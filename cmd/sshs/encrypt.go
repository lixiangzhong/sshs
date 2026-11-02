package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/parser"
	"github.com/goccy/go-yaml/token"
	"github.com/urfave/cli/v2"
)

type yamlNodeVisitor struct {
	visit func(ast.Node) error
	err   error
}

func (v *yamlNodeVisitor) Visit(node ast.Node) ast.Visitor {
	if node == nil || v.err != nil {
		return nil
	}
	if err := v.visit(node); err != nil {
		v.err = err
		return nil
	}
	return v
}

func isPasswordKeyNode(key ast.Node) bool {
	if key == nil {
		return false
	}
	if sn, ok := key.(*ast.StringNode); ok && sn.Value == "password" {
		return true
	}
	if tk := key.GetToken(); tk != nil && tk.Value == "password" {
		return true
	}
	return false
}

func extractNodeValue(node ast.Node) string {
	if node == nil {
		return ""
	}
	switch v := node.(type) {
	case *ast.StringNode:
		return v.Value
	case *ast.IntegerNode:
		return fmt.Sprintf("%v", v.Value)
	case *ast.FloatNode:
		return fmt.Sprintf("%v", v.Value)
	case *ast.BoolNode:
		return fmt.Sprintf("%v", v.Value)
	default:
		tk := node.GetToken()
		if tk != nil {
			return tk.Value
		}
		return ""
	}
}

// EncryptPasswordInYAML 扫描 YAML 内容中的所有明文 password 字段并加密为 ENC(v1:...)。
// 使用 goccy/go-yaml AST 重写节点，保留原始文件的注释与格式。
func EncryptPasswordInYAML(content []byte, masterKey string) ([]byte, int, error) {
	if masterKey == "" {
		return nil, 0, errors.New("master key cannot be empty")
	}

	file, err := parser.ParseBytes(content, parser.ParseComments)
	if err != nil {
		return nil, 0, fmt.Errorf("parse yaml: %w", err)
	}

	count := 0
	visitor := &yamlNodeVisitor{
		visit: func(node ast.Node) error {
			mv, ok := node.(*ast.MappingValueNode)
			if !ok || !isPasswordKeyNode(mv.Key) {
				return nil
			}

			val := extractNodeValue(mv.Value)
			if val == "" || IsEncrypted(val) {
				return nil
			}

			encrypted, err := EncryptPassword(val, masterKey)
			if err != nil {
				return err
			}

			var pos *token.Position
			if tk := mv.Value.GetToken(); tk != nil {
				pos = tk.Position
			}
			newTk := token.DoubleQuote(encrypted, fmt.Sprintf("%q", encrypted), pos)
			mv.Value = ast.String(newTk)
			count++
			return nil
		},
	}

	for _, doc := range file.Docs {
		ast.Walk(visitor, doc)
		if visitor.err != nil {
			return nil, 0, visitor.err
		}
	}

	return []byte(file.String()), count, nil
}

// DecryptPasswordInYAML 扫描 YAML 内容中的所有 ENC(v1:...) 密码并解密为明文。
// 使用 goccy/go-yaml AST 重写节点，保留原始文件的注释与格式。
func DecryptPasswordInYAML(content []byte, masterKey string) ([]byte, int, error) {
	if masterKey == "" {
		return nil, 0, errors.New("master key cannot be empty")
	}

	file, err := parser.ParseBytes(content, parser.ParseComments)
	if err != nil {
		return nil, 0, fmt.Errorf("parse yaml: %w", err)
	}

	count := 0
	visitor := &yamlNodeVisitor{
		visit: func(node ast.Node) error {
			mv, ok := node.(*ast.MappingValueNode)
			if !ok || !isPasswordKeyNode(mv.Key) {
				return nil
			}

			val := extractNodeValue(mv.Value)
			if !IsEncrypted(val) {
				return nil
			}

			plain, err := DecryptPassword(val, masterKey)
			if err != nil {
				return err
			}

			var pos *token.Position
			if tk := mv.Value.GetToken(); tk != nil {
				pos = tk.Position
			}
			newTk := token.DoubleQuote(plain, fmt.Sprintf("%q", plain), pos)
			mv.Value = ast.String(newTk)
			count++
			return nil
		},
	}

	for _, doc := range file.Docs {
		ast.Walk(visitor, doc)
		if visitor.err != nil {
			return nil, 0, visitor.err
		}
	}

	return []byte(file.String()), count, nil
}

func findTargetConfigFile(c *cli.Context) (string, error) {
	if specified := c.String("file"); specified != "" {
		p := parsePath(specified)
		if _, err := os.Stat(p); err != nil {
			return "", err
		}
		return p, nil
	}

	filenames := configFileList(configFilenames...)
	for _, filename := range filenames {
		p := parsePath(filename)
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return "", errors.New("no config file found")
}

// writeFileAtomic 以原子方式写入文件（临时文件 + rename），并设置目标权限。
func writeFileAtomic(targetFile string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(targetFile)
	tempFile, err := os.CreateTemp(dir, ".sshs-config-*.tmp")
	if err != nil {
		return err
	}
	tempName := tempFile.Name()
	defer os.Remove(tempName)

	if _, err := tempFile.Write(data); err != nil {
		tempFile.Close()
		return err
	}
	if err := tempFile.Chmod(mode); err != nil {
		tempFile.Close()
		return err
	}
	if err := tempFile.Close(); err != nil {
		return err
	}

	return os.Rename(tempName, targetFile)
}

// AutoEncryptAction 是在所有命令执行完毕后的 AfterFunc 钩子中调用的自动加密函数。
// 如果配置文件中存在未加密的明文密码，将自动使用持久化后端（系统钥匙串或主密码文件）中的主密码完成加密存盘；
// 若无明文密码或未配置主密码，则静默安全返回，不影响命令正常输出与脚本管道。
// 注意：自动加密只使用持久化主密码，忽略 SSHS_MASTER_KEY 环境变量，避免临时注入的主密码把配置
// 加密成其他环境无法解密的内容。
func AutoEncryptAction(c *cli.Context) error {
	cmd := ""
	if c.Command != nil {
		cmd = c.Command.Name
	}
	if cmd == "" {
		cmd = c.Args().First()
	}

	if (cmd == "master-key" || cmd == "keyring") && c.NArg() > 1 {
		sub := c.Args().Get(1)
		if sub == "del" || sub == "delete" || sub == "remove" {
			return nil
		}
	}

	if cmd == "dec" || cmd == "decrypt" {
		return nil
	}

	configPath, err := findTargetConfigFile(c)
	if err != nil {
		return nil
	}

	masterKey, _ := loadPersistedMasterKey()
	if masterKey == "" {
		return nil
	}

	raw, err := os.ReadFile(configPath)
	if err != nil {
		return nil
	}

	info, err := os.Stat(configPath)
	if err != nil {
		return nil
	}

	newContent, count, err := EncryptPasswordInYAML(raw, masterKey)
	if err != nil || count == 0 {
		return nil
	}

	if err := writeFileAtomic(configPath, newContent, info.Mode()); err != nil {
		return err
	}

	fmt.Printf("Successfully encrypted %d plaintext password(s) in %s\n", count, configPath)
	return nil
}

// MasterKeyAction 管理主密码：set / delete / status。
// 主密码优先写入系统钥匙串；钥匙串不可用时（如无 Secret Service 的 Linux 服务器）落盘到 0600 文件。
func MasterKeyAction(c *cli.Context) error {
	action := c.Args().First()
	out := c.App.Writer
	if out == nil {
		out = os.Stdout
	}

	switch action {
	case "set":
		key, err := readMasterKeyInput(c)
		if err != nil {
			return cli.Exit(err.Error(), 1)
		}
		source, location, err := SaveMasterKey(key)
		if err != nil {
			return cli.Exit(fmt.Sprintf("save master key: %v", err), 1)
		}
		if source == masterKeySourceFile {
			fmt.Fprintf(out, "Master key saved to file %s (mode 0600).\n", location)
		} else {
			fmt.Fprintln(out, "Master key saved to system keyring.")
		}
		return nil

	case "del", "delete", "remove":
		if err := DeleteMasterKey(); err != nil {
			return cli.Exit(fmt.Sprintf("delete master key: %v", err), 1)
		}
		fmt.Fprintln(out, "Master key removed from system keyring and master key file.")
		return nil

	case "status", "":
		_, source := LoadMasterKey()
		switch source {
		case masterKeySourceEnv:
			fmt.Fprintf(out, "Status: Master key is configured via %s environment variable.\n", masterKeyEnv)
		case masterKeySourceKeyring:
			fmt.Fprintln(out, "Status: Master key is configured in system keyring.")
		case masterKeySourceFile:
			path, _ := MasterKeyFilePath()
			fmt.Fprintf(out, "Status: Master key is configured in file %s.\n", path)
		default:
			masterKeyStatusHint(out)
		}
		return nil

	default:
		return cli.Exit(fmt.Sprintf("unknown action %q, usage: sshs master-key [status|set|delete]", action), 1)
	}
}

// masterKeyStatusHint 在未配置主密码时输出状态，并指出已存在但不可用的主密码文件原因（如权限过宽）。
func masterKeyStatusHint(out io.Writer) {
	if _, err := readMasterKeyFile(); err != nil {
		path, _ := MasterKeyFilePath()
		fmt.Fprintf(out, "Status: Master key file %s exists but is unusable: %v\n", path, err)
		return
	}
	fmt.Fprintln(out, "Status: Master key is NOT configured.")
}

// readMasterKeyInput 依次从参数、stdin 管道、交互终端读取新主密码。
// 参数方式会把主密码暴露在 shell history 与进程列表中，仅为兼容保留；推荐使用管道或交互输入。
func readMasterKeyInput(c *cli.Context) (string, error) {
	if c.NArg() > 1 {
		key := strings.TrimSpace(c.Args().Get(1))
		if key == "" {
			return "", errors.New("master password cannot be empty")
		}
		return key, nil
	}

	if key, piped, err := readMasterKeyFromStdin(); err != nil {
		return "", err
	} else if piped {
		return key, nil
	}

	stdinFd := int(syscall.Stdin)
	if !stdinTerminalCheck(stdinFd) {
		return "", errors.New("interactive terminal required to set master key (or pipe the password to stdin)")
	}
	return readConfirmedPassword(stdinFd)
}

