package main

import (
	"errors"
	"fmt"
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

func writeConfigFileAtomic(targetFile string, data []byte, mode os.FileMode) error {
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
// 如果配置文件中存在未加密的明文密码，将自动使用 Keyring 中的主密码完成加密存盘；
// 若无明文密码或未配置主密码，则静默安全返回，不影响命令正常输出与脚本管道。
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

	configPath, err := findTargetConfigFile(c)
	if err != nil {
		return nil
	}

	masterKey, err := GetKeyringMasterKey()
	if err != nil || masterKey == "" {
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

	if err := writeConfigFileAtomic(configPath, newContent, info.Mode()); err != nil {
		return err
	}

	fmt.Printf("Successfully encrypted %d plaintext password(s) in %s\n", count, configPath)
	return nil
}

func MasterKeyAction(c *cli.Context) error {
	action := c.Args().First()
	out := c.App.Writer
	if out == nil {
		out = os.Stdout
	}

	switch action {
	case "set":
		var key string
		if c.NArg() > 1 {
			key = c.Args().Get(1)
		} else {
			stdinFd := int(syscall.Stdin)
			if !stdinTerminalCheck(stdinFd) {
				return cli.Exit("interactive terminal required to set master key", 1)
			}
			fmt.Fprint(os.Stderr, "Enter Master Password: ")
			b1, err := terminalPasswordReader(stdinFd)
			fmt.Fprintln(os.Stderr)
			if err != nil {
				return cli.Exit(fmt.Sprintf("read master password: %v", err), 1)
			}
			fmt.Fprint(os.Stderr, "Confirm Master Password: ")
			b2, err := terminalPasswordReader(stdinFd)
			fmt.Fprintln(os.Stderr)
			if err != nil {
				return cli.Exit(fmt.Sprintf("read confirm master password: %v", err), 1)
			}
			if string(b1) != string(b2) {
				return cli.Exit("master passwords do not match", 1)
			}
			key = strings.TrimSpace(string(b1))
		}
		if err := SetKeyringMasterKey(key); err != nil {
			return cli.Exit(fmt.Sprintf("save master key to keyring: %v", err), 1)
		}
		fmt.Fprintln(out, "Master key successfully saved to system keyring.")
		return nil

	case "del", "delete", "remove":
		if err := DeleteKeyringMasterKey(); err != nil {
			return cli.Exit(fmt.Sprintf("delete master key from keyring: %v", err), 1)
		}
		fmt.Fprintln(out, "Master key removed from system keyring.")
		return nil

	case "status", "":
		key, err := GetKeyringMasterKey()
		if err == nil && key != "" {
			fmt.Fprintln(out, "Status: Master key is configured in system keyring.")
		} else {
			fmt.Fprintln(out, "Status: Master key is NOT configured in system keyring.")
		}
		return nil

	default:
		return cli.Exit(fmt.Sprintf("unknown action %q, usage: sshs master-key [status|set|delete]", action), 1)
	}
}

