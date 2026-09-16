package main

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"sort"
	"strings"

	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/ssh"
)

type doctorIssue struct {
	Message string
}

func DoctorAction(c *cli.Context) error {
	cfg, configPath, err := loadConfigFile(configFileList(configFilenames...)...)
	if err != nil {
		return cli.Exit(fmt.Sprintf("config: %v", err), 1)
	}

	writer := doctorWriter(c)
	fmt.Fprintf(writer, "config file: %s\n", configPath)
	issues := checkDoctorIssues(cfg)
	if len(issues) == 0 {
		fmt.Fprintln(writer, "status: ok")
		return nil
	}

	fmt.Fprintln(writer, "status: issue found")
	for _, issue := range issues {
		fmt.Fprintf(writer, "- %s\n", issue.Message)
	}
	return cli.Exit("doctor found issues", 1)
}

func doctorWriter(c *cli.Context) io.Writer {
	if c == nil || c.App == nil || c.App.Writer == nil {
		return os.Stdout
	}
	return c.App.Writer
}

func checkDoctorIssues(cfg []Config) []doctorIssue {
	flatHosts := filter_unfolding(cfg, "")
	var issues []doctorIssue

	// 1. 重复远程主机地址检测
	issues = append(issues, checkDuplicateHosts(flatHosts)...)

	// 2. 主机静态规范与凭据健康检查
	for _, h := range flatHosts {
		name := strings.TrimPrefix(h.Name, "/")

		// 端口合法性校验
		if issue := checkPort(name, h.Port); issue != nil {
			issues = append(issues, *issue)
		}

		// 私钥文件有效性与权限校验
		if issue := checkKeyPath(name, h.KeyPath, h.Passphrase); issue != nil {
			issues = append(issues, *issue)
		}

		// 密码密文解密校验
		if issue := checkEncryptedPassword(name, h.Password); issue != nil {
			issues = append(issues, *issue)
		}

		// 跳板机链路校验（循环依赖与跳板机凭据）
		if h.Jumper != nil {
			visited := make(map[string]bool)
			if h.Host != "" {
				visited[h.RemoteAddr()] = true
			}
			issues = append(issues, checkJumperChain(name, h.Jumper, visited)...)
		}
	}

	return issues
}

func checkDuplicateHosts(flatHosts []Config) []doctorIssue {
	hosts := make(map[string][]string)
	for _, h := range flatHosts {
		if h.Host == "" {
			continue
		}
		name := strings.TrimPrefix(h.Name, "/")
		remoteAddr := h.RemoteAddr()
		hosts[remoteAddr] = append(hosts[remoteAddr], name)
	}

	var issues []doctorIssue
	remoteAddrs := make([]string, 0, len(hosts))
	for remoteAddr := range hosts {
		remoteAddrs = append(remoteAddrs, remoteAddr)
	}
	sort.Strings(remoteAddrs)
	for _, remoteAddr := range remoteAddrs {
		names := hosts[remoteAddr]
		if len(names) <= 1 {
			continue
		}
		issues = append(issues, doctorIssue{
			Message: fmt.Sprintf("duplicate host %s in %v", remoteAddr, names),
		})
	}
	return issues
}

func checkPort(name string, port int) *doctorIssue {
	if port != 0 && (port < 1 || port > 65535) {
		return &doctorIssue{
			Message: fmt.Sprintf("host %s: invalid port %d (must be between 1 and 65535)", name, port),
		}
	}
	return nil
}

func checkKeyPath(name, rawPath, passphrase string) *doctorIssue {
	if rawPath == "" {
		return nil
	}
	expanded := parsePath(rawPath)
	info, err := os.Stat(expanded)
	if err != nil {
		if os.IsNotExist(err) {
			return &doctorIssue{
				Message: fmt.Sprintf("host %s: private key file %q not found", name, rawPath),
			}
		}
		return &doctorIssue{
			Message: fmt.Sprintf("host %s: private key file %q inaccessible: %v", name, rawPath, err),
		}
	}
	if info.IsDir() {
		return &doctorIssue{
			Message: fmt.Sprintf("host %s: private key path %q is a directory", name, rawPath),
		}
	}

	// 权限安全校验（Unix 系统）：私钥不可对 group 或 others 开放权限 (推荐 0600 或 0400)
	if runtime.GOOS != "windows" {
		perm := info.Mode().Perm()
		if perm&0077 != 0 {
			return &doctorIssue{
				Message: fmt.Sprintf("host %s: private key file %q permissions %#o too open (expected 0600 or 0400)", name, rawPath, perm),
			}
		}
	}

	// 解析校验：验证私钥内容格式及密码短语
	keyBytes, err := os.ReadFile(expanded)
	if err != nil {
		return &doctorIssue{
			Message: fmt.Sprintf("host %s: failed to read private key %q: %v", name, rawPath, err),
		}
	}
	var parseErr error
	if passphrase != "" {
		_, parseErr = ssh.ParsePrivateKeyWithPassphrase(keyBytes, []byte(passphrase))
	} else {
		_, parseErr = ssh.ParsePrivateKey(keyBytes)
		if _, ok := parseErr.(*ssh.PassphraseMissingError); ok {
			return &doctorIssue{
				Message: fmt.Sprintf("host %s: private key file %q is encrypted but passphrase not configured", name, rawPath),
			}
		}
	}
	if parseErr != nil {
		return &doctorIssue{
			Message: fmt.Sprintf("host %s: failed to parse private key %q: %v", name, rawPath, parseErr),
		}
	}
	return nil
}

func checkEncryptedPassword(name, password string) *doctorIssue {
	if !IsEncrypted(password) {
		return nil
	}
	masterKey := getCachedMasterKey()
	if masterKey == "" {
		ringKey, err := activeKeyring.Get(keyringService, keyringMasterKey)
		if err != nil || ringKey == "" {
			return &doctorIssue{
				Message: fmt.Sprintf("host %s: encrypted password present but master key not found in keyring", name),
			}
		}
		masterKey = ringKey
	}
	_, err := DecryptPassword(password, masterKey)
	if err != nil {
		return &doctorIssue{
			Message: fmt.Sprintf("host %s: failed to decrypt password: %v", name, err),
		}
	}
	return nil
}

func checkJumperChain(hostName string, jumper *Config, visited map[string]bool) []doctorIssue {
	var issues []doctorIssue
	curr := jumper
	depth := 0
	const maxJumperDepth = 10

	for curr != nil {
		depth++
		if depth > maxJumperDepth {
			issues = append(issues, doctorIssue{
				Message: fmt.Sprintf("host %s: jumper chain exceeds max depth (%d), possible cycle", hostName, maxJumperDepth),
			})
			break
		}

		if curr.Host != "" {
			jumperAddr := curr.RemoteAddr()
			if visited[jumperAddr] {
				issues = append(issues, doctorIssue{
					Message: fmt.Sprintf("host %s: circular jumper reference detected at %s", hostName, jumperAddr),
				})
				break
			}
			visited[jumperAddr] = true
		}

		jName := fmt.Sprintf("%s (jumper %s)", hostName, curr.Host)
		if issue := checkPort(jName, curr.Port); issue != nil {
			issues = append(issues, *issue)
		}
		if issue := checkKeyPath(jName, curr.KeyPath, curr.Passphrase); issue != nil {
			issues = append(issues, *issue)
		}
		if issue := checkEncryptedPassword(jName, curr.Password); issue != nil {
			issues = append(issues, *issue)
		}

		curr = curr.Jumper
	}
	return issues
}
