package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"sort"

	"github.com/lixiangzhong/sshs/pkg/secureshell"
	"github.com/urfave/cli/v2"

	"golang.org/x/crypto/ssh"

	"github.com/goccy/go-yaml"
)

// configFilenames 是 sshs 依次查找的配置文件候选列表。
var configFilenames = []string{".sshs.yaml", "sshs.yaml", ".sshw.yaml", "sshw.yaml"}

// loadSortedHosts 解析上下文中的主机关键词、加载配置文件、扁平化过滤主机，并按主机名称排序。
func loadSortedHosts(c *cli.Context) ([]Config, error) {
	cfg, err := loadConfig(configFileList(configFilenames...)...)
	if err != nil {
		return nil, err
	}
	keywords, err := hostKeywords(c)
	if err != nil {
		return nil, cli.Exit(err, 1)
	}
	hosts := filter_unfolding(cfg, "", keywords...)
	if len(hosts) == 0 {
		return nil, cli.Exit("no host matched", 1)
	}
	sort.SliceStable(hosts, func(i, j int) bool {
		return hosts[i].Name < hosts[j].Name
	})
	return hosts, nil
}

type Config struct {
	Name       string   `yaml:"name"`
	Host       string   `yaml:"host"`
	User       string   `yaml:"user"`
	Port       int      `yaml:"port"`
	KeyPath    string   `yaml:"keypath"`
	Passphrase string   `yaml:"passphrase"`
	Password   string   `yaml:"password"`
	Children   []Config `yaml:"children"`
	Jumper     *Config  `yaml:"jumper"`
	//CMD        []string `yaml:"cmd"`
}

func (c *Config) Username() string {
	if c.User == "" {
		return "root"
	}
	return c.User
}

// HasPassword 判断该主机是否配置了密码（支持明文密码、密文密码或环境变量回退）。
// 该方法仅做配置存在性探测，绝对不触发解密或终端输入交互。
func (c *Config) HasPassword() bool {
	if c.Password != "" {
		return true
	}
	return os.Getenv("SSHS_PASSWORD") != ""
}

// PasswordValue 返回生效的密码及可能发生的解密错误：
// 1. 若配置中包含 ENC(v1:...) 密文，则尝试使用 Master Key 解密；若解密失败直接返回错误（快速失败）；
// 2. 若配置中为普通明文，直接返回；
// 3. 否则回退环境变量 SSHS_PASSWORD。
func (c *Config) PasswordValue() (string, error) {
	raw := c.Password
	if raw == "" {
		return os.Getenv("SSHS_PASSWORD"), nil
	}
	if !IsEncrypted(raw) {
		return raw, nil
	}
	masterKey, err := ResolveMasterKey(false)
	if err != nil {
		return "", fmt.Errorf("failed to resolve master key: %w", err)
	}
	plain, err := DecryptPassword(raw, masterKey)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt password for host %q: %w", c.Name, err)
	}
	return plain, nil
}

func (c *Config) RemotePort() int {
	if c.Port <= 0 {
		return 22
	}
	return c.Port
}

func (c *Config) RemoteAddr() string {
	return net.JoinHostPort(c.Host, strconv.Itoa(c.RemotePort()))
}

func (c *Config) AuthMethod() ([]ssh.AuthMethod, error) {
	var auth []ssh.AuthMethod
	if c.KeyPath != "" {
		b, err := os.ReadFile(parsePath(c.KeyPath))
		if err != nil {
			log.Println(err)
		} else {
			auth = append(auth, secureshell.KeyAuth(b, c.Passphrase))
		}
	}
	password, err := c.PasswordValue()
	if err != nil {
		return nil, err
	}
	if password != "" {
		auth = append(auth, secureshell.PasswordAuth(password))
	}
	return auth, nil
}

func configFileList(names ...string) []string {
	var filenames []string
	filenames = append(filenames, names...)
	for _, name := range names {
		filenames = append(filenames, filepath.Join(homeDir(), name))
	}
	return filenames
}

func loadConfig(filenames ...string) ([]Config, error) {
	cfg, _, err := loadConfigFile(filenames...)
	return cfg, err
}

func loadConfigFile(filenames ...string) ([]Config, string, error) {
	var b []byte
	var err error
	var cfg []Config
	for _, filename := range filenames {
		configPath := parsePath(filename)
		b, err = os.ReadFile(configPath)
		if err != nil {
			continue
		}
		err = yaml.Unmarshal(b, &cfg)
		if err != nil {
			return nil, configPath, fmt.Errorf("%v: %v", configPath, err)
		}
		return cfg, configPath, nil
	}
	return cfg, "", fmt.Errorf("no config file found (searched: %s)", strings.Join(filenames, ", "))
}

func homeDir() string {
	s, err := os.UserHomeDir()
	if err != nil {
		log.Println(err)
	}
	return s
}

func parsePath(path string) string {
	if len(path) == 0 {
		return path
	}
	if path[0] == '~' {
		return filepath.Join(homeDir(), strings.Replace(path, "~", "", 1))
	}
	return path
}
