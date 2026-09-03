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
	"gopkg.in/yaml.v2"
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

// PasswordValue 返回生效的密码：配置中写明则用配置值，否则回退环境变量 SSHS_PASSWORD。
func (c *Config) PasswordValue() string {
	if c.Password != "" {
		return c.Password
	}
	return os.Getenv("SSHS_PASSWORD")
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

func (c *Config) AuthMethod() []ssh.AuthMethod {
	var auth []ssh.AuthMethod
	if c.KeyPath != "" {
		b, err := os.ReadFile(parsePath(c.KeyPath))
		if err != nil {
			log.Println(err)
		} else {
			auth = append(auth, secureshell.KeyAuth(b, c.Passphrase))
		}
	}
	if password := c.PasswordValue(); password != "" {
		auth = append(auth, secureshell.PasswordAuth(password))
	}
	return auth
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
