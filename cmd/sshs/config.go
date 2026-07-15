package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/lixiangzhong/sshs/pkg/secureshell"

	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v2"
)

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
	if c.Password != "" {
		auth = append(auth, secureshell.PasswordAuth(c.Password))
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
	return cfg, "", err
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
