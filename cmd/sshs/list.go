package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/urfave/cli/v2"
)

// hostInfo 是 sshs list 的单台主机输出结构，字段与表格列一一对应。
type hostInfo struct {
	Name   string   `json:"name"`
	User   string   `json:"user"`
	Host   string   `json:"host"`
	Port   int      `json:"port"`
	Auth   []string `json:"auth"`
	Jumper []string `json:"jumper"`
	Addr   string   `json:"-"`
}

func ListAction(c *cli.Context) error {
	hosts, err := loadSortedHosts(c)
	if err != nil {
		return err
	}

	infos := make([]hostInfo, 0, len(hosts))
	for _, h := range hosts {
		infos = append(infos, toHostInfo(h))
	}

	if c.Bool("json") {
		b, err := json.MarshalIndent(infos, "", "  ")
		if err != nil {
			return cli.Exit(err, 1)
		}
		fmt.Fprintln(os.Stdout, string(b))
		return nil
	}
	printHostTable(os.Stdout, infos)
	return nil
}

// toHostInfo 只依据配置字段展开，不触发 AuthMethod（避免读取私钥文件、打日志）。
func toHostInfo(c Config) hostInfo {
	return hostInfo{
		Name:   c.Name,
		User:   c.Username(),
		Host:   c.Host,
		Port:   c.RemotePort(),
		Auth:   authMethods(c),
		Jumper: jumperChain(c),
		Addr:   c.RemoteAddr(),
	}
}

// authMethods 按配置字段列出可用认证方式，不校验密钥文件是否存在。
// 返回非 nil 空切片，保证 JSON 输出为 [] 而非 null。
func authMethods(c Config) []string {
	auth := make([]string, 0, 2)
	if c.KeyPath != "" {
		auth = append(auth, "key")
	}
	if c.Password != "" {
		auth = append(auth, "password")
	}
	return auth
}

// jumperChain 沿 Jumper 指针逐级收集跳板链展示名（Name 优先，缺省用 RemoteAddr）。
func jumperChain(c Config) []string {
	var chain []string
	for j := c.Jumper; j != nil; j = j.Jumper {
		if j.Name != "" {
			chain = append(chain, j.Name)
		} else {
			chain = append(chain, j.RemoteAddr())
		}
	}
	if chain == nil {
		chain = make([]string, 0)
	}
	return chain
}

func printHostTable(w io.Writer, infos []hostInfo) {
	t := table.NewWriter()
	t.SetStyle(table.Style{
		Box:     table.StyleBoxDefault,
		Options: table.OptionsNoBordersAndSeparators,
	})
	t.AppendHeader(table.Row{"NAME", "USER", "HOST:PORT", "AUTH", "JUMPER"})
	for _, info := range infos {
		auth := strings.Join(info.Auth, "+")
		if auth == "" {
			auth = "none"
		}
		jumper := strings.Join(info.Jumper, " -> ")
		if jumper == "" {
			jumper = "-"
		}
		t.AppendRow(table.Row{
			info.Name,
			info.User,
			info.Addr,
			auth,
			jumper,
		})
	}
	fmt.Fprintln(w, t.Render())
}
