package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/lixiangzhong/sshs/pkg/secureshell"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/ssh"
)

const (
	inspectTimeoutDefault     = 10 * time.Second
	inspectConcurrencyDefault = 10
)

// inspectScript 在远程主机上执行，输出 key=value 行（disk= 行可重复，格式 mount|size|used|pct%）。
// 脚本按 POSIX sh 编写，单条命令失败不影响整体，最终 exit 0 保证 session.Output 不报退出码错误。
const inspectScript = `
if [ ! -d /proc ]; then
  echo "platform=unsupported"
  exit 0
fi
echo "hostname=$(hostname 2>/dev/null)"
echo "os=$(awk -F= '/^PRETTY_NAME=/{gsub(/["\r]/,"",$2);print $2}' /etc/os-release 2>/dev/null)"
echo "kernel=$(uname -r 2>/dev/null)"
echo "load1=$(awk '{print $1}' /proc/loadavg 2>/dev/null)"
echo "load5=$(awk '{print $2}' /proc/loadavg 2>/dev/null)"
echo "load15=$(awk '{print $3}' /proc/loadavg 2>/dev/null)"
echo "cpu_cores=$(nproc 2>/dev/null)"
s1=$(grep '^cpu ' /proc/stat 2>/dev/null)
sleep 0.2
s2=$(grep '^cpu ' /proc/stat 2>/dev/null)
echo "cpu_pct=$(awk -v a="$s1" -v b="$s2" 'BEGIN{split(a,x);split(b,y);idle=y[5]-x[5];total=(y[2]+y[3]+y[4]+y[5]+y[6]+y[7]+y[8])-(x[2]+x[3]+x[4]+x[5]+x[6]+x[7]+x[8]);if(total>0)printf "%.1f",100*(1-idle/total)}')"
mem_total=$(awk '/^MemTotal:/{print int($2/1024)}' /proc/meminfo 2>/dev/null)
mem_avail=$(awk '/^MemAvailable:/{print int($2/1024)}' /proc/meminfo 2>/dev/null)
echo "mem_total=${mem_total}MB"
echo "mem_avail=${mem_avail}MB"
echo "mem_pct=$(awk -v t="$mem_total" -v a="$mem_avail" 'BEGIN{if(t>0)printf "%.1f",100*(1-a/t)}')"
df -P -h 2>/dev/null | awk 'NR>1 && $6 ~ /^\// {print "disk=" $6 "|" $2 "|" $3 "|" $5}'
echo "time_epoch=$(date +%s 2>/dev/null)"
exit 0
`

// inspectResult 是单台主机的巡检结果。
type inspectResult struct {
	Name  string            `json:"name"`
	Host  string            `json:"host"`
	Data  map[string]string `json:"data,omitempty"`
	Disks []string          `json:"disks,omitempty"`
	Error string            `json:"error,omitempty"`
}

func InspectAction(c *cli.Context) error {
	cfg, err := loadConfig(configFileList(configFilenames...)...)
	if err != nil {
		return err
	}
	keywords, err := hostKeywords(c)
	if err != nil {
		return cli.Exit(err, 1)
	}
	hosts := filter_unfolding(cfg, "", keywords...)
	if len(hosts) == 0 {
		return cli.Exit("no host matched", 1)
	}
	sort.SliceStable(hosts, func(i, j int) bool {
		return hosts[i].Name < hosts[j].Name
	})

	timeout := inspectTimeoutDefault
	if c.IsSet("timeout") {
		timeout = c.Duration("timeout")
	}
	concurrency := inspectConcurrencyDefault
	if c.IsSet("concurrency") {
		concurrency = c.Int("concurrency")
	}

	results := runInspect(c.Context, hosts, timeout, concurrency)

	if c.Bool("json") {
		b, err := json.MarshalIndent(results, "", "  ")
		if err != nil {
			return cli.Exit(err, 1)
		}
		fmt.Fprintln(os.Stdout, string(b))
		return nil
	}
	printInspectTables(os.Stdout, results)
	return nil
}

// runInspect 并发巡检所有主机，结果按下标归位以保持输出顺序稳定。
func runInspect(ctx context.Context, hosts []Config, timeout time.Duration, concurrency int) []inspectResult {
	results := make([]inspectResult, len(hosts))
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for i, h := range hosts {
		wg.Add(1)
		go func(index int, h Config) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[index] = inspectHost(ctx, h, timeout)
		}(i, h)
	}
	wg.Wait()
	return results
}

// inspectHost 拨号并采集单台主机。拨号阶段与命令执行阶段均受 ctx 超时约束；
// 超时通过关闭连接中断阻塞的 session，避免 goroutine 泄漏。
func inspectHost(parent context.Context, c Config, timeout time.Duration) inspectResult {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	result := inspectResult{Name: c.Name, Host: c.RemoteAddr()}

	type dialResult struct {
		client *ssh.Client
		err    error
	}
	dialCh := make(chan dialResult, 1)
	go func() {
		client, err := dialThroughJumpers(c, secureshell.DialNonInteractive)
		dialCh <- dialResult{client, err}
	}()
	var client *ssh.Client
	select {
	case dr := <-dialCh:
		if dr.err != nil {
			result.Error = dr.err.Error()
			return result
		}
		client = dr.client
	case <-ctx.Done():
		result.Error = "timeout"
		return result
	}
	defer client.Close()

	go func() {
		<-ctx.Done()
		client.Close()
	}()

	session, err := client.NewSession()
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer session.Close()

	out, err := session.Output(inspectScript)
	if err != nil {
		if ctx.Err() != nil {
			result.Error = "timeout"
		} else {
			result.Error = err.Error()
		}
		return result
	}
	result.Data, result.Disks = parseInspectOutput(string(out))
	return result
}

// parseInspectOutput 解析 key=value 行；disk= 行单独收集为磁盘明细。
func parseInspectOutput(out string) (map[string]string, []string) {
	data := make(map[string]string)
	var disks []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		kv := strings.SplitN(line, "=", 2)
		if len(kv) != 2 {
			continue
		}
		if kv[0] == "disk" {
			disks = append(disks, kv[1])
			continue
		}
		data[kv[0]] = kv[1]
	}
	return data, disks
}

func printInspectTables(w io.Writer, results []inspectResult) {
	style := table.Style{
		Box:     table.StyleBoxDefault,
		Options: table.OptionsNoBordersAndSeparators,
	}
	summary := table.NewWriter()
	summary.SetStyle(style)
	summary.AppendHeader(table.Row{"NAME", "LOAD(1/5/15)", "CPU%", "MEM%", "DISK%", "KERNEL", "OS", "NTP"})
	detail := table.NewWriter()
	detail.SetStyle(style)
	detail.AppendHeader(table.Row{"NAME", "MOUNT", "SIZE", "USED", "USE%"})
	for _, r := range results {
		name := inspectDisplayName(r)
		if r.Error != "" {
			summary.AppendRow(table.Row{name, "", "", "", "", "", "ERROR: " + r.Error, ""})
			continue
		}
		osName := r.Data["os"]
		if r.Data["platform"] == "unsupported" {
			osName = "unsupported"
		}
		summary.AppendRow(table.Row{
			name,
			strings.Join([]string{r.Data["load1"], r.Data["load5"], r.Data["load15"]}, " "),
			r.Data["cpu_pct"],
			r.Data["mem_pct"],
			maxDiskPct(r.Disks),
			r.Data["kernel"],
			osName,
			ntpOffset(r.Data["time_epoch"]),
		})
		for _, d := range r.Disks {
			if parts := strings.Split(d, "|"); len(parts) == 4 {
				detail.AppendRow(table.Row{name, parts[0], parts[1], parts[2], parts[3]})
			}
		}
	}
	fmt.Fprintln(w, summary.Render())
	if detail.Length() > 1 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, detail.Render())
	}
}

// inspectDisplayName 拼接待巡检主机名与其地址，用于区分同名主机。
func inspectDisplayName(r inspectResult) string {
	if r.Host == "" {
		return r.Name
	}
	return fmt.Sprintf("%s(%s)", r.Name, r.Host)
}

// maxDiskPct 取磁盘明细中最大的挂载点使用率，无数据返回 "-"。
func maxDiskPct(disks []string) string {
	maxValue := 0.0
	maxStr := "-"
	for _, d := range disks {
		parts := strings.Split(d, "|")
		if len(parts) != 4 {
			continue
		}
		value, err := strconv.ParseFloat(strings.TrimSuffix(parts[3], "%"), 64)
		if err != nil {
			continue
		}
		if value > maxValue {
			maxValue = value
			maxStr = parts[3]
		}
	}
	return maxStr
}

// ntpOffset 对比远程与本地时间，返回秒级偏移（如 +2s / -45s）。
func ntpOffset(epoch string) string {
	if epoch == "" {
		return "-"
	}
	remote, err := strconv.ParseInt(epoch, 10, 64)
	if err != nil {
		return "-"
	}
	offset := remote - time.Now().Unix()
	if offset > 0 {
		return fmt.Sprintf("+%ds", offset)
	}
	return fmt.Sprintf("%ds", offset)
}
