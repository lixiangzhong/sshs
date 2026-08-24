package main

import (
	"bytes"
	"context"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestInspectHostTimeout(t *testing.T) {
	// 192.0.2.1 是保留文档地址（TEST-NET-1），通常不可达，用于触发拨号阻塞/失败。
	cfg := Config{Name: "test", Host: "192.0.2.1", Port: 22, User: "root"}
	start := time.Now()
	result := inspectHost(context.Background(), cfg, 200*time.Millisecond)
	elapsed := time.Since(start)

	if result.Error == "" {
		t.Fatalf("expected error for unreachable host, got success: %+v", result)
	}
	if elapsed > 3*time.Second {
		t.Fatalf("inspectHost did not respect timeout, took %v", elapsed)
	}
}

func TestInspectHostTimeoutShort(t *testing.T) {
	cfg := Config{Name: "test", Host: "192.0.2.1", Port: 22, User: "root"}
	result := inspectHost(context.Background(), cfg, time.Millisecond)
	if result.Error != "timeout" {
		t.Fatalf("expected timeout error, got %q", result.Error)
	}
}

func TestParseInspectOutput(t *testing.T) {
	out := "hostname=web-01\nos=Ubuntu 24.04\nload1=0.1\nload5=0.2\nload15=0.3\n" +
		"cpu_model=Intel(R) Xeon(R) Platinum 8269CY CPU @ 2.50GHz\ncpu_cores=4\ncpu_threads=8\n" +
		"uptime_sec=2764800\ntcp_estab=128\n" +
		"mem_total=16384MB\nmem_avail=12288MB\nmem_used=4096MB\nmem_pct=25.0\n" +
		"disk=/ 20G 5G 25%\ndisk=/data 80G 60G 75%\ndisk=/var/lib/docker/overlay2/abc 100G 20G 20%\ndisk=overlay2/2d31c2a45870decae8363efc9513603a28c11713ff8f87b621d32d0889ce744a/merged 100G 20G 20%\ndisk=/var/lib/docker/containers/123/mounts/shm 64M 0 0%\ntime_epoch=1700000000\n"
	data, disks := parseInspectOutput(out)

	if data["hostname"] != "web-01" {
		t.Errorf("hostname = %q, want web-01", data["hostname"])
	}
	// os 值含空格，应保留整段
	if data["os"] != "Ubuntu 24.04" {
		t.Errorf("os = %q, want %q", data["os"], "Ubuntu 24.04")
	}
	if data["cpu_model"] != "Intel(R) Xeon(R) Platinum 8269CY CPU @ 2.50GHz" {
		t.Errorf("cpu_model = %q", data["cpu_model"])
	}
	if data["cpu_cores"] != "4" || data["cpu_threads"] != "8" {
		t.Errorf("cpu cores/threads = %s/%s, want 4/8", data["cpu_cores"], data["cpu_threads"])
	}
	if data["uptime_sec"] != "2764800" || data["tcp_estab"] != "128" {
		t.Errorf("uptime/tcp = %s/%s", data["uptime_sec"], data["tcp_estab"])
	}
	if data["mem_total"] != "16384MB" {
		t.Errorf("mem_total = %q, want 16384MB", data["mem_total"])
	}
	if len(disks) != 2 {
		t.Errorf("disks = %v, want 2 entries (all docker overlay/containers should be filtered)", disks)
	}
}

func TestFormatCPUSpec(t *testing.T) {
	d1 := map[string]string{
		"cpu_cores":   "4",
		"cpu_threads": "8",
		"cpu_pct":     "13.0",
	}
	if got := formatCPUSpec(d1); got != "4C8T(13.0%)" {
		t.Errorf("formatCPUSpec = %q, want 4C8T(13.0%%)", got)
	}

	d2 := map[string]string{
		"cpu_cores":   "2",
		"cpu_threads": "2",
		"cpu_pct":     "5.0",
	}
	if got := formatCPUSpec(d2); got != "2C(5.0%)" {
		t.Errorf("formatCPUSpec = %q, want 2C(5.0%%)", got)
	}

	// 多物理 CPU (双路 16 核无超线程)
	d3 := map[string]string{
		"cpu_sockets":          "2",
		"cpu_cores_per_socket": "16",
		"cpu_cores":            "32",
		"cpu_threads":          "32",
		"cpu_pct":              "15.0",
	}
	if got := formatCPUSpec(d3); got != "2*16C(15.0%)" {
		t.Errorf("formatCPUSpec = %q, want 2*16C(15.0%%)", got)
	}

	// 多物理 CPU (双路 16 核 32 线程带超线程)
	d4 := map[string]string{
		"cpu_sockets":          "2",
		"cpu_cores_per_socket": "16",
		"cpu_cores":            "32",
		"cpu_threads":          "64",
		"cpu_pct":              "20.0",
	}
	if got := formatCPUSpec(d4); got != "2*16C32T(20.0%)" {
		t.Errorf("formatCPUSpec = %q, want 2*16C32T(20.0%%)", got)
	}

	if got := formatCPUSpec(nil); got != "-" {
		t.Errorf("formatCPUSpec(nil) = %q, want -", got)
	}
}

func TestFormatMemSpec(t *testing.T) {
	d1 := map[string]string{
		"mem_total": "16384MB",
		"mem_pct":   "50.0",
	}
	if got := formatMemSpec(d1); got != "16G(50.0%)" {
		t.Errorf("formatMemSpec = %q, want 16G(50.0%%)", got)
	}

	d2 := map[string]string{
		"mem_total": "7980MB",
		"mem_pct":   "57.5",
	}
	if got := formatMemSpec(d2); got != "7.8G(57.5%)" {
		t.Errorf("formatMemSpec = %q, want 7.8G(57.5%%)", got)
	}

	d3 := map[string]string{
		"mem_total": "512MB",
		"mem_pct":   "50.0",
	}
	if got := formatMemSpec(d3); got != "512M(50.0%)" {
		t.Errorf("formatMemSpec = %q, want 512M(50.0%%)", got)
	}

	if got := formatMemSpec(nil); got != "-" {
		t.Errorf("formatMemSpec(nil) = %q, want -", got)
	}
}

func TestNtpOffset(t *testing.T) {
	if got := ntpOffset(""); got != "-" {
		t.Errorf("ntpOffset(empty) = %q, want -", got)
	}
	if got := ntpOffset("not-a-number"); got != "-" {
		t.Errorf("ntpOffset(bad) = %q, want -", got)
	}
	now := time.Now().Unix()
	if got := ntpOffset(strconv.FormatInt(now, 10)); got != "0s" {
		t.Errorf("ntpOffset(now) = %q, want 0s", got)
	}
	if got := ntpOffset(strconv.FormatInt(now+5, 10)); got != "+5s" {
		t.Errorf("ntpOffset(now+5) = %q, want +5s", got)
	}
	if got := ntpOffset("1700000005", 1700000000); got != "+5s" {
		t.Errorf("ntpOffset with localTime = %q, want +5s", got)
	}
	if got := ntpOffset("1700000000", 1700000005); got != "-5s" {
		t.Errorf("ntpOffset with localTime = %q, want -5s", got)
	}
}

func TestFormatTimeSpec(t *testing.T) {
	d1 := map[string]string{
		"ntp_offset": "0s",
		"timezone":   "Asia/Shanghai",
		"tz_offset":  "+0800",
	}
	if got := formatTimeSpec(d1); got != "0s (Asia/Shanghai +08:00)" {
		t.Errorf("formatTimeSpec = %q", got)
	}

	d2 := map[string]string{
		"ntp_offset": "+1s",
		"timezone":   "Etc/UTC",
		"tz_offset":  "+0000",
	}
	if got := formatTimeSpec(d2); got != "+1s (UTC +00:00)" {
		t.Errorf("formatTimeSpec = %q", got)
	}

	if got := formatTimeSpec(nil); got != "-" {
		t.Errorf("formatTimeSpec(nil) = %q, want -", got)
	}
}

func TestFormatTZOffset(t *testing.T) {
	if got := formatTZOffset("+0800"); got != "+08:00" {
		t.Errorf("formatTZOffset(+0800) = %q, want +08:00", got)
	}
	if got := formatTZOffset("-0500"); got != "-05:00" {
		t.Errorf("formatTZOffset(-0500) = %q, want -05:00", got)
	}
	if got := formatTZOffset("UTC"); got != "UTC" {
		t.Errorf("formatTZOffset(UTC) = %q, want UTC", got)
	}
}

func TestFormatTCP(t *testing.T) {
	if got := formatTCP(map[string]string{"tcp_estab": "128"}); got != "128" {
		t.Errorf("formatTCP = %q, want 128", got)
	}
	if got := formatTCP(map[string]string{"tcp_estab": "12500"}); got != "12.5k" {
		t.Errorf("formatTCP = %q, want 12.5k", got)
	}
	if got := formatTCP(nil); got != "-" {
		t.Errorf("formatTCP(nil) = %q, want -", got)
	}
}

func TestFormatOSSpec(t *testing.T) {
	d1 := map[string]string{
		"os":          "Ubuntu 24.04",
		"uptime_sec":  "2764800",
	}
	if got := formatOSSpec(d1); got != "Ubuntu 24.04 (32d)" {
		t.Errorf("formatOSSpec = %q, want Ubuntu 24.04 (32d)", got)
	}
	if got := formatOSSpec(nil); got != "-" {
		t.Errorf("formatOSSpec(nil) = %q, want -", got)
	}
}

func TestFormatUptime(t *testing.T) {
	if got := formatUptime("86400"); got != "1d" {
		t.Errorf("formatUptime(86400) = %q, want 1d", got)
	}
	if got := formatUptime("3600"); got != "1h" {
		t.Errorf("formatUptime(3600) = %q, want 1h", got)
	}
	if got := formatUptime("120"); got != "2m" {
		t.Errorf("formatUptime(120) = %q, want 2m", got)
	}
	if got := formatUptime("45"); got != "45s" {
		t.Errorf("formatUptime(45) = %q, want 45s", got)
	}
	if got := formatUptime(""); got != "-" {
		t.Errorf("formatUptime(empty) = %q, want -", got)
	}
}

func TestInspectDisplayName(t *testing.T) {
	tests := []struct {
		name string
		host string
		want string
	}{
		{"web-01", "10.0.1.10:22", "web-01(10.0.1.10:22)"},
		{"web-01", "", "web-01"},
	}
	for _, tt := range tests {
		got := inspectDisplayName(inspectResult{Name: tt.name, Host: tt.host})
		if got != tt.want {
			t.Errorf("inspectDisplayName(%q, %q) = %q, want %q", tt.name, tt.host, got, tt.want)
		}
	}
}

func TestPrintInspectTablesIncludesAddr(t *testing.T) {
	results := []inspectResult{
		{Name: "/prod/web-01", Host: "10.0.1.10:22", Data: map[string]string{"load1": "0.1", "load5": "0.2", "load15": "0.3"}, Disks: []string{"/|20G|5G|25%"}},
		{Name: "/prod/web-01", Host: "10.0.2.10:22", Error: "timeout"},
	}
	var buf bytes.Buffer
	printInspectTables(&buf, results)
	out := buf.String()

	if !strings.Contains(out, "/prod/web-01(10.0.1.10:22)") {
		t.Errorf("summary missing name+addr for normal host:\n%s", out)
	}
	if !strings.Contains(out, "/prod/web-01(10.0.2.10:22)") {
		t.Errorf("summary missing name+addr for error host:\n%s", out)
	}
	if !strings.Contains(out, "ERROR: timeout") {
		t.Errorf("summary missing error detail:\n%s", out)
	}
}
