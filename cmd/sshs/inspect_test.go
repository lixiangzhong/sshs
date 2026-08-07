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
		"disk=/ 20G 5G 25%\ndisk=/data 80G 60G 75%\ntime_epoch=1700000000\n"
	data, disks := parseInspectOutput(out)

	if data["hostname"] != "web-01" {
		t.Errorf("hostname = %q, want web-01", data["hostname"])
	}
	// os 值含空格，应保留整段
	if data["os"] != "Ubuntu 24.04" {
		t.Errorf("os = %q, want %q", data["os"], "Ubuntu 24.04")
	}
	if len(disks) != 2 {
		t.Errorf("disks = %v, want 2 entries", disks)
	}
}

func TestMaxDiskPct(t *testing.T) {
	if got := maxDiskPct([]string{"/|20G|5G|25%", "/data|80G|60G|75%"}); got != "75%" {
		t.Errorf("maxDiskPct = %q, want 75%%", got)
	}
	if got := maxDiskPct(nil); got != "-" {
		t.Errorf("maxDiskPct(nil) = %q, want -", got)
	}
	if got := maxDiskPct([]string{"bad"}); got != "-" {
		t.Errorf("maxDiskPct(bad) = %q, want -", got)
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
