package main

import (
	"context"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/lixiangzhong/sshs/pkg/secureshell"
	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/ssh"
)

const (
	graphTimeoutDefault  = 10 * time.Second
	graphIntervalDefault = 10 * time.Second
	graphIntervalMinimum = 2 * time.Second
)

// graphCollectScript 在远程主机上执行，采集网络连接、本机IP与容器（Docker/Podman/nerdctl等）映射信息
const graphCollectScript = `
echo "===META==="
echo "hostname=$(hostname 2>/dev/null)"
echo "kernel=$(uname -r 2>/dev/null)"

echo "===IPS==="
hostname -I 2>/dev/null || ip -o -4 addr show | awk '{print $4}' | cut -d/ -f1 2>/dev/null || ifconfig | awk '/inet / {print $2}' | sed 's/addr://' 2>/dev/null

echo "===CONTAINERS==="
if command -v docker >/dev/null 2>&1; then
  docker ps --format "{{.Names}}\t{{.Ports}}" 2>/dev/null || true
fi
if command -v podman >/dev/null 2>&1; then
  podman ps --format "{{.Names}}\t{{.Ports}}" 2>/dev/null || true
fi
if command -v nerdctl >/dev/null 2>&1; then
  nerdctl ps --format "{{.Names}}\t{{.Ports}}" 2>/dev/null || true
fi

echo "===CONTAINER_IPS==="
if command -v docker >/dev/null 2>&1; then
  for id in $(docker ps -q 2>/dev/null); do
    docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' "$id" 2>/dev/null || true
  done
fi
if command -v podman >/dev/null 2>&1; then
  for id in $(podman ps -q 2>/dev/null); do
    podman inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' "$id" 2>/dev/null || true
  done
fi
if command -v nerdctl >/dev/null 2>&1; then
  for id in $(nerdctl ps -q 2>/dev/null); do
    nerdctl inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' "$id" 2>/dev/null || true
  done
fi

echo "===NET==="
if command -v ss >/dev/null 2>&1; then
  echo "TYPE=SS"
  ss -Hntuap 2>/dev/null || ss -Hntua 2>/dev/null
elif command -v netstat >/dev/null 2>&1; then
  echo "TYPE=NETSTAT"
  netstat -ntuap 2>/dev/null || netstat -ntua 2>/dev/null
else
  echo "TYPE=PROC"
  [ -r /proc/net/tcp ] && awk 'NR>1 {print "tcp|" $2 "|" $3 "|" $4 "|" $10}' /proc/net/tcp 2>/dev/null
  [ -r /proc/net/tcp6 ] && awk 'NR>1 {print "tcp6|" $2 "|" $3 "|" $4 "|" $10}' /proc/net/tcp6 2>/dev/null
  [ -r /proc/net/udp ] && awk 'NR>1 {print "udp|" $2 "|" $3 "|" $4 "|" $10}' /proc/net/udp 2>/dev/null
  [ -r /proc/net/udp6 ] && awk 'NR>1 {print "udp6|" $2 "|" $3 "|" $4 "|" $10}' /proc/net/udp6 2>/dev/null
fi
exit 0
`

// RawConn 代表单条网络连接 5 元组与进程信息
type RawConn struct {
	Proto      string `json:"proto"`
	State      string `json:"state"`
	LocalIP    string `json:"local_ip"`
	LocalPort  int    `json:"local_port"`
	RemoteIP   string `json:"remote_ip"`
	RemotePort int    `json:"remote_port"`
	Process    string `json:"process,omitempty"`
	PID        int    `json:"pid,omitempty"`
	LocalRaw   string `json:"local_raw"`
	RemoteRaw  string `json:"remote_raw"`
}

// GraphNode G6 节点
type GraphNode struct {
	ID          string                 `json:"id"`
	Label       string                 `json:"label"`
	NodeType    string                 `json:"nodeType"` // "client", "service", "server", "outbound"
	IP          string                 `json:"ip,omitempty"`
	Port        int                    `json:"port,omitempty"`
	Process     string                 `json:"process,omitempty"`
	Proto       string                 `json:"proto,omitempty"`
	Level       int                    `json:"level,omitempty"`
	IsContainer bool                   `json:"is_container,omitempty"`
	Style       map[string]interface{} `json:"style,omitempty"`
}

// GraphEdge G6 边
type GraphEdge struct {
	ID        string                 `json:"id"`
	Source    string                 `json:"source"`
	Target    string                 `json:"target"`
	Label     string                 `json:"label"`    // 边的状态/进程简述
	EdgeType  string                 `json:"edgeType"` // "inbound", "listen", "outbound"
	Proto     string                 `json:"proto"`
	ConnCount int                    `json:"connCount"`
	Details   []RawConn              `json:"details"` // 关联的 5 元组
	Style     map[string]interface{} `json:"style,omitempty"`
}

// TopologyData 完整的图拓扑数据
type TopologyData struct {
	HostName       string      `json:"host_name"`
	HostIP         string      `json:"host_ip"`
	CollectedAt    string      `json:"collected_at"`
	Nodes          []GraphNode `json:"nodes"`
	Edges          []GraphEdge `json:"edges"`
	RawConns       []RawConn   `json:"raw_conns"`
	ListeningPorts []string    `json:"listening_ports"`
	Summary        struct {
		TotalConns     int `json:"total_conns"`
		ListeningCount int `json:"listening_count"`
		InboundClients int `json:"inbound_clients"`
		OutboundCount  int `json:"outbound_count"`
		TCPCount       int `json:"tcp_count"`
		UDPCount       int `json:"udp_count"`
	} `json:"summary"`
}

// GraphServer 管理动态采集与本地 HTTP 服务
type GraphServer struct {
	hostCfg Config
	timeout time.Duration

	collectMu       sync.Mutex
	mu              sync.RWMutex
	interval        time.Duration
	currentTopo     *TopologyData
	lastErr         error
	intervalChanged chan struct{}
	client          *ssh.Client
}

// newGraphServer 初始化采集状态和刷新周期通知通道。
func newGraphServer(hostCfg Config, timeout, interval time.Duration) *GraphServer {
	return &GraphServer{
		hostCfg:         hostCfg,
		timeout:         timeout,
		interval:        interval,
		intervalChanged: make(chan struct{}, 1),
	}
}

// getClientLocked 返回可用 SSH 连接。调用方必须持有 collectMu。
func (s *GraphServer) getClientLocked() (*ssh.Client, error) {
	if s.client != nil {
		_, _, err := s.client.SendRequest("keepalive@openssh.com", true, nil)
		if err == nil {
			return s.client, nil
		}
		s.client.Close()
		s.client = nil
	}

	client, err := dialThroughJumpers(s.hostCfg, secureshell.Dial)
	if err != nil {
		return nil, err
	}
	s.client = client
	return s.client, nil
}

func (s *GraphServer) fetchOnce(ctx context.Context) (*TopologyData, error) {
	s.collectMu.Lock()
	defer s.collectMu.Unlock()

	client, err := s.getClientLocked()
	if err != nil {
		collectErr := fmt.Errorf("connect failed: %w", err)
		s.setLastError(collectErr)
		return nil, collectErr
	}

	topo, err := collectAndBuildTopology(ctx, client, s.hostCfg, s.timeout)
	if err != nil {
		if s.client == client {
			s.client.Close()
			s.client = nil
		}
		s.setLastError(err)
		return nil, err
	}

	s.mu.Lock()
	s.currentTopo = topo
	s.lastErr = nil
	s.mu.Unlock()

	return topo, nil
}

// setLastError 保存最近一次采集失败，供页面展示旧数据时明确标记异常。
func (s *GraphServer) setLastError(err error) {
	s.mu.Lock()
	s.lastErr = err
	s.mu.Unlock()
}

// getInterval 返回当前后端采集周期。
func (s *GraphServer) getInterval() time.Duration {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.interval
}

// setInterval 更新采集周期并唤醒 poller，使新周期立即生效。
func (s *GraphServer) setInterval(interval time.Duration) {
	s.mu.Lock()
	s.interval = interval
	s.mu.Unlock()

	select {
	case s.intervalChanged <- struct{}{}:
	default:
	}
}

// snapshot 在同一读锁下返回页面响应需要的完整状态。
func (s *GraphServer) snapshot() (*TopologyData, error, time.Duration) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.currentTopo, s.lastErr, s.interval
}

// closeClient 等待正在执行的采集结束后关闭 SSH 连接。
func (s *GraphServer) closeClient() {
	s.collectMu.Lock()
	defer s.collectMu.Unlock()
	if s.client != nil {
		s.client.Close()
		s.client = nil
	}
}

// startPoller 按可动态调整的周期串行触发后台采集。
func (s *GraphServer) startPoller(ctx context.Context) {
	for {
		interval := s.getInterval()
		if interval <= 0 {
			select {
			case <-ctx.Done():
				return
			case <-s.intervalChanged:
				continue
			}
		}

		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			stopTimer(timer)
			return
		case <-s.intervalChanged:
			stopTimer(timer)
			continue
		case <-timer.C:
			if _, err := s.fetchOnce(ctx); err != nil {
				log.Printf("[graph] collect update failed: %v", err)
			}
		}
	}
}

// stopTimer 停止计时器，并在旧版 Go 计时器语义下安全排空通道。
func stopTimer(timer *time.Timer) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
}

// validateGraphInterval 接受手动模式 0 或不短于最小值的自动刷新周期。
func validateGraphInterval(interval time.Duration) error {
	if interval < 0 {
		return fmt.Errorf("refresh interval must not be negative")
	}
	if interval > 0 && interval < graphIntervalMinimum {
		return fmt.Errorf("refresh interval must be 0 or at least %v", graphIntervalMinimum)
	}
	return nil
}

// graphIntervalFromSeconds 在转换前检查 time.Duration 溢出。
func graphIntervalFromSeconds(seconds int) (time.Duration, error) {
	if seconds < 0 {
		return 0, fmt.Errorf("refresh interval must not be negative")
	}
	maxSeconds := int64((time.Duration(1<<63 - 1)) / time.Second)
	if int64(seconds) > maxSeconds {
		return 0, fmt.Errorf("refresh interval is too large")
	}
	interval := time.Duration(seconds) * time.Second
	return interval, validateGraphInterval(interval)
}

// newGraphHTTPHandler 构造拓扑页面、数据查询和刷新周期接口。
func newGraphHTTPHandler(server *GraphServer, hostCfg Config) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		htmlStr := renderDynamicG6HTML(hostCfg.Name, hostCfg.Host, int(server.getInterval().Seconds()))
		_, _ = w.Write([]byte(htmlStr))
	})

	mux.HandleFunc("/api/topology", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		var fetchErr error
		if r.URL.Query().Get("force") == "1" {
			_, fetchErr = server.fetchOnce(r.Context())
		}

		currentTopo, lastErr, currentInterval := server.snapshot()
		response := map[string]interface{}{
			"data":        currentTopo,
			"interval":    int(currentInterval.Seconds()),
			"host_name":   hostCfg.Name,
			"host_ip":     hostCfg.Host,
			"remote_addr": hostCfg.RemoteAddr(),
		}
		if lastErr != nil {
			response["error"] = lastErr.Error()
		}
		if fetchErr != nil {
			w.WriteHeader(http.StatusBadGateway)
		}
		_ = json.NewEncoder(w).Encode(response)
	})

	mux.HandleFunc("/api/interval", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var request struct {
			Interval int `json:"interval"`
		}
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&request); err != nil {
			http.Error(w, fmt.Sprintf("invalid request: %v", err), http.StatusBadRequest)
			return
		}
		if err := decoder.Decode(&struct{}{}); err != io.EOF {
			http.Error(w, "invalid request: expected one JSON object", http.StatusBadRequest)
			return
		}

		requestedInterval, err := graphIntervalFromSeconds(request.Interval)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		server.setInterval(requestedInterval)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(map[string]int{"interval": request.Interval})
	})

	return mux
}

// GraphAction 执行 graph 命令
func GraphAction(c *cli.Context) error {
	keywords, err := hostKeywords(c)
	if err != nil {
		return cli.Exit(err, 1)
	}

	hostCfg, err := UISelect(keywords...)
	if err != nil {
		return cli.Exit(err, 1)
	}

	interval := graphIntervalDefault
	if c.IsSet("interval") {
		interval = c.Duration("interval")
	}
	if err := validateGraphInterval(interval); err != nil {
		return cli.Exit(err, 1)
	}

	server := newGraphServer(hostCfg, graphTimeoutDefault, interval)

	fmt.Printf("Connecting to %s (%s) to collect network topology...\n", hostCfg.Name, hostCfg.RemoteAddr())
	_, err = server.fetchOnce(c.Context)
	if err != nil {
		return cli.Exit(fmt.Sprintf("failed to collect initial graph data: %v", err), 1)
	}

	listenAddr := c.String("addr")
	if listenAddr == "" {
		listenAddr = "127.0.0.1:0"
	}

	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return cli.Exit(fmt.Sprintf("failed to listen on %s: %v", listenAddr, err), 1)
	}
	defer listener.Close()

	actualAddr := listener.Addr().String()
	webURL := fmt.Sprintf("http://%s", actualAddr)

	httpServer := &http.Server{
		Handler:           newGraphHTTPHandler(server, hostCfg),
		ReadHeaderTimeout: 5 * time.Second,
	}

	ctx, cancel := context.WithCancel(c.Context)
	defer cancel()

	go server.startPoller(ctx)

	go func() {
		if err := httpServer.Serve(listener); err != nil && err != http.ErrServerClosed {
			log.Printf("[graph] HTTP server error: %v", err)
		}
	}()

	fmt.Println("==================================================================")
	fmt.Printf("🚀 Topology Web Server running at: \033[1;36m%s\033[0m\n", webURL)
	fmt.Printf("🎯 Target Host: %s (%s)\n", hostCfg.Name, hostCfg.RemoteAddr())
	if interval > 0 {
		fmt.Printf("⏱️  Refresh Interval: %v\n", interval)
	} else {
		fmt.Println("⏱️  Refresh Mode: Manual (手动刷新模式)")
	}
	fmt.Println("💡 Press \033[1mCtrl+C\033[0m to stop server.")
	fmt.Println("==================================================================")

	_ = openBrowser(webURL)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigChan)
	select {
	case <-sigChan:
	case <-c.Context.Done():
	}

	fmt.Println("\nShutting down topology server...")
	cancel()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer shutdownCancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		_ = httpServer.Close()
	}
	server.closeClient()
	return nil
}

func collectAndBuildTopology(parent context.Context, client *ssh.Client, hostCfg Config, timeout time.Duration) (*TopologyData, error) {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	session, err := client.NewSession()
	if err != nil {
		return nil, err
	}
	defer session.Close()

	go func() {
		<-ctx.Done()
		session.Close()
	}()

	out, err := session.Output(graphCollectScript)
	if err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("collect network data: %w", ctx.Err())
		}
		return nil, fmt.Errorf("collect network data: %w", err)
	}

	conns, meta, knownLocalIPs, dockerPortMap := parseGraphCollectOutput(string(out))
	hostName := meta["hostname"]
	if hostName == "" {
		hostName = hostCfg.Name
	}

	topo := buildTopology(hostName, hostCfg.Host, conns, knownLocalIPs, dockerPortMap)
	return topo, nil
}

func parseGraphCollectOutput(out string) ([]RawConn, map[string]string, []string, map[int]string) {
	meta := make(map[string]string)
	var conns []RawConn
	var knownLocalIPs []string
	dockerPortMap := make(map[int]string)
	lines := strings.Split(out, "\n")
	mode := ""
	netType := ""

	rePort := regexp.MustCompile(`:(\d+)->`)

	for _, rawLine := range lines {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			continue
		}
		if line == "===META===" {
			mode = "meta"
			continue
		}
		if line == "===IPS===" {
			mode = "ips"
			continue
		}
		if line == "===DOCKER===" || line == "===CONTAINERS===" {
			mode = "containers"
			continue
		}
		if line == "===CONTAINER_IPS===" {
			mode = "container_ips"
			continue
		}
		if line == "===NET===" {
			mode = "net"
			continue
		}

		if mode == "meta" {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				meta[parts[0]] = parts[1]
			}
			continue
		}

		if mode == "ips" {
			fields := strings.Fields(line)
			for _, f := range fields {
				ipStr := strings.TrimSpace(f)
				if idx := strings.Index(ipStr, "/"); idx != -1 {
					ipStr = ipStr[:idx]
				}
				if ipStr != "" {
					knownLocalIPs = append(knownLocalIPs, ipStr)
				}
			}
			continue
		}

		if mode == "container_ips" {
			for _, ipStr := range strings.Fields(line) {
				if net.ParseIP(ipStr) != nil {
					knownLocalIPs = append(knownLocalIPs, ipStr)
				}
			}
			continue
		}

		if mode == "containers" {
			parts := strings.SplitN(line, "\t", 2)
			if len(parts) >= 2 {
				containerName := strings.TrimSpace(parts[0])
				portsStr := parts[1]
				matches := rePort.FindAllStringSubmatch(portsStr, -1)
				for _, m := range matches {
					if len(m) > 1 {
						if p, err := strconv.Atoi(m[1]); err == nil && p > 0 {
							dockerPortMap[p] = containerName
						}
					}
				}
			}
			continue
		}

		if mode == "net" {
			if strings.HasPrefix(line, "TYPE=") {
				netType = strings.TrimPrefix(line, "TYPE=")
				continue
			}

			switch netType {
			case "SS":
				if c, ok := parseSSLine(line); ok {
					conns = append(conns, c)
				}
			case "NETSTAT":
				if c, ok := parseNetstatLine(line); ok {
					conns = append(conns, c)
				}
			case "PROC":
				if c, ok := parseProcLine(line); ok {
					conns = append(conns, c)
				}
			}
		}
	}

	return conns, meta, knownLocalIPs, dockerPortMap
}

func parseSSLine(line string) (RawConn, bool) {
	fields := strings.Fields(line)
	if len(fields) < 5 {
		return RawConn{}, false
	}

	proto := strings.ToLower(fields[0])
	state := normalizeState(fields[1])

	localAddr := fields[4]
	peerAddr := "*:*"
	if len(fields) >= 6 {
		peerAddr = fields[5]
	}

	processStr := ""
	pid := 0
	if len(fields) >= 7 {
		processStr = strings.Join(fields[6:], " ")
		processStr, pid = extractProcessAndPID(processStr)
	}

	localIP, localPort := splitHostPortSafe(localAddr)
	remoteIP, remotePort := splitHostPortSafe(peerAddr)

	return RawConn{
		Proto:      proto,
		State:      state,
		LocalIP:    localIP,
		LocalPort:  localPort,
		RemoteIP:   remoteIP,
		RemotePort: remotePort,
		Process:    processStr,
		PID:        pid,
		LocalRaw:   localAddr,
		RemoteRaw:  peerAddr,
	}, true
}

func parseNetstatLine(line string) (RawConn, bool) {
	fields := strings.Fields(line)
	if len(fields) < 5 {
		return RawConn{}, false
	}

	proto := strings.ToLower(fields[0])
	localAddr := fields[3]
	remoteAddr := fields[4]

	state := "UNKNOWN"
	procIdx := 5
	if strings.HasPrefix(proto, "tcp") {
		if len(fields) >= 6 {
			state = normalizeState(fields[5])
			procIdx = 6
		}
	} else if strings.HasPrefix(proto, "udp") {
		state = "UNCONN"
	}

	processStr := ""
	pid := 0
	if len(fields) > procIdx {
		procField := fields[procIdx]
		if procField != "-" {
			parts := strings.SplitN(procField, "/", 2)
			if len(parts) == 2 {
				pid, _ = strconv.Atoi(parts[0])
				processStr = parts[1]
			} else {
				processStr = procField
			}
		}
	}

	localIP, localPort := splitHostPortSafe(localAddr)
	remoteIP, remotePort := splitHostPortSafe(remoteAddr)

	return RawConn{
		Proto:      proto,
		State:      state,
		LocalIP:    localIP,
		LocalPort:  localPort,
		RemoteIP:   remoteIP,
		RemotePort: remotePort,
		Process:    processStr,
		PID:        pid,
		LocalRaw:   localAddr,
		RemoteRaw:  remoteAddr,
	}, true
}

func parseProcLine(line string) (RawConn, bool) {
	parts := strings.Split(line, "|")
	if len(parts) < 4 {
		return RawConn{}, false
	}
	proto := parts[0]
	localIP, localPort := parseHexAddr(parts[1])
	remoteIP, remotePort := parseHexAddr(parts[2])
	state := parseProcState(parts[3])

	return RawConn{
		Proto:      proto,
		State:      state,
		LocalIP:    localIP,
		LocalPort:  localPort,
		RemoteIP:   remoteIP,
		RemotePort: remotePort,
		LocalRaw:   fmt.Sprintf("%s:%d", localIP, localPort),
		RemoteRaw:  fmt.Sprintf("%s:%d", remoteIP, remotePort),
	}, true
}

func parseHexAddr(hexAddr string) (string, int) {
	parts := strings.Split(hexAddr, ":")
	if len(parts) != 2 {
		return "", 0
	}
	portInt64, _ := strconv.ParseInt(parts[1], 16, 32)
	port := int(portInt64)

	ipHex := parts[0]
	if len(ipHex) == 8 {
		b, err := hex.DecodeString(ipHex)
		if err == nil && len(b) == 4 {
			ip := net.IPv4(b[3], b[2], b[1], b[0])
			return ip.String(), port
		}
	}
	return ipHex, port
}

var procTCPStates = map[string]string{
	"01": "ESTABLISHED",
	"02": "SYN_SENT",
	"03": "SYN_RECV",
	"04": "FIN_WAIT1",
	"05": "FIN_WAIT2",
	"06": "TIME_WAIT",
	"07": "CLOSE",
	"08": "CLOSE_WAIT",
	"09": "LAST_ACK",
	"0A": "LISTEN",
	"0B": "CLOSING",
}

func parseProcState(hexState string) string {
	hexState = strings.ToUpper(strings.TrimSpace(hexState))
	if s, ok := procTCPStates[hexState]; ok {
		return s
	}
	return "UNKNOWN"
}

func normalizeState(s string) string {
	s = strings.ToUpper(s)
	switch s {
	case "LISTEN", "LISTENING":
		return "LISTEN"
	case "ESTAB", "ESTABLISHED":
		return "ESTABLISHED"
	case "TIME-WAIT", "TIME_WAIT":
		return "TIME_WAIT"
	case "CLOSE-WAIT", "CLOSE_WAIT":
		return "CLOSE_WAIT"
	case "SYN-SENT", "SYN_SENT":
		return "SYN_SENT"
	case "SYN-RECV", "SYN_RECV":
		return "SYN_RECV"
	case "FIN-WAIT-1", "FIN_WAIT1":
		return "FIN_WAIT1"
	case "FIN-WAIT-2", "FIN_WAIT2":
		return "FIN_WAIT2"
	case "UNCONN":
		return "UNCONN"
	default:
		return s
	}
}

func extractProcessAndPID(s string) (string, int) {
	reName := regexp.MustCompile(`"([^"]+)"`)
	rePID := regexp.MustCompile(`pid=(\d+)`)

	var name string
	var pid int

	if matches := reName.FindStringSubmatch(s); len(matches) > 1 {
		name = matches[1]
	}
	if matches := rePID.FindStringSubmatch(s); len(matches) > 1 {
		pid, _ = strconv.Atoi(matches[1])
	}
	return name, pid
}

func splitHostPortSafe(addr string) (string, int) {
	addr = strings.TrimSpace(addr)
	if addr == "" || addr == "*:*" {
		return "*", 0
	}
	lastColon := strings.LastIndex(addr, ":")
	if lastColon == -1 {
		return addr, 0
	}
	host := addr[:lastColon]
	portStr := addr[lastColon+1:]
	if portStr == "*" {
		return host, 0
	}
	port, _ := strconv.Atoi(portStr)
	host = strings.Trim(host, "[]")
	return host, port
}

// isLocalOrContainerIP 判断远端 IP 是否为回环、本机网卡或已采集到的容器地址。
func isLocalOrContainerIP(remoteIP, hostIP string, knownLocalIPs []string) bool {
	remoteIP = strings.TrimSpace(strings.Trim(remoteIP, "[]"))
	if remoteIP == "" || remoteIP == "*" || remoteIP == "0.0.0.0" || remoteIP == "::" {
		return true
	}
	if remoteIP == "127.0.0.1" || strings.HasPrefix(remoteIP, "127.") || remoteIP == "::1" || remoteIP == "localhost" {
		return true
	}
	if hostIP != "" && remoteIP == hostIP {
		return true
	}
	for _, localIP := range knownLocalIPs {
		if localIP != "" && remoteIP == localIP {
			return true
		}
	}
	return false
}

func isContainerProxyProcess(proc string) bool {
	proc = strings.ToLower(strings.TrimSpace(proc))
	switch proc {
	case "", "docker-proxy", "rootlessport", "slirp4netns", "pasta", "conmon", "nerdctl", "podman":
		return true
	default:
		return false
	}
}

func resolveProcName(rawProc string, port int, protoBase string, containerPortMap map[int]string) (string, bool) {
	if isContainerProxyProcess(rawProc) {
		if cName, ok := containerPortMap[port]; ok && cName != "" {
			return cName, true
		}
	}
	if rawProc != "" {
		return rawProc, false
	}
	return protoBase, false
}

// buildTopology 构建 [remoteip:port] -> [mysql:3306] -> [server] -> [tcp://remoteip:port] 链路拓扑
// 本机与 Docker 内部连接直接从 [server] -> [mysql:3306]
func buildTopology(hostName, hostIP string, conns []RawConn, knownLocalIPs []string, dockerPortMap map[int]string) *TopologyData {
	topo := &TopologyData{
		HostName:    hostName,
		HostIP:      hostIP,
		CollectedAt: time.Now().Format("2006-01-02 15:04:05"),
		RawConns:    conns,
	}

	serverNodeID := "node_server"
	serverLabel := "server"
	if hostName != "" {
		serverLabel = hostName
	}
	if hostIP != "" {
		serverLabel = fmt.Sprintf("%s\n(%s)", serverLabel, hostIP)
	}

	// 1. 提取所有本地监听服务配置
	listeningMap := make(map[string]RawConn)
	for _, c := range conns {
		if c.State == "LISTEN" || (strings.HasPrefix(c.Proto, "udp") && (c.RemotePort == 0 || c.RemoteIP == "*" || c.RemoteIP == "0.0.0.0")) {
			protoBase := getBaseProto(c.Proto)
			key := fmt.Sprintf("%s_%d", protoBase, c.LocalPort)
			listeningMap[key] = c

			procName, isContainer := resolveProcName(c.Process, c.LocalPort, protoBase, dockerPortMap)
			serviceLabel := fmt.Sprintf("%s:%d", procName, c.LocalPort)
			if isContainer {
				serviceLabel = "🐳 " + serviceLabel
			}
			topo.ListeningPorts = append(topo.ListeningPorts, serviceLabel)
		}
	}
	sort.Strings(topo.ListeningPorts)

	// 添加本服务器节点 [server] (Level 3)
	topo.Nodes = append(topo.Nodes, GraphNode{
		ID:       serverNodeID,
		Label:    serverLabel,
		NodeType: "server",
		IP:       hostIP,
		Level:    3,
	})

	// 2. 构建入站与出站连接，仅为产生实际连接的服务生成 service 节点
	clientNodes := make(map[string]*GraphNode)
	activeServiceNodes := make(map[string]*GraphNode)
	outboundNodes := make(map[string]*GraphNode)
	edgeMap := make(map[string]*GraphEdge)

	for _, c := range conns {
		protoBase := getBaseProto(c.Proto)
		if protoBase == "tcp" {
			topo.Summary.TCPCount++
		} else if protoBase == "udp" {
			topo.Summary.UDPCount++
		}
		topo.Summary.TotalConns++

		// 忽略本地监听状态本身（无外部对端）
		if c.State == "LISTEN" {
			continue
		}
		if c.RemoteIP == "" || c.RemoteIP == "*" || c.RemoteIP == "0.0.0.0" || c.RemoteIP == "::" {
			continue
		}

		srvKey := fmt.Sprintf("%s_%d", protoBase, c.LocalPort)
		listenConn, isListening := listeningMap[srvKey]

		if isListening {
			srvNodeID := fmt.Sprintf("srv_%s_%d", protoBase, c.LocalPort)

			// 仅当产生连接时，才激活并创建监听服务节点 [process:port]
			if _, exists := activeServiceNodes[srvNodeID]; !exists {
				procName, isContainer := resolveProcName(listenConn.Process, c.LocalPort, protoBase, dockerPortMap)
				if procName == protoBase && c.Process != "" {
					procName, isContainer = resolveProcName(c.Process, c.LocalPort, protoBase, dockerPortMap)
				}
				activeServiceNodes[srvNodeID] = &GraphNode{
					ID:          srvNodeID,
					Label:       fmt.Sprintf("%s:%d", procName, c.LocalPort),
					NodeType:    "service",
					Port:        c.LocalPort,
					Process:     procName,
					Proto:       c.Proto,
					Level:       2,
					IsContainer: isContainer,
				}
			}

			// 判断是否为本机/Docker 内部连接
			if isLocalOrContainerIP(c.RemoteIP, hostIP, knownLocalIPs) {
				// 本机/Docker 内部调用：不生成 client 节点，直接 [server] -> [service]
				edgeID := fmt.Sprintf("edge_internal_%s_%s_%s", serverNodeID, srvNodeID, protoBase)
				if edge, exists := edgeMap[edgeID]; exists {
					edge.ConnCount++
					edge.Details = append(edge.Details, c)
				} else {
					edgeMap[edgeID] = &GraphEdge{
						ID:        edgeID,
						Source:    serverNodeID,
						Target:    srvNodeID,
						EdgeType:  "internal",
						Proto:     c.Proto,
						ConnCount: 1,
						Details:   []RawConn{c},
					}
				}
			} else {
				// 外部客户端入站链路：[remoteip] -> [mysql:3306]
				clientID := fmt.Sprintf("client_%s", sanitizeNodeID(c.RemoteIP))
				clientLabel := c.RemoteIP

				if _, exists := clientNodes[clientID]; !exists {
					clientNodes[clientID] = &GraphNode{
						ID:       clientID,
						Label:    clientLabel,
						NodeType: "client",
						IP:       c.RemoteIP,
						Level:    1,
					}
				}

				edgeID := fmt.Sprintf("edge_%s_%s_%s", clientID, srvNodeID, protoBase)
				if edge, exists := edgeMap[edgeID]; exists {
					edge.ConnCount++
					edge.Details = append(edge.Details, c)
				} else {
					edgeMap[edgeID] = &GraphEdge{
						ID:        edgeID,
						Source:    clientID,
						Target:    srvNodeID,
						EdgeType:  "inbound",
						Proto:     c.Proto,
						ConnCount: 1,
						Details:   []RawConn{c},
					}
				}
			}
		} else {
			// B. 判断出站 remoteIP 是否为本机或 Docker IP
			if isLocalOrContainerIP(c.RemoteIP, hostIP, knownLocalIPs) {
				// 本机进程主动连接本机或 Docker 内部服务：归入内部调用 [server] -> [service]
				srvNodeID := fmt.Sprintf("srv_%s_%d", protoBase, c.RemotePort)
				if _, exists := activeServiceNodes[srvNodeID]; !exists {
					procName, isContainer := resolveProcName("", c.RemotePort, protoBase, dockerPortMap)
					targetKey := fmt.Sprintf("%s_%d", protoBase, c.RemotePort)
					if listenConn, ok := listeningMap[targetKey]; ok {
						procName, isContainer = resolveProcName(listenConn.Process, c.RemotePort, protoBase, dockerPortMap)
					}
					activeServiceNodes[srvNodeID] = &GraphNode{
						ID:          srvNodeID,
						Label:       fmt.Sprintf("%s:%d", procName, c.RemotePort),
						NodeType:    "service",
						Port:        c.RemotePort,
						Process:     procName,
						Proto:       c.Proto,
						Level:       2,
						IsContainer: isContainer,
					}
				}

				edgeID := fmt.Sprintf("edge_internal_%s_%s_%s", serverNodeID, srvNodeID, protoBase)
				if edge, exists := edgeMap[edgeID]; exists {
					edge.ConnCount++
					edge.Details = append(edge.Details, c)
				} else {
					edgeMap[edgeID] = &GraphEdge{
						ID:        edgeID,
						Source:    serverNodeID,
						Target:    srvNodeID,
						EdgeType:  "internal",
						Proto:     c.Proto,
						ConnCount: 1,
						Details:   []RawConn{c},
					}
				}
			} else {
				// 真正的外部出站外联链路：[server] -> [tcp://remoteip:port]
				remoteTarget := fmt.Sprintf("%s://%s:%d", protoBase, c.RemoteIP, c.RemotePort)
				outboundID := fmt.Sprintf("outbound_%s_%s_%d", protoBase, sanitizeNodeID(c.RemoteIP), c.RemotePort)

				if _, exists := outboundNodes[outboundID]; !exists {
					outboundNodes[outboundID] = &GraphNode{
						ID:       outboundID,
						Label:    remoteTarget,
						NodeType: "outbound",
						IP:       c.RemoteIP,
						Port:     c.RemotePort,
						Level:    4,
					}
				}

				edgeID := fmt.Sprintf("edge_%s_%s_%s", serverNodeID, outboundID, protoBase)
				if edge, exists := edgeMap[edgeID]; exists {
					edge.ConnCount++
					edge.Details = append(edge.Details, c)
				} else {
					edgeMap[edgeID] = &GraphEdge{
						ID:        edgeID,
						Source:    serverNodeID,
						Target:    outboundID,
						EdgeType:  "outbound",
						Proto:     c.Proto,
						ConnCount: 1,
						Details:   []RawConn{c},
					}
				}
			}
		}
	}

	// 3. 将激活的服务进程节点加入节点列表 (listen 不再产生边)
	for _, srvNode := range activeServiceNodes {
		topo.Nodes = append(topo.Nodes, *srvNode)
	}

	// 格式化边的显示文本（标注连接数与状态）
	for _, edge := range edgeMap {
		if edge.EdgeType == "inbound" {
			stateStr := "ESTAB"
			if len(edge.Details) > 0 && edge.Details[0].State != "" {
				s := edge.Details[0].State
				if s == "ESTABLISHED" {
					s = "ESTAB"
				}
				stateStr = s
			}
			protoBase := getBaseProto(edge.Proto)
			if edge.ConnCount > 1 {
				edge.Label = fmt.Sprintf("%d conns (%s %s)", edge.ConnCount, protoBase, stateStr)
			} else {
				edge.Label = fmt.Sprintf("%s %s", protoBase, stateStr)
			}
		} else if edge.EdgeType == "internal" {
			procStr := ""
			stateStr := "ESTAB"
			if len(edge.Details) > 0 {
				procStr = edge.Details[0].Process
				s := edge.Details[0].State
				if s == "ESTABLISHED" {
					s = "ESTAB"
				}
				stateStr = s
			}
			protoBase := getBaseProto(edge.Proto)
			if procStr != "" {
				if edge.ConnCount > 1 {
					edge.Label = fmt.Sprintf("[%s] %d local (%s)", procStr, edge.ConnCount, stateStr)
				} else {
					edge.Label = fmt.Sprintf("[%s] local (%s)", procStr, stateStr)
				}
			} else {
				if edge.ConnCount > 1 {
					edge.Label = fmt.Sprintf("local (%d %s %s)", edge.ConnCount, protoBase, stateStr)
				} else {
					edge.Label = fmt.Sprintf("local (%s %s)", protoBase, stateStr)
				}
			}
		} else if edge.EdgeType == "outbound" {
			procStr := ""
			stateStr := "ESTAB"
			if len(edge.Details) > 0 {
				procStr = edge.Details[0].Process
				s := edge.Details[0].State
				if s == "ESTABLISHED" {
					s = "ESTAB"
				}
				stateStr = s
			}
			if procStr == "" {
				procStr = getBaseProto(edge.Proto)
			}
			if edge.ConnCount > 1 {
				edge.Label = fmt.Sprintf("[%s] %d conns (%s)", procStr, edge.ConnCount, stateStr)
			} else {
				edge.Label = fmt.Sprintf("[%s] %s", procStr, stateStr)
			}
		}
	}

	for _, node := range clientNodes {
		topo.Nodes = append(topo.Nodes, *node)
	}
	for _, node := range outboundNodes {
		topo.Nodes = append(topo.Nodes, *node)
	}
	for _, edge := range edgeMap {
		topo.Edges = append(topo.Edges, *edge)
	}

	topo.Summary.ListeningCount = len(listeningMap)
	topo.Summary.InboundClients = len(clientNodes)
	topo.Summary.OutboundCount = len(outboundNodes)

	return topo
}

func getBaseProto(p string) string {
	p = strings.ToLower(p)
	if strings.HasPrefix(p, "tcp") {
		return "tcp"
	}
	if strings.HasPrefix(p, "udp") {
		return "udp"
	}
	return p
}

func sanitizeNodeID(s string) string {
	reg := regexp.MustCompile(`[^a-zA-Z0-9_]`)
	return reg.ReplaceAllString(s, "_")
}

func openBrowser(targetURL string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", targetURL)
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", targetURL)
	default:
		cmd = exec.Command("xdg-open", targetURL)
	}
	return cmd.Start()
}

func renderDynamicG6HTML(hostName, hostIP string, defaultIntervalSec int) string {
	tmpl, err := template.New("dynamic_g6").Parse(dynamicG6Template)
	if err != nil {
		return fmt.Sprintf("Template Error: %v", err)
	}

	var sb strings.Builder
	data := map[string]interface{}{
		"HostName":           hostName,
		"HostIP":             hostIP,
		"DefaultIntervalSec": defaultIntervalSec,
	}
	_ = tmpl.Execute(&sb, data)
	return sb.String()
}

//go:embed graph.html
var dynamicG6Template string
