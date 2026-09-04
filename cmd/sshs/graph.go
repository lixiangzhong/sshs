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
	graphTimeoutDefault   = 10 * time.Second
	graphIntervalDefault  = 30 * time.Second
	graphIntervalMinimum  = 2 * time.Second
	graphAggregateDefault = 3
)

// graphCollectScript 在远程主机上执行，采集网络连接、本机IP、容器（Docker/Podman/nerdctl等）映射信息，
// 以及各容器独立网络命名空间内的连接表（宿主 ss/netstat 看不到经 DNAT 进容器的连接）
const graphCollectScript = `
echo "===META==="
echo "hostname=$(hostname 2>/dev/null)"
echo "kernel=$(uname -r 2>/dev/null)"

echo "===IPS==="
hostname -I 2>/dev/null || ip -o -4 addr show | awk '{print $4}' | cut -d/ -f1 2>/dev/null || ifconfig | awk '/inet / {print $2}' | sed 's/addr://' 2>/dev/null

echo "===CONTAINERS==="
if command -v docker >/dev/null 2>&1; then
  docker ps -a --no-trunc --format "{{.Names}}\t{{.Ports}}" 2>/dev/null || docker ps --format "{{.Names}}\t{{.Ports}}" 2>/dev/null || true
fi
if command -v podman >/dev/null 2>&1; then
  podman ps -a --no-trunc --format "{{.Names}}\t{{.Ports}}" 2>/dev/null || true
fi
if command -v nerdctl >/dev/null 2>&1; then
  nerdctl ps -a --no-trunc --format "{{.Names}}\t{{.Ports}}" 2>/dev/null || true
fi

echo "===CONTAINER_IPS==="
host_ns=$(readlink /proc/self/ns/net 2>/dev/null)
cnet_tuples=""
if command -v docker >/dev/null 2>&1; then
  for cid in $(docker ps -q 2>/dev/null); do
    name=$(docker inspect --format '{{.Name}}' "$cid" 2>/dev/null | sed 's#^/##')
    pid=$(docker inspect --format '{{.State.Pid}}' "$cid" 2>/dev/null)
    ips=$(docker inspect --format '{{.NetworkSettings.IPAddress}} {{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' "$cid" 2>/dev/null)
    ports=$(docker inspect --format '{{range $p, $conf := .NetworkSettings.Ports}}{{range $conf}}{{.HostPort}} {{end}}{{end}}' "$cid" 2>/dev/null)
    echo "$name|$pid|$ips|$ports"
    ns=$(readlink "/proc/$pid/ns/net" 2>/dev/null)
    if [ -n "$pid" ] && [ "$pid" != "0" ] && [ -n "$ns" ] && [ "$ns" != "$host_ns" ]; then
      cnet_tuples="$cnet_tuples $name|$pid|$ns"
    fi
  done
fi
if command -v podman >/dev/null 2>&1; then
  for cid in $(podman ps -q 2>/dev/null); do
    name=$(podman inspect --format '{{.Name}}' "$cid" 2>/dev/null | sed 's#^/##')
    pid=$(podman inspect --format '{{.State.Pid}}' "$cid" 2>/dev/null)
    ips=$(podman inspect --format '{{.NetworkSettings.IPAddress}} {{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' "$cid" 2>/dev/null)
    ports=$(podman inspect --format '{{range $p, $conf := .NetworkSettings.Ports}}{{range $conf}}{{.HostPort}} {{end}}{{end}}' "$cid" 2>/dev/null)
    echo "$name|$pid|$ips|$ports"
    ns=$(readlink "/proc/$pid/ns/net" 2>/dev/null)
    if [ -n "$pid" ] && [ "$pid" != "0" ] && [ -n "$ns" ] && [ "$ns" != "$host_ns" ]; then
      cnet_tuples="$cnet_tuples $name|$pid|$ns"
    fi
  done
fi
if command -v nerdctl >/dev/null 2>&1; then
  for cid in $(nerdctl ps -q 2>/dev/null); do
    name=$(nerdctl inspect --format '{{.Name}}' "$cid" 2>/dev/null | sed 's#^/##')
    pid=$(nerdctl inspect --format '{{.State.Pid}}' "$cid" 2>/dev/null)
    ips=$(nerdctl inspect --format '{{.NetworkSettings.IPAddress}} {{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' "$cid" 2>/dev/null)
    ports=$(nerdctl inspect --format '{{range $p, $conf := .NetworkSettings.Ports}}{{range $conf}}{{.HostPort}} {{end}}{{end}}' "$cid" 2>/dev/null)
    echo "$name|$pid|$ips|$ports"
    ns=$(readlink "/proc/$pid/ns/net" 2>/dev/null)
    if [ -n "$pid" ] && [ "$pid" != "0" ] && [ -n "$ns" ] && [ "$ns" != "$host_ns" ]; then
      cnet_tuples="$cnet_tuples $name|$pid|$ns"
    fi
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

echo "===CONTAINER_NET==="
seen_ns=""
for tuple in $cnet_tuples; do
  name=${tuple%%|*}
  rest=${tuple#*|}
  pid=${rest%%|*}
  ns=${rest#*|}
  case " $seen_ns " in *" $ns "*) continue ;; esac
  seen_ns="$seen_ns $ns"
  names="$name"
  for t2 in $cnet_tuples; do
    n2=${t2%%|*}
    r2=${t2#*|}
    ns2=${r2#*|}
    if [ "$ns2" = "$ns" ] && [ "$n2" != "$name" ]; then names="$names,$n2"; fi
  done
  echo "[[container]] names=$names netns=$ns"
  if command -v nsenter >/dev/null 2>&1 && nsenter -t "$pid" -n true 2>/dev/null; then
    if command -v ss >/dev/null 2>&1; then
      echo "TYPE=SS"
      { nsenter -t "$pid" -n ss -Hntuap 2>/dev/null || nsenter -t "$pid" -n ss -Hntua 2>/dev/null; } | head -2000
    elif command -v netstat >/dev/null 2>&1; then
      echo "TYPE=NETSTAT"
      { nsenter -t "$pid" -n netstat -ntuap 2>/dev/null || nsenter -t "$pid" -n netstat -ntua 2>/dev/null; } | head -2000
    else
      echo "TYPE=PROC"
      [ -r "/proc/$pid/net/tcp" ] && awk 'NR>1 {print "tcp|" $2 "|" $3 "|" $4 "|" $10}' "/proc/$pid/net/tcp" 2>/dev/null
      [ -r "/proc/$pid/net/tcp6" ] && awk 'NR>1 {print "tcp6|" $2 "|" $3 "|" $4 "|" $10}' "/proc/$pid/net/tcp6" 2>/dev/null
      [ -r "/proc/$pid/net/udp" ] && awk 'NR>1 {print "udp|" $2 "|" $3 "|" $4 "|" $10}' "/proc/$pid/net/udp" 2>/dev/null
      [ -r "/proc/$pid/net/udp6" ] && awk 'NR>1 {print "udp6|" $2 "|" $3 "|" $4 "|" $10}' "/proc/$pid/net/udp6" 2>/dev/null
    fi
  else
    echo "TYPE=PROC"
    [ -r "/proc/$pid/net/tcp" ] && awk 'NR>1 {print "tcp|" $2 "|" $3 "|" $4 "|" $10}' "/proc/$pid/net/tcp" 2>/dev/null
    [ -r "/proc/$pid/net/tcp6" ] && awk 'NR>1 {print "tcp6|" $2 "|" $3 "|" $4 "|" $10}' "/proc/$pid/net/tcp6" 2>/dev/null
    [ -r "/proc/$pid/net/udp" ] && awk 'NR>1 {print "udp|" $2 "|" $3 "|" $4 "|" $10}' "/proc/$pid/net/udp" 2>/dev/null
    [ -r "/proc/$pid/net/udp6" ] && awk 'NR>1 {print "udp6|" $2 "|" $3 "|" $4 "|" $10}' "/proc/$pid/net/udp6" 2>/dev/null
  fi
done
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
	// Container 记录连接采自哪个（些）容器的网络命名空间；宿主视角采集时为空。
	Container string `json:"container,omitempty"`
	LocalRaw  string `json:"local_raw"`
	RemoteRaw string `json:"remote_raw"`
}

// GraphNode 拓扑图节点
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

// GraphEdge 拓扑图边
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
		LocalClients   int `json:"local_clients"`
		OutboundCount  int `json:"outbound_count"`
		TCPCount       int `json:"tcp_count"`
		UDPCount       int `json:"udp_count"`
	} `json:"summary"`
}

// GraphServer 管理动态采集与本地 HTTP 服务
type GraphServer struct {
	hostCfg            Config
	timeout            time.Duration
	aggregateThreshold int

	collectMu       sync.Mutex
	mu              sync.RWMutex
	interval        time.Duration
	currentTopo     *TopologyData
	lastErr         error
	intervalChanged chan struct{}
	client          *ssh.Client
}

// newGraphServer 初始化采集状态和刷新周期通知通道。
func newGraphServer(hostCfg Config, timeout, interval time.Duration, aggregateThreshold ...int) *GraphServer {
	threshold := graphAggregateDefault
	if len(aggregateThreshold) > 0 && aggregateThreshold[0] > 0 {
		threshold = aggregateThreshold[0]
	}
	return &GraphServer{
		hostCfg:            hostCfg,
		timeout:            timeout,
		interval:           interval,
		aggregateThreshold: threshold,
		intervalChanged:    make(chan struct{}, 1),
	}
}

// getAggregateThreshold 返回连接聚合阈值。
func (s *GraphServer) getAggregateThreshold() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.aggregateThreshold <= 0 {
		return graphAggregateDefault
	}
	return s.aggregateThreshold
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
		htmlStr := renderGraphPageHTML(hostCfg.Name, hostCfg.Host, int(server.getInterval().Seconds()), server.getAggregateThreshold())
		_, _ = w.Write([]byte(htmlStr))
	})

	mux.HandleFunc("/cosmos.min.js", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		_, _ = w.Write([]byte(cosmosJS))
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

	jsonOutput := c.Bool("json")

	// --json 面向脚本/管道，禁止交互式选择，关键词必须能唯一定位主机
	var hostCfg Config
	if jsonOutput {
		hostCfg, err = SelectHostNonInteractive(keywords...)
	} else {
		hostCfg, err = UISelect(keywords...)
	}
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

	aggregate := graphAggregateDefault
	if c.IsSet("aggregate") {
		aggregate = c.Int("aggregate")
		if aggregate < 1 {
			return cli.Exit("aggregate threshold must be at least 1", 1)
		}
	}

	server := newGraphServer(hostCfg, graphTimeoutDefault, interval, aggregate)

	if !jsonOutput {
		fmt.Printf("Connecting to %s (%s) to collect network topology...\n", hostCfg.Name, hostCfg.RemoteAddr())
	}
	topo, err := server.fetchOnce(c.Context)
	if err != nil {
		return cli.Exit(fmt.Sprintf("failed to collect initial graph data: %v", err), 1)
	}

	if jsonOutput {
		server.closeClient()
		return printGraphJSON(topo)
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

// printGraphJSON 将拓扑数据以缩进 JSON 输出到 stdout，供脚本/管道消费。
func printGraphJSON(topo *TopologyData) error {
	b, err := json.MarshalIndent(topo, "", "  ")
	if err != nil {
		return cli.Exit(err, 1)
	}
	fmt.Fprintln(os.Stdout, string(b))
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

	conns, meta, knownLocalIPs, dockerPortMap, containerIPMap := parseGraphCollectOutput(string(out))
	hostName := meta["hostname"]
	if hostName == "" {
		hostName = hostCfg.Name
	}

	topo := buildTopology(hostName, hostCfg.Host, conns, knownLocalIPs, dockerPortMap, containerIPMap)
	return topo, nil
}

var (
	rePort       = regexp.MustCompile(`:(\d+)->`)
	reSSProcName = regexp.MustCompile(`"([^"]+)"`)
	reSSPID      = regexp.MustCompile(`pid=(\d+)`)
	reSanitizeID = regexp.MustCompile(`[^a-zA-Z0-9_]`)
)

func parseGraphCollectOutput(out string) ([]RawConn, map[string]string, []string, map[int]string, map[string]string) {
	meta := make(map[string]string)
	var conns []RawConn
	var knownLocalIPs []string
	dockerPortMap := make(map[int]string)
	containerIPMap := make(map[string]string)
	lines := strings.Split(out, "\n")
	mode := ""
	netType := ""
	currentContainer := ""
	containerNetType := ""

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
		if line == "===CONTAINER_NET===" {
			mode = "container_net"
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
			if strings.Contains(line, "|") {
				parts := strings.Split(line, "|")
				name := strings.TrimPrefix(strings.TrimSpace(parts[0]), "/")
				var ipsPart, portsPart string
				if len(parts) >= 4 {
					// 格式: name|pid|ips|ports
					ipsPart = parts[2]
					portsPart = parts[3]
				} else if len(parts) == 3 {
					// 格式: name|ips|ports
					ipsPart = parts[1]
					portsPart = parts[2]
				} else if len(parts) == 2 {
					// 格式: name|ips
					ipsPart = parts[1]
				}

				for _, ipStr := range strings.Fields(ipsPart) {
					if net.ParseIP(ipStr) != nil {
						knownLocalIPs = append(knownLocalIPs, ipStr)
						if name != "" {
							containerIPMap[ipStr] = name
						}
					}
				}
				for _, portStr := range strings.Fields(portsPart) {
					if p, err := strconv.Atoi(portStr); err == nil && p > 0 && name != "" {
						dockerPortMap[p] = name
					}
				}
			} else {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					name := strings.TrimPrefix(fields[0], "/")
					for _, ipStr := range fields[1:] {
						if net.ParseIP(ipStr) != nil {
							knownLocalIPs = append(knownLocalIPs, ipStr)
							containerIPMap[ipStr] = name
						}
					}
				} else {
					for _, ipStr := range fields {
						if net.ParseIP(ipStr) != nil {
							knownLocalIPs = append(knownLocalIPs, ipStr)
						}
					}
				}
			}
			continue
		}

		if mode == "containers" {
			parts := strings.SplitN(line, "\t", 2)
			if len(parts) >= 2 {
				containerName := strings.TrimPrefix(strings.TrimSpace(parts[0]), "/")
				if idx := strings.Index(containerName, ","); idx != -1 {
					containerName = strings.TrimSpace(containerName[:idx])
				}
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
			continue
		}

		if mode == "container_net" {
			// [[container]] names=a,b netns=net:[...] 标记后续连接归属的容器
			if strings.HasPrefix(line, "[[container]]") {
				currentContainer = containerNetNames(line)
				containerNetType = ""
				continue
			}
			if strings.HasPrefix(line, "TYPE=") {
				containerNetType = strings.TrimPrefix(line, "TYPE=")
				continue
			}

			var c RawConn
			var ok bool
			switch containerNetType {
			case "SS":
				c, ok = parseSSLine(line)
			case "NETSTAT":
				c, ok = parseNetstatLine(line)
			case "PROC":
				c, ok = parseProcLine(line)
			}
			if ok {
				c.Container = currentContainer
				conns = append(conns, c)
			}
		}
	}

	return dedupeMirrorConns(conns), meta, knownLocalIPs, dockerPortMap, containerIPMap
}

// containerNetNames 从 [[container]] 头行提取容器名（共享网络命名空间时可能为逗号分隔的多个）。
func containerNetNames(line string) string {
	for _, field := range strings.Fields(line) {
		if name, ok := strings.CutPrefix(field, "names="); ok {
			return name
		}
	}
	return ""
}

// connTupleKey 用协议与两端原始地址拼出连接元组键。
func connTupleKey(proto, localRaw, remoteRaw string) string {
	return proto + "|" + localRaw + "|" + remoteRaw
}

// dedupeMirrorConns 去除同一连接在不同网络命名空间被重复采集的镜像对（宿主视角与容器视角互为镜像），
// 保留先出现的一条：宿主视角在前，其进程归属更准确。LISTEN 无真实对端，不参与去重。
func dedupeMirrorConns(conns []RawConn) []RawConn {
	seen := make(map[string]struct{}, len(conns))
	result := make([]RawConn, 0, len(conns))
	for _, c := range conns {
		if c.State == "LISTEN" {
			result = append(result, c)
			continue
		}
		key := connTupleKey(c.Proto, c.LocalRaw, c.RemoteRaw)
		if _, dup := seen[key]; dup {
			continue
		}
		if _, mirrored := seen[connTupleKey(c.Proto, c.RemoteRaw, c.LocalRaw)]; mirrored {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, c)
	}
	return result
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
	var name string
	var pid int

	if matches := reSSProcName.FindStringSubmatch(s); len(matches) > 1 {
		name = matches[1]
	}
	if matches := reSSPID.FindStringSubmatch(s); len(matches) > 1 {
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
	// IPv4 映射地址（如 [::ffff:172.18.0.4]）归一化为点分十进制，保证容器 IP 映射表可命中
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			host = v4.String()
		}
	}
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
	if proc == "" {
		return false
	}
	switch proc {
	case "docker-proxy", "rootlessport", "slirp4netns", "pasta", "conmon", "nerdctl", "podman", "containerd-shim", "runc":
		return true
	default:
		return false
	}
}

func isDockerBridgeSubnet(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	ipv4 := ip.To4()
	if ipv4 == nil {
		return false
	}
	// Docker 常用默认子网 172.17.0.0/16 ~ 172.31.0.0/16
	if ipv4[0] == 172 && ipv4[1] >= 17 && ipv4[1] <= 31 {
		return true
	}
	return false
}

func resolveServiceProcName(rawProc, localIP string, localPort int, protoBase string, container string, dockerPortMap map[int]string, containerIPMap map[string]string) (string, bool) {
	// 0. 连接直接采自容器网络命名空间，归属最可靠
	if container != "" {
		return container, true
	}

	// 1. 本地端口命中暴露容器端口映射
	if cName, ok := dockerPortMap[localPort]; ok && cName != "" {
		return cName, true
	}

	// 2. 本地 IP 命中已知容器 IP
	if cName, ok := containerIPMap[localIP]; ok && cName != "" {
		return cName, true
	}

	// 3. 进程名是容器代理进程（docker-proxy等）
	if isContainerProxyProcess(rawProc) {
		if cName, ok := dockerPortMap[localPort]; ok && cName != "" {
			return cName, true
		}
		if rawProc != "" {
			return rawProc, true
		}
		return "docker-proxy", true
	}

	// 4. 真实业务进程名
	rawProc = strings.TrimSpace(rawProc)
	if rawProc != "" {
		return rawProc, false
	}

	return protoBase, false
}

func resolveClientProcName(rawProc, localIP string, localPort int, remoteIP string, remotePort int, protoBase string, container string, dockerPortMap map[int]string, containerIPMap map[string]string) (string, bool) {
	// 0. 连接直接采自容器网络命名空间，客户端即该容器
	if container != "" {
		return container, true
	}

	// 1. 本地 IP 命中已知容器 IP，说明该客户端来自对应容器
	if cName, ok := containerIPMap[localIP]; ok && cName != "" {
		return cName, true
	}

	// 2. 本地端口命中已知容器暴露端口
	if cName, ok := dockerPortMap[localPort]; ok && cName != "" {
		return cName, true
	}

	// 3. 进程名若为容器代理进程（docker-proxy、rootlessport、conmon、podman等）
	if isContainerProxyProcess(rawProc) {
		if cName, ok := dockerPortMap[localPort]; ok && cName != "" {
			return cName, true
		}
		if cName, ok := dockerPortMap[remotePort]; ok && cName != "" {
			return cName, true
		}
		if cName, ok := containerIPMap[remoteIP]; ok && cName != "" {
			return cName, true
		}
		if rawProc != "" {
			return rawProc, true
		}
		return "docker-proxy", true
	}

	// 4. 进程名已知且不为空
	rawProc = strings.TrimSpace(rawProc)
	if rawProc != "" {
		return rawProc, false
	}

	// 5. 若本地 IP 属于容器私网网段但未能在名称表中匹配到名字
	if isDockerBridgeSubnet(localIP) {
		return localIP, true
	}

	// 6. 兜底默认值
	return "local-client", false
}

// buildTopology 构建 [inbound_client] -> [service] 且 [local_client] -> [service / outbound] 链路拓扑
func buildTopology(hostName, hostIP string, conns []RawConn, knownLocalIPs []string, dockerPortMap map[int]string, containerIPMap map[string]string) *TopologyData {
	topo := &TopologyData{
		HostName:    hostName,
		HostIP:      hostIP,
		CollectedAt: time.Now().Format("2006-01-02 15:04:05"),
		RawConns:    conns,
	}

	// 1. 提取所有本地监听服务配置
	// 同一协议端口在宿主与容器视角各有一条 LISTEN 时，优先保留容器视角（归属更准确）。
	listeningMap := make(map[string]RawConn)
	listeningLabels := make(map[string]struct{})
	for _, c := range conns {
		if c.State == "LISTEN" || (strings.HasPrefix(c.Proto, "udp") && (c.RemotePort == 0 || c.RemoteIP == "*" || c.RemoteIP == "0.0.0.0")) {
			protoBase := getBaseProto(c.Proto)
			key := fmt.Sprintf("%s_%d", protoBase, c.LocalPort)
			if prev, ok := listeningMap[key]; !ok || (prev.Container == "" && c.Container != "") {
				listeningMap[key] = c
			}

			procName, isContainer := resolveServiceProcName(c.Process, c.LocalIP, c.LocalPort, protoBase, c.Container, dockerPortMap, containerIPMap)
			serviceLabel := fmt.Sprintf("%s:%d", procName, c.LocalPort)
			if isContainer {
				serviceLabel = "🐳 " + serviceLabel
			}
			if _, ok := listeningLabels[serviceLabel]; !ok {
				listeningLabels[serviceLabel] = struct{}{}
				topo.ListeningPorts = append(topo.ListeningPorts, serviceLabel)
			}
		}
	}
	sort.Strings(topo.ListeningPorts)

	// 2. 构建入站、内部调用与出站连接
	clientNodes := make(map[string]*GraphNode)
	localClientNodes := make(map[string]*GraphNode)
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
				// 连接自带容器归属（采自容器网络命名空间）时优先，其次用监听条目归属
				attribution := c.Container
				if attribution == "" {
					attribution = listenConn.Container
				}
				procName, isContainer := resolveServiceProcName(listenConn.Process, c.LocalIP, c.LocalPort, protoBase, attribution, dockerPortMap, containerIPMap)
				if (procName == protoBase || isContainerProxyProcess(procName)) && c.Process != "" {
					procName2, isContainer2 := resolveServiceProcName(c.Process, c.LocalIP, c.LocalPort, protoBase, attribution, dockerPortMap, containerIPMap)
					if isContainer2 || procName2 != protoBase {
						procName = procName2
						isContainer = isContainer2
					}
				}
				activeServiceNodes[srvNodeID] = &GraphNode{
					ID:          srvNodeID,
					Label:       fmt.Sprintf("%s:%d", procName, c.LocalPort),
					NodeType:    "service",
					Port:        c.LocalPort,
					Process:     procName,
					Proto:       c.Proto,
					Level:       3,
					IsContainer: isContainer,
				}
			}

			// 判断是否为本机/Docker 内部连接
			if isLocalOrContainerIP(c.RemoteIP, hostIP, knownLocalIPs) {
				// 本机/Docker 内部调用：客户端进程节点 [local_client] -> [service]
				// 注意此处客户端在连接的 remote 端，容器归属属于服务端容器，不能用于标注客户端，故传 ""
				clientProcName, isContainer := resolveClientProcName(c.Process, c.RemoteIP, c.RemotePort, c.LocalIP, c.LocalPort, protoBase, "", dockerPortMap, containerIPMap)
				if clientProcName == "local-client" && c.Process != "" && !isContainerProxyProcess(c.Process) {
					clientProcName = c.Process
				}
				clientProcID := fmt.Sprintf("clientproc_%s", sanitizeNodeID(clientProcName))
				if _, exists := localClientNodes[clientProcID]; !exists {
					localClientNodes[clientProcID] = &GraphNode{
						ID:          clientProcID,
						Label:       clientProcName,
						NodeType:    "local_client",
						Process:     clientProcName,
						Level:       2,
						IsContainer: isContainer,
					}
				}

				edgeID := fmt.Sprintf("edge_internal_%s_%s_%s", clientProcID, srvNodeID, protoBase)
				if edge, exists := edgeMap[edgeID]; exists {
					edge.ConnCount++
					edge.Details = append(edge.Details, c)
				} else {
					edgeMap[edgeID] = &GraphEdge{
						ID:        edgeID,
						Source:    clientProcID,
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
			// 发起方连接：客户端进程作为 Source；容器网络命名空间内采集的连接，发起方即该容器
			clientProcName, isContainer := resolveClientProcName(c.Process, c.LocalIP, c.LocalPort, c.RemoteIP, c.RemotePort, protoBase, c.Container, dockerPortMap, containerIPMap)
			clientProcID := fmt.Sprintf("clientproc_%s", sanitizeNodeID(clientProcName))
			if _, exists := localClientNodes[clientProcID]; !exists {
				localClientNodes[clientProcID] = &GraphNode{
					ID:          clientProcID,
					Label:       clientProcName,
					NodeType:    "local_client",
					Process:     clientProcName,
					Level:       2,
					IsContainer: isContainer,
				}
			}

			// B. 判断出站 remoteIP 是否为本机或 Docker IP
			if isLocalOrContainerIP(c.RemoteIP, hostIP, knownLocalIPs) {
				// 本机进程主动连接本机或 Docker 内部服务：归入内部调用 [clientproc] -> [service]
				srvNodeID := fmt.Sprintf("srv_%s_%d", protoBase, c.RemotePort)
				if _, exists := activeServiceNodes[srvNodeID]; !exists {
					procName, isContainerSrv := resolveServiceProcName("", c.RemoteIP, c.RemotePort, protoBase, "", dockerPortMap, containerIPMap)
					targetKey := fmt.Sprintf("%s_%d", protoBase, c.RemotePort)
					if listenConn, ok := listeningMap[targetKey]; ok {
						procName, isContainerSrv = resolveServiceProcName(listenConn.Process, c.RemoteIP, c.RemotePort, protoBase, listenConn.Container, dockerPortMap, containerIPMap)
					}
					activeServiceNodes[srvNodeID] = &GraphNode{
						ID:          srvNodeID,
						Label:       fmt.Sprintf("%s:%d", procName, c.RemotePort),
						NodeType:    "service",
						Port:        c.RemotePort,
						Process:     procName,
						Proto:       c.Proto,
						Level:       3,
						IsContainer: isContainerSrv,
					}
				}

				edgeID := fmt.Sprintf("edge_internal_%s_%s_%s", clientProcID, srvNodeID, protoBase)
				if edge, exists := edgeMap[edgeID]; exists {
					edge.ConnCount++
					edge.Details = append(edge.Details, c)
				} else {
					edgeMap[edgeID] = &GraphEdge{
						ID:        edgeID,
						Source:    clientProcID,
						Target:    srvNodeID,
						EdgeType:  "internal",
						Proto:     c.Proto,
						ConnCount: 1,
						Details:   []RawConn{c},
					}
				}
			} else {
				// 真正的外部出站外联链路：[clientproc] -> [tcp://remoteip:port]
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

				edgeID := fmt.Sprintf("edge_%s_%s_%s", clientProcID, outboundID, protoBase)
				if edge, exists := edgeMap[edgeID]; exists {
					edge.ConnCount++
					edge.Details = append(edge.Details, c)
				} else {
					edgeMap[edgeID] = &GraphEdge{
						ID:        edgeID,
						Source:    clientProcID,
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

	// 3. 将激活的服务进程节点与客户端进程节点加入节点列表
	for _, node := range clientNodes {
		topo.Nodes = append(topo.Nodes, *node)
	}
	for _, node := range localClientNodes {
		topo.Nodes = append(topo.Nodes, *node)
	}
	for _, node := range activeServiceNodes {
		topo.Nodes = append(topo.Nodes, *node)
	}
	for _, node := range outboundNodes {
		topo.Nodes = append(topo.Nodes, *node)
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
			stateStr := "ESTAB"
			if len(edge.Details) > 0 {
				s := edge.Details[0].State
				if s == "ESTABLISHED" {
					s = "ESTAB"
				}
				stateStr = s
			}
			protoBase := getBaseProto(edge.Proto)
			if edge.ConnCount > 1 {
				edge.Label = fmt.Sprintf("%d local (%s %s)", edge.ConnCount, protoBase, stateStr)
			} else {
				edge.Label = fmt.Sprintf("local (%s %s)", protoBase, stateStr)
			}
		} else if edge.EdgeType == "outbound" {
			stateStr := "ESTAB"
			if len(edge.Details) > 0 {
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
		}
		topo.Edges = append(topo.Edges, *edge)
	}

	sort.Slice(topo.Nodes, func(i, j int) bool {
		return topo.Nodes[i].ID < topo.Nodes[j].ID
	})
	sort.Slice(topo.Edges, func(i, j int) bool {
		return topo.Edges[i].ID < topo.Edges[j].ID
	})

	topo.Summary.ListeningCount = len(listeningMap)
	topo.Summary.InboundClients = len(clientNodes)
	topo.Summary.LocalClients = len(localClientNodes)
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
	return reSanitizeID.ReplaceAllString(s, "_")
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

func renderGraphPageHTML(hostName, hostIP string, defaultIntervalSec int, defaultAggregateThreshold ...int) string {
	threshold := graphAggregateDefault
	if len(defaultAggregateThreshold) > 0 && defaultAggregateThreshold[0] > 0 {
		threshold = defaultAggregateThreshold[0]
	}

	var sb strings.Builder
	data := map[string]interface{}{
		"HostName":                  hostName,
		"HostIP":                    hostIP,
		"DefaultIntervalSec":        defaultIntervalSec,
		"DefaultAggregateThreshold": threshold,
	}
	_ = graphPageTmpl.Execute(&sb, data)
	return sb.String()
}

//go:embed graph.html
var graphPageTemplate string

var graphPageTmpl = template.Must(template.New("graph_page").Parse(graphPageTemplate))

// cosmosJS 是内嵌的 cosmos.gl (https://cosmos.gl, MIT License, 见 cosmos.LICENSE)
// UMD 构建，由本地 Web 服务直接吐出，页面渲染不依赖外部 CDN。
//
//go:embed cosmos.min.js
var cosmosJS string
