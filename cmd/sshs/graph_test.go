package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/urfave/cli/v2"
)

func TestGraphDefaultsToTenSecondRefresh(t *testing.T) {
	if graphIntervalDefault != 10*time.Second {
		t.Fatalf("graphIntervalDefault = %v, want 10s", graphIntervalDefault)
	}
}

func TestParseSSLine(t *testing.T) {
	// TCP Listen
	l1 := `tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=853,fd=3))`
	c1, ok1 := parseSSLine(l1)
	if !ok1 {
		t.Fatalf("failed to parse ss listen line")
	}
	if c1.Proto != "tcp" || c1.State != "LISTEN" || c1.LocalPort != 22 || c1.Process != "sshd" || c1.PID != 853 {
		t.Errorf("unexpected parsed conn: %+v", c1)
	}

	// TCP Established
	l2 := `tcp ESTAB 0 0 192.168.1.100:22 192.168.1.50:51234 users:(("sshd",pid=1234,fd=4))`
	c2, ok2 := parseSSLine(l2)
	if !ok2 {
		t.Fatalf("failed to parse ss estab line")
	}
	if c2.Proto != "tcp" || c2.State != "ESTABLISHED" || c2.LocalIP != "192.168.1.100" || c2.LocalPort != 22 ||
		c2.RemoteIP != "192.168.1.50" || c2.RemotePort != 51234 || c2.Process != "sshd" || c2.PID != 1234 {
		t.Errorf("unexpected parsed conn: %+v", c2)
	}

	// UDP Unconnected
	l3 := `udp UNCONN 0 0 0.0.0.0:53 0.0.0.0:* users:(("named",pid=450,fd=5))`
	c3, ok3 := parseSSLine(l3)
	if !ok3 {
		t.Fatalf("failed to parse ss udp line")
	}
	if c3.Proto != "udp" || c3.LocalPort != 53 || c3.Process != "named" {
		t.Errorf("unexpected parsed conn: %+v", c3)
	}
}

func TestParseNetstatLine(t *testing.T) {
	// netstat tcp listen
	l1 := `tcp 0 0 0.0.0.0:80 0.0.0.0:* LISTEN 1024/nginx`
	c1, ok1 := parseNetstatLine(l1)
	if !ok1 {
		t.Fatalf("failed to parse netstat listen line")
	}
	if c1.Proto != "tcp" || c1.State != "LISTEN" || c1.LocalPort != 80 || c1.Process != "nginx" || c1.PID != 1024 {
		t.Errorf("unexpected parsed netstat conn: %+v", c1)
	}

	// netstat tcp established
	l2 := `tcp 0 0 10.0.0.2:45678 10.0.0.5:6379 ESTABLISHED 2048/app`
	c2, ok2 := parseNetstatLine(l2)
	if !ok2 {
		t.Fatalf("failed to parse netstat estab line")
	}
	if c2.Proto != "tcp" || c2.State != "ESTABLISHED" || c2.LocalPort != 45678 || c2.RemoteIP != "10.0.0.5" || c2.RemotePort != 6379 || c2.Process != "app" || c2.PID != 2048 {
		t.Errorf("unexpected parsed netstat conn: %+v", c2)
	}
}

func TestParseNetstatLineRejectsShortInput(t *testing.T) {
	if conn, ok := parseNetstatLine("tcp 0 0 127.0.0.1:22"); ok {
		t.Fatalf("parseNetstatLine() = %+v, true; want zero value, false", conn)
	}
}

func TestParseProcLine(t *testing.T) {
	// /proc/net/tcp format: proto|local_hex|remote_hex|state_hex|inode
	// 0100007F:0050 -> 127.0.0.1:80
	// 00000000:0000 -> 0.0.0.0:0
	// 0A -> LISTEN
	l1 := `tcp|0100007F:0050|00000000:0000|0A|12345`
	c1, ok1 := parseProcLine(l1)
	if !ok1 {
		t.Fatalf("failed to parse proc line")
	}
	if c1.Proto != "tcp" || c1.State != "LISTEN" || c1.LocalIP != "127.0.0.1" || c1.LocalPort != 80 {
		t.Errorf("unexpected proc conn: %+v", c1)
	}
}

func TestBuildTopology(t *testing.T) {
	rawOutput := `
===META===
hostname=app-server-01

===IPS===
192.168.1.10 172.17.0.1

	===CONTAINERS===
	redis-cluster	0.0.0.0:6379->6379/tcp
	mysql-db	0.0.0.0:3306->3306/tcp

	===CONTAINER_IPS===
	client-worker|1001|172.17.0.3|
	mysql-db|1002|172.17.0.2|3306

===NET===
TYPE=SS
tcp LISTEN 0 128 0.0.0.0:80 0.0.0.0:* users:(("nginx",pid=100,fd=3))
tcp LISTEN 0 128 0.0.0.0:3306 0.0.0.0:* users:(("rootlessport",pid=105,fd=3))
tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=200,fd=3))
tcp ESTAB  0 0 192.168.1.10:80 192.168.1.50:50001 users:(("nginx",pid=101,fd=4))
tcp ESTAB  0 0 192.168.1.10:80 192.168.1.50:50002 users:(("nginx",pid=101,fd=5))
tcp ESTAB  0 0 192.168.1.10:80 192.168.1.51:50003 users:(("nginx",pid=101,fd=6))
tcp ESTAB  0 0 127.0.0.1:3306 127.0.0.1:45678 users:(("rootlessport",pid=105,fd=4))
tcp ESTAB  0 0 192.168.1.10:45678 172.17.0.2:6379 users:(("my-app",pid=300,fd=8))
tcp ESTAB  0 0 192.168.1.10:34567 10.0.0.2:6379 users:(("my-app",pid=300,fd=7))
tcp ESTAB  0 0 172.17.0.3:55555 10.0.0.9:8080 users:(("docker-proxy",pid=999,fd=3))
udp UNCONN 0 0 0.0.0.0:53 0.0.0.0:* users:(("named",pid=400,fd=8))
`
	conns, meta, knownLocalIPs, dockerPortMap, containerIPMap := parseGraphCollectOutput(rawOutput)
	if meta["hostname"] != "app-server-01" {
		t.Errorf("meta hostname = %q, want app-server-01", meta["hostname"])
	}
	if dockerPortMap[3306] != "mysql-db" || dockerPortMap[6379] != "redis-cluster" {
		t.Errorf("unexpected dockerPortMap: %+v", dockerPortMap)
	}
	if containerIPMap["172.17.0.3"] != "client-worker" {
		t.Errorf("containerIPMap[172.17.0.3] = %q, want client-worker", containerIPMap["172.17.0.3"])
	}

	topo := buildTopology(meta["hostname"], "192.168.1.10", conns, knownLocalIPs, dockerPortMap, containerIPMap)

	if topo.Summary.TotalConns != 11 {
		t.Errorf("total conns = %d, want 11", topo.Summary.TotalConns)
	}
	if topo.Summary.ListeningCount != 4 { // nginx:80, mysql-db:3306, sshd:22, named:53
		t.Errorf("listening count = %d, want 4", topo.Summary.ListeningCount)
	}
	if topo.Summary.InboundClients != 2 { // 2 distinct external remote IPs: 192.168.1.50, 192.168.1.51
		t.Errorf("inbound clients = %d, want 2", topo.Summary.InboundClients)
	}
	if topo.Summary.LocalClients < 2 {
		t.Errorf("local clients = %d, want >= 2", topo.Summary.LocalClients)
	}
	if topo.Summary.OutboundCount != 2 { // 10.0.0.2:6379 和 10.0.0.9:8080
		t.Errorf("outbound count = %d, want 2", topo.Summary.OutboundCount)
	}

	// 验证 127.0.0.1 和 172.17.0.2 不会生成外部 client/outbound 节点
	for _, node := range topo.Nodes {
		if strings.Contains(node.ID, "127_0_0_1") || strings.Contains(node.ID, "outbound_tcp_172_17_0_2") {
			t.Errorf("local/docker IP should not produce external client/outbound node: %s", node.ID)
		}
	}

	// 验证有活跃连接的服务节点 [nginx:80], [mysqld:3306], [6379] 与客户端进程节点 [my-app], [client-worker] 存在
	var nginxFound, mysqlFound, dockerRedisFound, sshdFound, namedFound, myAppClientFound, containerClientFound bool
	for _, node := range topo.Nodes {
		if node.ID == "srv_tcp_80" {
			nginxFound = true
			if node.IsContainer {
				t.Errorf("expected srv_tcp_80 IsContainer = false")
			}
		}
		if node.ID == "srv_tcp_3306" {
			mysqlFound = true
			if node.Process != "mysql-db" || node.Label != "mysql-db:3306" {
				t.Errorf("srv_tcp_3306 process = %q label = %q, want mysql-db & mysql-db:3306", node.Process, node.Label)
			}
			if !node.IsContainer {
				t.Errorf("expected srv_tcp_3306 IsContainer = true")
			}
		}
		if node.ID == "srv_tcp_6379" {
			dockerRedisFound = true
		}
		if node.ID == "srv_tcp_22" {
			sshdFound = true
		}
		if node.ID == "srv_udp_53" {
			namedFound = true
		}
		if node.ID == "clientproc_my_app" {
			myAppClientFound = true
			if node.NodeType != "local_client" {
				t.Errorf("expected nodeType = local_client, got %q", node.NodeType)
			}
		}
		if node.ID == "clientproc_client_worker" {
			containerClientFound = true
			if node.NodeType != "local_client" {
				t.Errorf("expected nodeType = local_client, got %q", node.NodeType)
			}
			if !node.IsContainer {
				t.Errorf("expected container client IsContainer = true")
			}
		}
	}
	if !nginxFound {
		t.Errorf("expected active service node srv_tcp_80 not found")
	}
	if !mysqlFound {
		t.Errorf("expected active internal service node srv_tcp_3306 not found")
	}
	if !dockerRedisFound {
		t.Errorf("expected docker internal service node srv_tcp_6379 not found")
	}
	if !myAppClientFound {
		t.Errorf("expected client process node clientproc_my_app not found")
	}
	if !containerClientFound {
		t.Errorf("expected container client process node clientproc_client_worker not found")
	}
	if sshdFound {
		t.Errorf("expected inactive service node srv_tcp_22 to be omitted")
	}
	if namedFound {
		t.Errorf("expected inactive service node srv_udp_53 to be omitted")
	}

	// 验证内部连接：从客户端进程 [my-app] -> [srv_tcp_6379] 建立 internal 边
	var internalRedisEdgeFound bool
	for _, edge := range topo.Edges {
		if edge.Source == "clientproc_my_app" && edge.Target == "srv_tcp_6379" && edge.EdgeType == "internal" {
			internalRedisEdgeFound = true
		}
	}
	if !internalRedisEdgeFound {
		t.Errorf("expected direct internal edge [my-app] -> [srv_tcp_6379] not found")
	}

	// 验证出站连接：从客户端进程 [my-app] -> [outbound] 建立 outbound 边
	var outboundRedisEdgeFound bool
	for _, edge := range topo.Edges {
		if edge.Source == "clientproc_my_app" && edge.Target == "outbound_tcp_10_0_0_2_6379" && edge.EdgeType == "outbound" {
			outboundRedisEdgeFound = true
		}
	}
	if !outboundRedisEdgeFound {
		t.Errorf("expected outbound edge [my-app] -> [outbound_tcp_10_0_0_2_6379] not found")
	}

	// 验证链路：[192.168.1.50] -> [nginx:80] 只有 1 条边，连接数显示 2 conns
	var client50Edge *GraphEdge
	for _, edge := range topo.Edges {
		if edge.Source == "client_192_168_1_50" && edge.Target == "srv_tcp_80" {
			client50Edge = &edge
		}
		if edge.EdgeType == "listen" {
			t.Errorf("listen should not produce any edge, but found: %+v", edge)
		}
	}
	if client50Edge == nil {
		t.Fatalf("expected single aggregated edge for client 192.168.1.50 -> nginx:80 not found")
	}
	if client50Edge.ConnCount != 2 {
		t.Errorf("client 192.168.1.50 edge connCount = %d, want 2", client50Edge.ConnCount)
	}
	if !strings.Contains(client50Edge.Label, "2 conns") {
		t.Errorf("client 192.168.1.50 edge label = %q, want containing '2 conns'", client50Edge.Label)
	}

	// 检查动态 HTML 模板渲染
	html := renderDynamicG6HTML(topo.HostName, topo.HostIP, 10)
	if !strings.Contains(html, "app-server-01") || !strings.Contains(html, "antv/g6") || !strings.Contains(html, "/api/topology") {
		t.Errorf("rendered HTML missing expected keywords or api endpoint")
	}
	if !strings.Contains(html, "escapeHTML") || !strings.Contains(html, "/api/interval") || !strings.Contains(html, "combo_local_clients") || !strings.Contains(html, "toggleLayout") || !strings.Contains(html, "nodeClusterBy") {
		t.Errorf("rendered HTML missing safe detail rendering, interval update endpoint, combo_local_clients, or toggleLayout/nodeClusterBy")
	}
	for _, escapedExpression := range []string{
		"escapeHTML(model.process)",
		"escapeHTML(peer.label)",
		"escapeHTML(p)",
		"escapeHTML(d.local_raw)",
	} {
		if !strings.Contains(html, escapedExpression) {
			t.Errorf("rendered HTML missing %q", escapedExpression)
		}
	}
}

func TestBuildTopologyDoesNotGuessPrivateNetworksAreLocal(t *testing.T) {
	connections := []RawConn{
		{
			Proto:      "tcp",
			State:      "ESTABLISHED",
			LocalIP:    "10.0.0.10",
			LocalPort:  42000,
			RemoteIP:   "172.20.30.40",
			RemotePort: 5432,
		},
	}

	topology := buildTopology("app", "10.0.0.10", connections, []string{"10.0.0.10"}, nil, nil)
	if topology.Summary.OutboundCount != 1 {
		t.Fatalf("outbound count = %d, want 1 for an uncollected private address", topology.Summary.OutboundCount)
	}
	if topology.Edges[0].EdgeType != "outbound" {
		t.Fatalf("edge type = %q, want outbound", topology.Edges[0].EdgeType)
	}
}

func TestGraphIntervalHandler(t *testing.T) {
	server := newGraphServer(Config{}, graphTimeoutDefault, graphIntervalDefault)
	handler := newGraphHTTPHandler(server, Config{})

	request := httptest.NewRequest(http.MethodPost, "/api/interval", strings.NewReader(`{"interval":20}`))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %q", response.Code, http.StatusOK, response.Body.String())
	}
	if interval := server.getInterval(); interval != 20*time.Second {
		t.Fatalf("server interval = %v, want 20s", interval)
	}
}

func TestGraphIntervalHandlerRejectsInvalidRequests(t *testing.T) {
	testCases := []struct {
		name   string
		method string
		body   string
		status int
	}{
		{name: "too short", method: http.MethodPost, body: `{"interval":1}`, status: http.StatusBadRequest},
		{name: "negative", method: http.MethodPost, body: `{"interval":-1}`, status: http.StatusBadRequest},
		{name: "overflow", method: http.MethodPost, body: `{"interval":9223372037}`, status: http.StatusBadRequest},
		{name: "unknown field", method: http.MethodPost, body: `{"interval":10,"extra":true}`, status: http.StatusBadRequest},
		{name: "wrong method", method: http.MethodGet, status: http.StatusMethodNotAllowed},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			server := newGraphServer(Config{}, graphTimeoutDefault, graphIntervalDefault)
			handler := newGraphHTTPHandler(server, Config{})
			request := httptest.NewRequest(testCase.method, "/api/interval", strings.NewReader(testCase.body))
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, request)
			if response.Code != testCase.status {
				t.Fatalf("status = %d, want %d; body = %q", response.Code, testCase.status, response.Body.String())
			}
		})
	}
}

func TestGraphCommandAliases(t *testing.T) {
	app := newApp()
	var graphCmd *cli.Command
	for _, cmd := range app.Commands {
		if cmd.Name == "graph" {
			graphCmd = cmd
			break
		}
	}
	if graphCmd == nil {
		t.Fatalf("graph command not found in app commands")
	}

	expectedAliases := map[string]bool{"g": true, "topo": true}
	if len(graphCmd.Aliases) != len(expectedAliases) {
		t.Fatalf("graph command aliases len = %d, want %d: %v", len(graphCmd.Aliases), len(expectedAliases), graphCmd.Aliases)
	}
	for _, alias := range graphCmd.Aliases {
		if !expectedAliases[alias] {
			t.Errorf("unexpected alias for graph command: %q", alias)
		}
	}
}
