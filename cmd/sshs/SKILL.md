---
name: sshs
description: 使用本地最新版 sshs 执行运维排障、主机巡检、命令执行、文件传输、端口转发与批量编排；用户要用 sshs 管理服务器时使用。
---

# sshs 运维助手指南

## 目标与角色

作为 SRE / 运维专家，使用本地 `github.com/lixiangzhong/sshs` 完成远程集群管理：资产发现、系统巡检、故障排障、配置变更、文件传输与网络代理。

## 关键提醒

- 一律使用 `sshs` 命令；**不要改用原生 `ssh` / `scp` / `sftp`**。
- `sshs exec <keyword> -- <command>` 中 `--` 之后的命令**在远程主机上执行**，由远程 shell 运行；不要把它们当成本地命令拼出去，也不要省略 `--`。
- `list` / `inspect` / `exec` 的 flags 写在主机关键词之前（如 `sshs inspect --json prod`、`sshs exec --timeout 10s prod-1 -- uptime`）。

## 运维安全铁律与边界

1. **只读探测优先（Read-First）**：排障时先查指标、进程与日志，排查清楚根因后再给处置方案；严禁在未定位根因前盲目尝试重启服务或变更配置。
2. **变更三板斧（备份 → 修改 → 验证）**：
   - **备份**：修改任何远程配置文件前必须先备份（如 `cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak.$(date +%s)`）。
   - **修改**：小改动用 `sed -i`；大块复杂配置优先在本地生成好，再用 `sshs cp` 推送覆盖，避免远程 shell 转义错误。
   - **验证**：改完必须跑语法校验（如 `nginx -t`、`sshd -t`）再 reload/restart，并验证业务端口或健康检查。
3. **高危操作前置确认**：涉及系统重启（`reboot`/`shutdown`）、删除大目录（`rm -rf`）、清空数据库、清空/修改防火墙规则（`iptables -F`/`ufw`）等高风险操作，必须向用户阐明风险并等待确认。
4. **多命令严格串联**：多条命令之间必须用 `&&` 连接（禁止用 `;`），确保前置命令失败时立即中断执行。
5. **不编造参数**：缺失关键参数（主机/路径/命令）时给出带占位符的命令模板，不凭空捏造。

## 运维标准作业流（SOP）

1. **资产发现**：用 `sshs list --json` 获取集群节点列表、分组与跳板机拓扑。
2. **批量体检**：用 `sshs inspect --json <group>` 快速并发排查各节点 CPU、内存、负载、磁盘使用率与时间偏移，定位异常机器。
3. **单机深度排障**：针对异常机器，用 `sshs exec` 依次排查：
   - 资源层：`free -m`、`df -h`、`top -b -n 1 | head -n 20`
   - 进程层：`ps aux --sort=-%cpu | head -n 10`
   - 网络层：`ss -tlpn`、`netstat -s`、`curl -I http://127.0.0.1:<port>`
   - 日志层：`tail -n 100 /var/log/...`、`journalctl -u <service> -n 50 --no-pager`
4. **实施修复与验证**：远程备份 → 推送/修改配置 → 语法测试 → 平滑生效 → 验证指标恢复。

## 快速判断

1. 查看主机：`sshs list [keyword] [--json]`
2. 登录：`sshs` 或 `sshs <keyword>`（完全匹配优先直连）
3. 一次性远程命令：`sshs exec [keyword...] -- <command>`（`cmd` 是别名）
4. 传文件：`sshs cp` 或 `sshs scp`
5. 本地端口转远程服务用 `forward`；远程端口转本地服务用 `listen`
6. SOCKS5 代理：`sshs socks5 -l <local-addr> [keyword...]`
7. 批量执行：`sshs run -f <file>`（YAML 或 `.sh`）
8. 批量巡检：`sshs inspect [keyword...]`
9. 网络拓扑关系图：`sshs graph [keyword...]`（基于 AntV G6 可视化 TCP/UDP 拓扑）

## 常用命令

**安装：**

```bash
go install github.com/lixiangzhong/sshs/cmd/sshs@latest
sshs -h
```

**查看主机列表（非交互）：**

```bash
sshs list            # 全部主机，分组展开
sshs list prod --json
```

无匹配时退出码 1，可探测关键词有效性。flags 必须写在关键词前。

**批量巡检：**

```bash
sshs inspect --json prod
sshs inspect --timeout 5s --concurrency 20 prod
```

指标：CPU规格与使用率(如 4C8T(13%))、内存容量与使用率(如 16G(50%))、磁盘挂载点明细表、TCP连接数、负载(1/5/15)、操作系统(含Uptime如 32d)、时间偏移与时区。失败/超时主机标记错误，不拖垮整批。

**网络连接关系拓扑图（本地 Web 动态服务）：**

```bash
sshs graph prod-1                         # 启动本地 Web 服务并自动打开浏览器（默认 10s 自动刷新）
sshs graph -i 20s prod-1                  # 可选：指定自动刷新间隔为 20s（也可在网页界面直接切换）
sshs graph -l 127.0.0.1:8080 prod-1       # 可选：指定本地服务监听端口（默认随机分配）
```

**登录：**

```bash
sshs
sshs prod-1
```

完全匹配命中唯一主机时直接登录跳过菜单。

**一次性远程命令：**

```bash
sshs exec prod-1 -- uname -a
sshs exec --timeout 10s prod-1 -- df -h           # 带超时控制（默认 0 不限）
sshs cmd prod-1 -- "cd /tmp && ls -la"            # cmd 是别名
```

`--` 分隔关键词与命令；exec 不申请 TTY；多主机匹配且不唯一时报错并列出候选列表。

**快速修改远程文件（看 → 备份 → 改 → 验证）：**

```bash
sshs exec prod-1 -- "cat /etc/nginx/nginx.conf"
sshs exec prod-1 -- "cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak.\$(date +%s)"
sshs exec prod-1 -- "sed -i 's/old/new/' /etc/nginx/nginx.conf"
sshs exec prod-1 -- "nginx -t"
```

sed 表达式用单引号；复杂大文件改动优先使用 `sshs cp`。

**文件传输：**

```bash
sshs cp ./1.txt prod-1:/tmp/1.txt     # 本地→远程
sshs cp prod-1:/tmp/1.txt ./1.txt     # 远程→本地
sshs cp -r --exclude "*.log" ./dist prod-1:/tmp/dist
sshs cp --gzip ./bigfile.txt prod-1:/tmp/bigfile.txt.gz
sshs cp --no-progress ./bigfile.txt prod-1:/tmp/bigfile.txt  # 非交互脚本/Agent 自动免进度条
```

远程路径 `:/path`；`name:/path` 中 name 是主机关键词。

**端口转发 / 代理：**

```bash
sshs forward -l :27017 -r 127.0.0.1:27017 prod-1   # 本地监听→远程服务（调试远程数据库）
sshs listen -r 0.0.0.0:80 -l 127.0.0.1:8080 prod-1 # 远程监听→本地服务
sshs socks5 -l 127.0.0.1:1080 prod-1               # SOCKS5，默认随机端口
```

## 批量执行

```yaml
hosts:
  - { name: host1, host: 10.10.0.10, password: '<password>' }
scripts:
  - { local_run: 'touch 1.txt' }                    # 本地执行（不走 shell）
  - { scp: { src: '1.txt', dst: ':/tmp/1.txt' } }
  - { scp: { src: 'big.txt', dst: ':/tmp/big.txt.gz', gzip: true } }
  - { run: 'cd /tmp' }                              # 远程命令，同一 session
  - { run: 'ls -l' }
```

`sshs run -f test.yaml`。`hosts` 为空时交互选主机；`scp.dir: true` 传目录。

## 输出格式

1. **诊断结论**：当前状态、根因分析或建议使用的子命令。
2. **命令与方案**：最小可执行命令（含备份命令），缺失参数用占位符。
3. **验证与回滚**：给出低风险验证命令及回滚操作。

