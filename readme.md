# sshs

不想反复输入 ssh、scp 密码时，可以用 `sshs` 通过配置文件管理主机，并完成 ssh 登录、文件传输、端口转发、SOCKS5 代理、批量命令执行，以及非交互的主机列表查看（list）与批量巡检（inspect）。

本项目 terminal ui 参考了 https://github.com/yinheli/sshw

## install

```sh
go install github.com/lixiangzhong/sshs/cmd/sshs@latest
```

或从 [GitHub Releases](https://github.com/lixiangzhong/sshs/releases) 下载对应平台的二进制（linux/darwin/windows × amd64/arm64），解压后放入 PATH 即可。

## configuration

`sshs` 会依次查找当前目录和用户家目录下的配置文件：

- `.sshs.yaml`
- `sshs.yaml`
- `.sshw.yaml`
- `sshw.yaml`

常用方式：

```sh
vi ~/.sshs.yaml
```

配置示例：

```yaml
- { name: server1, host: 10.10.0.1, password: 123456 } # 默认 user: root, port: 22
- { name: server2, host: 10.10.0.2, port: 2222, user: root, password: 123456 }
- {
    name: server3,
    host: 10.10.0.3,
    port: 2222,
    keypath: ~/.ssh/server3.key,
    passphrase: abcdefghijk,
  } # 使用私钥 + passphrase
- name: group_name1
  children:
    - { name: server4, host: 10.10.0.4, password: 123456 }
    - { name: server5, host: 10.10.0.5, password: 123456 }
- {
    name: server6,
    host: 10.10.0.2,
    port: 2222,
    user: root,
    password: 123456,
    jumper: { host: 10.10.0.1, password: 123456 },
  } # 使用跳板机
```

> 配置里没写 `password` 的主机（含跳板机）会回退读取系统钥匙串中的 `default-password`：
>
> ```sh
> # macOS: 写入系统钥匙串（一次性设置即可，service 为 sshs，account 为 default-password）
> security add-generic-password -U -s sshs -a default-password -w "YOUR_PASSWORD"
> ```
>
> 配置中写明的 `password` 优先；未配置钥匙串默认密码时行为不变。
> 该回退只支持系统钥匙串：无桌面的 Linux 服务器请在配置中直接写 `password`（可用主口令加密为 `ENC(v1:...)`）。

### 密码加密与安全防护

为了防止 AI Agent 或其他第三方应用扫描读取配置文件中的明文密码，支持使用主口令将密码加密存储为 `ENC(v1:...)`。主口令按以下优先级读取，保存时优先系统钥匙串、不可用则自动落盘 0600 文件：

| 优先级 | 主密码后端 | 适用场景 |
| --- | --- | --- |
| 1 | `SSHS_MASTER_KEY` 环境变量 | MCP / CI 等需要临时注入、不落盘的场景 |
| 2 | 系统钥匙串（macOS Keychain / Linux Secret Service） | macOS、带桌面的 Linux |
| 3 | 主密码文件（`SSHS_MASTER_KEY_FILE`，默认 `~/.config/sshs/master-key`，权限 0600） | 无桌面的 Linux 服务器、容器 |

```sh
# 1. 自动加密与日常使用：无需手动执行加密命令
#    - 使用 `sshs edit` 编辑保存时，自动全量加密落盘；
#    - 外部手动修改配置写入明文后，执行任何 sshs 命令退出时，系统均会自动将明文加密存盘；
#    - 日常使用完全免密秒连（自动从主密码后端静默获取主口令并在内存解密）。
sshs server1
sshs exec server1 -- uptime

# 2. 主口令维护管理
sshs master-key status      # 查看主口令是否已配置及当前来源（环境变量/钥匙串/文件）
sshs master-key set         # 交互式设置；钥匙串不可用时自动落盘 0600 文件
printf '%s\n' "$KEY" | sshs master-key set   # 非交互场景：走 stdin 管道，避免主密码进入 shell history
sshs master-key delete      # 清除钥匙串与文件中的主口令

# 3. 自动化场景：用环境变量指定主密码或密钥文件位置（不落盘）
SSHS_MASTER_KEY="$KEY" sshs list
SSHS_MASTER_KEY_FILE=/run/secrets/sshs-master sshs list
```

#### Linux / 无桌面服务器（headless）

Linux 的系统钥匙串依赖 Secret Service（D-Bus），无桌面的服务器、容器以及非交互 SSH 会话中通常不存在该服务。此时 `sshs` 会自动降级到 0600 主密码文件，无需额外配置，也不会阻塞任何命令：

```sh
# 首次设置：写入 ~/.config/sshs/master-key（0600）
sshs master-key set

# 之后所有非交互调用（脚本、Agent、ssh host 'sshs ...'）静默可用
sshs list
sshs exec web -- uptime
```

安全边界：主密码文件与 SSH 私钥同级，只防止"顺手扫描配置文件的工具/Agent"，不防止能读取当前用户 home 的进程。需要更强隔离时，把主密码放到独立 secret（如 `/run/secrets/`、Docker secret、systemd credential）并用 `SSHS_MASTER_KEY_FILE` 指向它，或让 Agent 以独立用户运行。

## Usage

### 查看主机列表

非交互列出匹配的主机，可用于脚本或快速查看有哪些主机可用：

```sh
# 列出全部主机（分组会展开）
sshs list

# 用关键词过滤，规则与登录/exec 一致（匹配 name/user/host:port）
sshs list server1

# 输出 JSON，供脚本解析
sshs list --json
```

展示 `NAME`（含分组前缀）、`USER`、`HOST:PORT`、`AUTH`（认证方式）、`JUMPER`（跳板机链）。无匹配主机时退出码为 1。

### 批量巡检主机

对一批主机批量采集系统指标并汇总，`inspect` 非交互运行，可用于脚本或快速扫状态：

```sh
# 巡检全部主机，输出概览表 + 磁盘明细表
sshs inspect

# 用关键词过滤目标主机
sshs inspect prod

# 输出 JSON，供脚本解析
sshs inspect --json

# 控制单台超时（默认 10s）与并发数（默认 10）
sshs inspect --timeout 5s --concurrency 20 prod
```

巡检指标：负载(1/5/15)、CPU 使用率、内存使用率、磁盘使用率（最大挂载点入概览，明细表逐挂载点）、内核与发行版、与本地的时间偏移。单台拨号或采集失败会在对应行标记错误，超时标记为 `timeout`，不影响整批。

注意：带主机关键词的子命令必须把 flags 写在关键词之前，例如 `sshs inspect --json prod`、`sshs graph -i 20s prod`。

### 网络连接关系拓扑图 (graph)

连接目标主机采集 TCP/UDP 网络连接（端口、状态、进程、客户端与出站连接），以本地随机端口启动轻量 Web 服务，提供基于 cosmos.gl（WebGL GPU 渲染，JS 已内嵌、离线可用）的交互式拓扑页面与 `/api/topology` 动态接口，并按指定时间间隔（默认 30 秒）自动定时刷新：

```sh
# 启动本地 Web 服务并在默认浏览器打开（默认 30s 自动刷新，聚合阈值默认 3）
sshs graph server1

# 可选：指定自动刷新间隔为 10 秒
sshs graph -i 10s server1

# 可选：指定连接聚合阈值（默认 3，同一对端连接达到此值聚合为单条加粗边）
sshs graph -a 5 server1

# 可选：指定本地服务监听端口（默认随机分配）
sshs graph -l 127.0.0.1:8080 server1

# 可选：只采集一次并以 JSON 输出拓扑数据（不启动 Web 服务），便于脚本/管道消费
sshs graph --json server1
sshs graph --json server1 | jq '.edges[] | select(.edgeType=="inbound")'
```

### ssh 登录

```sh
# 选择主机并登录
sshs

# 用关键词过滤主机后登录，关键词会匹配 name/user/host:port
sshs server1
```

### 编辑配置

```sh
sshs edit
```

`edit` 打开编辑器前强制要求在终端手动输入 Master Key 认证身份，验证通过后自动将 `ENC(v1:...)` 密文密码解密为明文供直观核对与修改（口令错误直接拦截，绝不暴露配置）；保存并退出编辑器后，自动全量加密落盘，兼顾易用与磁盘凭据安全。临时文件严格采用 `0600` 权限并在退出后立即清除。

### 诊断配置

```sh
sshs doctor
```

`doctor` 会输出当前加载到的配置文件路径，并检查配置中是否存在重复的 `host:port`。

### 执行一次远程命令

`exec` 会连接所选主机，执行一次命令后退出。`cmd` 是 `exec` 的别名，`--` 后面的内容会作为远程命令执行。

```sh
# 选择主机后执行
sshs exec -- uptime

# 用关键词过滤主机后执行
sshs exec server1 -- uname -a

# 使用多个关键词过滤主机
sshs exec prod db -- df -h

# 执行需要 shell 解析的命令
sshs exec server1 -- "cd /tmp && pwd && ls -la"

# 使用 cmd 别名
sshs cmd server1 -- "cd /tmp && ls -la"
```

### 快速修改远程文件

`exec` 通过远程 shell 执行命令，可以直接查看和修改远程文件：

```sh
# 查看当前内容
sshs exec server1 -- "cat /etc/nginx/nginx.conf"

# 替换字符串（sed -i 直接覆盖原文件，表达式用单引号包裹避免本地 shell 展开）
sshs exec server1 -- "sed -i 's/worker_processes 1/worker_processes 4/' /etc/nginx/nginx.conf"

# 追加一行（>> 不覆盖原文件）
sshs exec server1 -- "echo 'client_max_body_size 10m;' >> /etc/nginx/nginx.conf"

# 验证改动
sshs exec server1 -- "grep -n worker_processes /etc/nginx/nginx.conf"
```

`sed -i` 直接覆盖文件且不可逆，改动前建议先备份（`cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak`）；追加用 `>>`，覆盖用 `>`，写错会清空文件。

### 文件传输

远程路径用 `:` 开头。文件传输底层使用 SFTP。

```sh
# 把本地 1.txt 传输到远程主机
sshs cp 1.txt :/tmp/1.txt

# 把远程文件传输到本地
sshs cp :/tmp/1.txt 1.txt

# 传输目录
sshs cp -r dist :/tmp/dist

# 传输时 gzip 压缩目标文件
sshs cp --gzip bigfile.txt :/tmp/bigfile.txt.gz

# 不显示进度条
sshs cp --no-progress bigfile.txt :/tmp/bigfile.txt
```

也可以在 `:` 前写关键词，让 `sshs` 自动过滤主机：

```sh
sshs cp server1:/tmp/1.txt 1.txt
sshs cp 1.txt server1:/tmp/1.txt
```

### 本地端口转发

监听本地端口，通过 SSH 连接远程地址。

```sh
# 访问本地 27017，会通过所选主机连接远程 127.0.0.1:27017
sshs forward -l :27017 -r 127.0.0.1:27017
```

### 远程端口监听转发

在远程主机监听端口，并转发到本地地址。

```sh
# 访问远程主机的 80 端口，会转发到本地 127.0.0.1:8080
sshs listen -r 0.0.0.0:80 -l 127.0.0.1:8080
```

### SOCKS5 代理

```sh
sshs socks5 -l 127.0.0.1:1080
```

启动后会输出可直接使用的代理环境变量。

### 批量执行脚本

```sh
sshs run -f test.yaml
```

`test.yaml` 示例：

```yaml
hosts:
  - { name: host1, host: 10.10.0.10, password: 123456 }
  - { name: host2, host: 10.10.0.11, password: 123456 }

scripts:
  - { local_run: 'touch 1.txt' } # 在本地创建文件 1.txt
  - { local_run: 'touch bigfile.txt' }
  - { scp: { src: '1.txt', dst: ':/tmp/1.txt' } } # 传输到远程主机
  - { scp: { src: 'bigfile.txt', dst: ':/tmp/bigfile.txt.gz', gzip: true } } # 实时 gzip 压缩后传输到远程主机
  - { run: 'cd /tmp' }
  - { run: 'rm 1.txt' } # 在远程主机上执行命令
```

如果 `hosts` 为空，会进入交互选择主机。

也可以直接执行本地 `.sh` 文件：

```sh
sshs run -f deploy.sh
```

## Help

```sh
> sshs -h
NAME:
   sshs - make ssh scp easy

USAGE:
   sshs [flags] [command] [args...]

VERSION:
   1.17.1

COMMANDS:
   list       list matched hosts (non-interactive)
   inspect    inspect matched hosts metrics
   scp, cp    scp transfer file or dir
   run        run shell file
   exec, cmd  execute remote command
   forward    direct_tcp_ip
   listen     listen remote forward to local
   socks5     socks5 proxy
   edit       edit config
   doctor     check sshs config
   skill      show sshs agent skill documentation
   help, h    Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --help, -h     show help
   --version, -v  print the version
```

```sh
> sshs exec -h
NAME:
   sshs exec - execute remote command

USAGE:
   sshs exec [host keywords...] -- <command>

OPTIONS:
   --help, -h  show help
```

## Notes

- `user` 为空时默认使用 `root`。
- `port` 为空或小于等于 0 时默认使用 `22`。
- `exec` 默认不申请 TTY，适合执行一次性命令；需要交互的命令建议直接用 `sshs` 登录后执行。
- `local_run` 会直接执行本地命令，不会通过 shell 解析复杂的管道或重定向。
- `run` 中的远程命令会写入同一个 shell session，前面的 `cd` 会影响后续命令。
