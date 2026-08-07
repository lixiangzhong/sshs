---
name: sshs
description: 使用本地最新版 sshs 执行登录、传输、端口转发、SOCKS5、exec/cmd、run -f、list 和 inspect；用户要用 sshs 命令完成操作时使用。
---

# sshs 使用助手

## 目标

帮助用户用本地最新版 `github.com/lixiangzhong/sshs` 完成日常 SSH 操作：登录、传文件、端口转发、SOCKS5 代理、执行一次性远程命令和批量脚本。

## 安全边界

- 不要替用户编造主机关键词、路径、端口或远程命令；缺失关键参数时，给出带占位符的命令模板。
- 不要主动执行会连接真实服务器的命令，除非用户明确要求并确认目标主机。
- 不要指导用户修改 sshs 配置文件；本 skill 默认目标主机已经能被 sshs 选中。
- 用户只想要命令时，直接输出可复制片段，不要要求用户先解释 SSH 基础概念。

## 快速判断

1. 安装或首次使用：给 `go install` 和 `sshs -h` 验证命令。
2. 查看有哪些主机：用 `sshs list`（可加关键词过滤，`--json` 输出结构化结果）。
3. 批量巡检主机状态（负载/内存/磁盘/时间偏移）：用 `sshs inspect`（`--json` 输出结构化结果）。
4. 登录：用 `sshs`，或 `sshs <keyword>` 先按关键词过滤。
5. 执行一次性远程命令：用 `sshs exec [keyword...] -- <command>`，`cmd` 是别名。
6. 传文件：用 `sshs cp` 或 `sshs scp`。
7. 转发端口：本地端口访问远程服务用 `forward`；远程端口暴露本地服务用 `listen`。
8. SOCKS5 代理：用 `sshs socks5 -l <local-addr> [keyword...]`。
9. 批量执行：用 `sshs run -f <file>`，文件可以是 YAML 或 `.sh`。

## 常用命令

**安装与验证：**

```bash
go install github.com/lixiangzhong/sshs/cmd/sshs@latest
sshs -h
```

**查看主机列表（非交互，脚本/agent 友好）：**

```bash
# 列出全部主机（分组展开），匹配 name/user/host:port。
sshs list

# 用关键词过滤。
sshs list prod

# 结构化输出，供脚本解析。
sshs list --json
```

无匹配主机时退出码为 1，可用于探测关键词是否有效。

**批量巡检主机（非交互）：**

```bash
# 巡检全部主机，输出概览表 + 磁盘明细表。
sshs inspect

# 用关键词过滤目标主机。
sshs inspect prod

# 结构化输出，供脚本解析。
sshs inspect --json

# 控制单台超时（默认 10s）与并发数（默认 10）。
sshs inspect --timeout 5s --concurrency 20 prod
```

巡检指标：负载(1/5/15)、CPU 使用率、内存、磁盘使用率、内核/发行版、与本地的时间偏移。单台拨号/采集失败会在对应行标记错误，超时标记 `timeout`，不拖垮整批。

注意：`list` 与 `inspect` 的 flags 必须写在主机关键词之前，例如 `sshs inspect --json prod`（不支持 `sshs inspect prod --json`）。

**交互登录：**

```bash
sshs
sshs prod-1
```

关键词会匹配 `name`、`user`、`host:port`。

**一次性远程命令：**

```bash
# 选择主机后执行。
sshs exec -- uptime

# 用关键词过滤主机后执行。
sshs exec prod-1 -- uname -a

# cmd 是 exec 的别名。
sshs cmd prod-1 -- "cd /tmp && ls -la"
```

注意 `--` 必须存在；它用于分隔主机关键词和远程命令。`exec` 默认不申请 TTY，适合非交互命令；交互命令建议直接 `sshs` 登录后执行。

**文件传输：**

```bash
# 本地到远程；冒号前可放主机关键字，用于筛选目标主机。
sshs cp ./1.txt prod-1:/tmp/1.txt

# 远程到本地。
sshs cp prod-1:/tmp/1.txt ./1.txt

# 目录传输（默认排除 .DS_Store）。
sshs cp -r ./dist prod-1:/tmp/dist

# 指定排除文件/目录模式（可重复多次指定）。
sshs cp -r -exclude "*.log" -exclude ".git" ./dist prod-1:/tmp/dist

# 传输时 gzip 压缩目标文件。
sshs cp --gzip ./bigfile.txt prod-1:/tmp/bigfile.txt.gz

# 不显示进度条（适合非交互/脚本场景，避免终端被进度条刷屏）。
sshs cp --no-progress ./bigfile.txt prod-1:/tmp/bigfile.txt
```

`cp` 和 `scp` 是同一类传输命令，底层使用 SFTP。远程路径用 `:/path` 表示；如果写成 `name:/path`，`name` 会作为主机筛选关键字。

**本地监听，转到远程服务：**

```bash
sshs forward -l :27017 -r 127.0.0.1:27017 prod-1
```

这会在本地监听 `:27017`，连接经 SSH 到目标主机上的 `127.0.0.1:27017`。

**远程监听，转到本地服务：**

```bash
sshs listen -r 0.0.0.0:80 -l 127.0.0.1:8080 prod-1
```

这会让远程主机监听 `0.0.0.0:80`，流量转回本地 `127.0.0.1:8080`。

**SOCKS5 代理：**

```bash
sshs socks5 -l 127.0.0.1:1080 prod-1
```

不指定 `-l` 时默认监听 `127.0.0.1:0`，即系统分配随机端口。启动后会输出 `https_proxy`、`http_proxy`、`all_proxy` 环境变量。

## 批量执行

`sshs run -f <file>` 支持 `.sh` 和 YAML。

**YAML 示例：**

```yaml
hosts:
  - { name: host1, host: 10.10.0.10, password: '<password>' }
  - { name: host2, host: 10.10.0.11, password: '<password>' }

scripts:
  - { local_run: 'touch 1.txt' }
  - { scp: { src: '1.txt', dst: ':/tmp/1.txt' } }
  - { scp: { src: 'bigfile.txt', dst: ':/tmp/bigfile.txt.gz', gzip: true } }
  - { run: 'cd /tmp' }
  - { run: 'ls -l /tmp/1.txt' }
```

执行：

```bash
sshs run -f test.yaml
```

注意：

- `hosts` 为空时，sshs 会进入交互选择主机。
- `scripts[].scp.dir: true` 表示传目录；命令行对应 `sshs cp -r`。
- `scripts[].sleep` 是 Go duration，例如 `2s`、`500ms`。
- `local_run` 在本地执行，不是远程命令；远程命令使用 `run`。
- `local_run` 通过 `strings.Fields` 拆分后直接执行命令，不经过 shell；复杂管道、重定向、引号语义不要依赖它。需要复杂本地准备动作时，建议先单独准备文件，或让用户确认可接受的简单命令。
- `run` 中的远程命令写入同一个 shell session，前面的 `cd` 会影响后续命令。

## 输出格式

回答用户时优先给出：

1. 结论：应该用哪个 sshs 子命令。
2. 命令：给出最小可执行命令，缺失参数用占位符。
3. 验证：给一个低风险验证命令，例如 `sshs -h`、`sshs <keyword>`、执行 `sshs run -f test.yaml` 前先检查文件内容。

## 常见取舍

- 想知道有哪些主机、或验证关键词是否有效：先执行 `sshs list <keyword> --json`。
- 批量看一批主机状态（负载/内存/磁盘/时间偏移）：用 `sshs inspect --json`。
- 只是登录一台机器：直接执行 `sshs <keyword>`，不要写复杂脚本。
- 只跑一个非交互远程命令：优先用 `sshs exec <keyword> -- <command>`。
- 需要传多个文件并跑远程命令：优先生成 `sshs run -f` YAML，把传输步骤、远程步骤串起来。
- 需要临时访问远程数据库：用 `forward`，因为它是本地端口转远程服务。
- 需要把本地开发服务暴露给远程机器访问：用 `listen`，因为它是远程端口转本地服务。
- 需要让本机应用通过目标主机出网：用 `socks5`，并根据输出设置代理环境变量。
