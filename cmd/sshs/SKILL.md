---
name: sshs
description: 使用本地最新版 sshs 执行登录、传输、端口转发、SOCKS5、exec/cmd、run -f、list 和 inspect；用户要用 sshs 命令完成操作时使用。
---

# sshs 使用助手

## 目标

用本地 `github.com/lixiangzhong/sshs` 完成 SSH 操作：登录、传文件、端口转发、SOCKS5、执行远程命令、批量脚本。

## 关键提醒

- 一律使用 `sshs` 命令；**不要改用原生 `ssh` / `scp` / `sftp`**。
- `sshs exec <keyword> -- <command>` 中 `--` 之后的命令**在远程主机上执行**，由远程 shell 运行；不要把它们当成本地命令拼出去，也不要省略 `--`。
- `list` / `inspect` 的 flags 写在主机关键词之前（如 `sshs inspect --json prod`）。

## 安全边界

- 缺失关键参数（主机/路径/命令）时给带占位符的命令模板，不编造。
- 不主动连接真实服务器，除非用户明确要求并确认目标主机。
- 默认目标主机已能被 sshs 选中，不指导修改配置文件。

## 快速判断

1. 查看主机：`sshs list [keyword] [--json]`
2. 登录：`sshs` 或 `sshs <keyword>`
3. 一次性远程命令：`sshs exec [keyword...] -- <command>`（`cmd` 是别名）
4. 传文件：`sshs cp` 或 `sshs scp`
5. 本地端口转远程服务用 `forward`；远程端口转本地服务用 `listen`
6. SOCKS5 代理：`sshs socks5 -l <local-addr> [keyword...]`
7. 批量执行：`sshs run -f <file>`（YAML 或 `.sh`）
8. 批量巡检：`sshs inspect [keyword...]`

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

无匹配时退出码 1，可探测关键词有效性。flags 必须写在关键词前（`list`/`inspect`）。

**批量巡检：**

```bash
sshs inspect --json prod
sshs inspect --timeout 5s --concurrency 20 prod
```

指标：负载(1/5/15)、CPU、内存、磁盘、内核/发行版、时间偏移。失败/超时主机标记错误，不拖垮整批。

**登录：**

```bash
sshs
sshs prod-1
```

**一次性远程命令：**

```bash
sshs exec prod-1 -- uname -a
sshs exec --timeout 10s prod-1 -- uname -a        # 支持超时控制（默认 0 不限）
sshs cmd prod-1 -- "cd /tmp && ls -la"            # cmd 是别名
```

`--` 分隔关键词与命令；exec 不申请 TTY；flags（如 `--timeout`）写在关键词前。

**快速修改远程文件（看 → 改 → 验证）：**

```bash
sshs exec prod-1 -- "cat /etc/nginx/nginx.conf"
sshs exec prod-1 -- "sed -i 's/old/new/' /etc/nginx/nginx.conf"
sshs exec prod-1 -- "echo 'x=1' >> /etc/nginx/nginx.conf"
sshs exec prod-1 -- "grep -n old /etc/nginx/nginx.conf"
```

sed 表达式用单引号；`sed -i` 不可逆，改前先备份；`>>` 追加、`>` 覆盖。

**文件传输：**

```bash
sshs cp ./1.txt prod-1:/tmp/1.txt     # 本地→远程
sshs cp prod-1:/tmp/1.txt ./1.txt     # 远程→本地
sshs cp -r -exclude "*.log" ./dist prod-1:/tmp/dist
sshs cp --gzip ./bigfile.txt prod-1:/tmp/bigfile.txt.gz
sshs cp --no-progress ./bigfile.txt prod-1:/tmp/bigfile.txt  # 非交互场景
```

远程路径 `:/path`；`name:/path` 中 name 是主机关键词。

**端口转发 / 代理：**

```bash
sshs forward -l :27017 -r 127.0.0.1:27017 prod-1   # 本地监听→远程服务
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

1. 结论：应该用哪个子命令。
2. 命令：最小可执行命令，缺失参数用占位符。
3. 验证：给低风险验证命令（如 `sshs list <keyword>`、`sshs exec <keyword> -- true`）。

## 常见取舍

- 看有哪些主机/验证关键词：`sshs list <keyword> --json`。
- 批量看主机状态：`sshs inspect --json`。
- 登录一台机器：`sshs <keyword>`，不要写复杂脚本。
- 单个非交互远程命令：`sshs exec <keyword> -- <command>`。
- 传文件+跑命令串联：生成 `sshs run -f` YAML。
- 远程数据库：`forward`；暴露本地服务：`listen`；出网代理：`socks5`。
