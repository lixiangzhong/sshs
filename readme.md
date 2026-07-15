# sshs

不想反复输入 ssh、scp 密码时，可以用 `sshs` 通过配置文件管理主机，并完成 ssh 登录、文件传输、端口转发、SOCKS5 代理和批量命令执行。

本项目 terminal ui 参考了 https://github.com/yinheli/sshw

## install

```sh
go install github.com/lixiangzhong/sshs/cmd/sshs@latest
```

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

## Usage

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

### 执行一次远程命令

`exec` 会连接所选主机，执行一次命令后退出。`cmd` 是 `exec` 的别名。

```sh
# 选择主机后执行
sshs exec -- uptime

# 用关键词过滤主机后执行
sshs exec server1 -- uname -a

# 使用 cmd 别名
sshs cmd server1 -- "cd /tmp && ls -la"
```

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
   1.13.0

COMMANDS:
   scp, cp    scp transfer file or dir
   run        run shell file
   exec, cmd  execute remote command
   forward    direct_tcp_ip
   listen     listen remote forward to local
   socks5     socks5 proxy
   edit       edit config
   help, h    Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --help, -h     show help
   --version, -v  print the version
```

## Notes

- `user` 为空时默认使用 `root`。
- `port` 为空或小于等于 0 时默认使用 `22`。
- `exec` 默认不申请 TTY，适合执行一次性命令；需要交互的命令建议直接用 `sshs` 登录后执行。
- `local_run` 会直接执行本地命令，不会通过 shell 解析复杂的管道或重定向。
- `run` 中的远程命令会写入同一个 shell session，前面的 `cd` 会影响后续命令。
