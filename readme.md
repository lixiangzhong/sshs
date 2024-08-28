# sshs

#### 不想输入 ssh,scp 密码

本项目 terminal ui 参考了 https://github.com/yinheli/sshw

## install

```sh
go install  github.com/lixiangzhong/sshs/cmd/sshs@latest
```

## configuration

```sh
vi ~/.sshs.yaml
```

#### 配置示例

```yaml
- { name: server1, host: 10.10.0.1, password: 123456 } #default user: root ,port: 22
- { name: server2, host: 10.10.0.2, port: 2222, user: root, password: 123456 }
- {
    name: server3,
    host: 10.10.0.3,
    port: 2222,
    keypath: ~/.ssh/server3.key,
    passphrase: abcdefghijk,
  } #使用私钥+passphrase方式
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
  } #使用跳板机
```

## Usage

```sh
#输入sshs后选择主机进行ssh登录
sshs

#把1.txt 传输到远程主机
sshs cp 1.txt :/tmp/1.txt
#把远程文件传输到本地
sshs cp :/tmp/1.txt 1.txt
#传输目录
sshs cp -r dist :/tmp/dist


#端口映射:在远程主机上把127.0.0.1:27017映射到本地27017(访问本地27017端口转到远程主机的27017端口)
sshs forward -r 127.0.0.1:27017 -l :27017

#端口监听转发: 在远程主机上监听80端口,并将80端口转发到本地8080端口(访问远程主机的80端口转到本地的8080端口)
sshs listen -l 0.0.0.0:80 -l 127.0.0.1:8080

#sshs socks5 连接到服务器,并启动一个socks5代理服务
sshs socks5

#批量执行脚本
sshs run -f test.yaml
```

---

#### 批量执行脚本示例

```yaml
# vi test.yaml

hosts:
  - { name: host1, host: 10.10.0.10, password: 123456 }
  - { name: host2, host: 10.10.0.11, password: 123456 }

scripts:
  - { local_run: 'echo 123 >> 1.txt' } #在本地创建文件1.txt
  - { local_run: 'echo big >> bigfile.txt' }
  - { scp: { src: '1.txt', dst: ':/tmp/1.txt' } } #传输到远程主机
  - { scp: { src: 'bigfile.txt', dst: ':/tmp/bigfile.txt.gz', gzip: true } } #实时gzip压缩,传输到远程主机
  - { run: 'cd /tmp' }
  - { run: 'rm 1.txt' } #在远程主机上执行命令
```

```sh
#以上脚本将会在2台机器上执行
sshs run -f test.yaml
```

---

```sh
> sshs -h
NAME:
   sshs - make ssh scp easy

USAGE:
   sshs [flags] [command] [args...]

VERSION:
   1.8.0

COMMANDS:
   scp, cp  scp transfer file or dir
   run      run shell file
   forward  direct_tcp_ip
   listen   listen remote forward to local
   socks5   socks5 proxy
   help, h  Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --help, -h     show help
   --version, -v  print the version
```
