# sshs

#### 不想输入ssh,scp密码

本项目terminal ui参考了 https://github.com/yinheli/sshw

## install

```sh
go install  github.com/lixiangzhong/sshs/cmd/sshs
```

## configuration

```sh
vi ~/.sshs.yaml
```

#### 配置示例

```yaml
- { name: server1, host: 10.10.0.1, password: 123456 } #default user: root ,port: 22
- { name: server2, host: 10.10.0.2, port: 2222, user: root, password: 123456 }
- { name: server3, host: 10.10.0.3, port: 2222, keypath: ~/.ssh/server3.key, passphrase: abcdefghijk } #使用私钥+passphrase方式
- name: group_name1
  children:
    - { name: server4, host: 10.10.0.4, password: 123456 }
    - { name: server5, host: 10.10.0.5, password: 123456 }
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


#端口映射:在远程主机上把127.0.0.1:27017映射到本地27017
sshs forward -r 127.0.0.1:27017 -l :27017

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
  - {local_run: "echo 123 >> 1.txt"} #在本地创建文件1.txt
  - {scp: {src: "1.txt",dst: ":/1.txt"}} #传输到远程主机
  - {run: "mv /tmp/1.txt /tmp/1.txt.bak"} #在远程主机上执行命令
  - {run: "rm /tmp/1.txt"} #在远程主机上执行命令
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
   1.3.0

COMMANDS:
   scp, cp  scp transfer file or dir
   run      run shell file
   forward  direct_tcp_ip
   help, h  Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --help, -h     show help (default: false)
   --version, -v  print the version (default: false)
```