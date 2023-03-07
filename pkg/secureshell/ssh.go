package secureshell

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
)

type DialConfig struct {
	Username    string
	Host        string
	AuthMethods []ssh.AuthMethod
}

func Dial(username, host string, authmethod ...ssh.AuthMethod) (*ssh.Client, error) {
	cfg := &ssh.ClientConfig{
		User:            username,
		Auth:            append([]ssh.AuthMethod{keyboardInteractive()}, authmethod...),
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}
	return ssh.Dial("tcp", host, cfg)
}

func JumperDial(c *ssh.Client, username, host string, authmethod ...ssh.AuthMethod) (*ssh.Client, error) {
	cfg := &ssh.ClientConfig{
		User:            username,
		Auth:            append([]ssh.AuthMethod{keyboardInteractive()}, authmethod...),
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}
	conn, err := c.Dial("tcp", host)
	if err != nil {
		return nil, err
	}
	cc, newCh, reqCh, err := ssh.NewClientConn(conn, host, cfg)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return ssh.NewClient(cc, newCh, reqCh), nil
}

var (
	PasswordAuth = ssh.Password
)

func KeyAuth(pemBytes []byte, passphrase ...string) ssh.AuthMethod {
	var signer ssh.Signer
	var err error
	var usePassphrase bool
	for _, pass := range passphrase {
		if pass != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(pemBytes, []byte(passphrase[0]))
			usePassphrase = true
		}
	}
	if !usePassphrase {
		signer, err = ssh.ParsePrivateKey(pemBytes)
	}
	if err != nil {
		log.Println(err)
	}
	return ssh.PublicKeys(signer)
}

func keyboardInteractive() ssh.AuthMethod {
	auth := ssh.KeyboardInteractive(func(user, instruction string, questions []string, echos []bool) ([]string, error) {
		answers := make([]string, 0, len(questions))
		for i, q := range questions {
			fmt.Printf(q)
			if echos[i] {
				scan := bufio.NewScanner(os.Stdin)
				if scan.Scan() {
					answers = append(answers, scan.Text())
				}
				err := scan.Err()
				if err != nil {
					return nil, err
				}
			} else {
				b, err := terminal.ReadPassword(int(syscall.Stdin))
				if err != nil {
					return nil, err
				}
				answers = append(answers, string(b))
			}
		}
		return answers, nil
	})
	return auth
}
