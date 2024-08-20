package secureshell

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/net/proxy"
	"golang.org/x/term"
)

type DialConfig struct {
	Username    string
	Host        string
	AuthMethods []ssh.AuthMethod
}

var (
	_ Dialer = (*ssh.Client)(nil)
	_ Dialer = proxy.FromEnvironment()
)

type Dialer interface {
	Dial(network, addr string) (net.Conn, error)
}

func Dial(dialer Dialer, username, host string, authmethod ...ssh.AuthMethod) (*ssh.Client, error) {
	cfg := &ssh.ClientConfig{
		User:            username,
		Auth:            append([]ssh.AuthMethod{keyboardInteractive()}, authmethod...),
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}
	conn, err := dialer.Dial("tcp", host)
	if err != nil {
		return nil, err
	}
	cc, ch, reqch, err := ssh.NewClientConn(conn, host, cfg)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return ssh.NewClient(cc, ch, reqch), nil
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
				b, err := term.ReadPassword(int(syscall.Stdin))
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
