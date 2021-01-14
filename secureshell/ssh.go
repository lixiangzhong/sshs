package secureshell

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
)

func Dial(username, host string, authmethod ...ssh.AuthMethod) (*ssh.Client, error) {
	cfg := &ssh.ClientConfig{
		User:            username,
		Auth:            append([]ssh.AuthMethod{keyboardInteractive()}, authmethod...),
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}
	return ssh.Dial("tcp", host, cfg)
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

func Terminal(c *ssh.Client) error {
	session, err := c.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()
	err = xtermShell(session)
	if err != nil {
		return err
	}
	go resizeTerminal(session)
	go sessionKeepalive(session)
	return session.Wait()
}

func resizeTerminal(session *ssh.Session) {
	stdin := int(os.Stdin.Fd())
	state, err := terminal.MakeRaw(stdin)
	if err != nil {
		log.Fatal(err)
	}
	defer terminal.Restore(stdin, state)
	tk := time.NewTicker(time.Second)
	defer tk.Stop()
	var w, h int
	for range tk.C {
		w1, h1, err := terminal.GetSize(stdin)
		if err != nil {
			break
		}
		if w1 != w || h1 != h {
			err = session.WindowChange(h, w)
			if err != nil {
				break
			}
			w = w1
			h = h1
		}
	}
}

func sessionKeepalive(session *ssh.Session) {
	tk := time.NewTicker(time.Second * 15)
	defer tk.Stop()
	for range tk.C {
		_, err := session.SendRequest("keepalive@openssh.com", false, nil)
		if err != nil {
			return
		}
	}
}

func xtermShell(session *ssh.Session) error {
	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}
	err := session.RequestPty("xterm", 80, 80, modes)
	if err != nil {
		return err
	}
	session.Stdout = os.Stdout
	session.Stderr = os.Stderr
	pipe, err := session.StdinPipe()
	if err != nil {
		return err
	}
	go func() {
		io.Copy(pipe, os.Stdin)
		session.Close()
	}()
	err = session.Shell()
	if err != nil {
		return err
	}
	return nil
}
