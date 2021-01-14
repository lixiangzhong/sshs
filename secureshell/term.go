package secureshell

import (
	"io"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
)

type TerminalOption func(*Term)

func WithStdout(out io.Writer) TerminalOption {
	return func(t *Term) {
		t.stdout = out
	}
}

type Term struct {
	wg            *sync.WaitGroup
	session       *ssh.Session
	fd            int
	width, height int
	state         *terminal.State
	stdin         io.WriteCloser
	stdout        io.Writer
}

func NewTerminal(c *ssh.Client, options ...TerminalOption) (*Term, error) {
	t := &Term{
		stdout: os.Stdout,
		wg:     new(sync.WaitGroup),
	}
	t.fd = int(os.Stdin.Fd())
	var err error
	t.width, t.height, err = terminal.GetSize(t.fd)
	if err != nil {
		return nil, err
	}
	for _, op := range options {
		op(t)
	}
	t.state, err = terminal.MakeRaw(t.fd)
	if err != nil {
		return nil, err
	}
	err = t.shell(c)
	return t, err
}

func (t *Term) Wait() error {
	t.session.Wait()
	err := terminal.Restore(t.fd, t.state)
	if err != nil {
		return err
	}
	return t.session.Close()
}

func (t *Term) resize() {
	tk := time.NewTicker(time.Second)
	defer tk.Stop()
	for range tk.C {
		w, h, err := terminal.GetSize(t.fd)
		if err != nil {
			break
		}
		if w != t.width || h != t.height {
			t.width = w
			t.height = h
			err = t.session.WindowChange(h, w)
			if err != nil {
				break
			}
		}
	}
}

func (t *Term) keepalive() {
	tk := time.NewTicker(time.Second * 15)
	defer tk.Stop()
	for range tk.C {
		_, err := t.session.SendRequest("keepalive@openssh.com", false, nil)
		if err != nil {
			return
		}
	}
}

func (t *Term) shell(c *ssh.Client) error {
	s, err := c.NewSession()
	if err != nil {
		return err
	}
	t.session = s
	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}
	err = s.RequestPty("xterm", t.height, t.width, modes)
	if err != nil {
		return err
	}
	s.Stdout = t.stdout
	s.Stderr = t.stdout
	t.stdin, err = s.StdinPipe()
	if err != nil {
		return err
	}
	go func() {
		io.Copy(t.stdin, os.Stdin)
		s.Close()
	}()
	err = s.Shell()
	if err != nil {
		return err
	}
	go t.resize()
	go t.keepalive()
	return nil
}
