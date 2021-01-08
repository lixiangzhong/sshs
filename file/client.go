package file

import (
	"os"

	"github.com/pkg/sftp"
)

func NewOSClient() Client {
	return &osclient{}
}

func NewSFTPClient(c *sftp.Client) Client {
	return &sftpclient{c}
}

type Client interface {
	Create(string) (File, error)
	Open(string) (File, error)
	Makedir
}

type Makedir interface {
	MkdirAll(string, os.FileMode) error
}

var _ Client = &osclient{}

type osclient struct {
}

func (o osclient) Create(name string) (File, error) {
	return Create(name)
}

func (o osclient) Open(name string) (File, error) {
	return Open(name)
}

func (o osclient) MkdirAll(path string, mode os.FileMode) error {
	return os.MkdirAll(path, mode)
}

var _ Client = &sftpclient{}

type sftpclient struct {
	*sftp.Client
}

func (s *sftpclient) MkdirAll(path string, mode os.FileMode) error {
	info, err := s.Client.Stat(path)
	if os.IsNotExist(err) {
		err := s.Client.MkdirAll(path)
		if err != nil {
			return err
		}
		return s.Client.Chmod(path, mode)
	}
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return NotDirError{path}
	}
	return err
}

func (s *sftpclient) Create(name string) (File, error) {
	return SFTPCreate(s.Client, name)
}

func (s *sftpclient) Open(name string) (File, error) {
	return SFTPOpen(s.Client, name)
}
