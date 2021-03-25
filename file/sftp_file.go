package file

import (
	"os"
	"path/filepath"

	"github.com/pkg/sftp"
)

func warpSFTPFile(c *sftp.Client, f *sftp.File) (File, error) {
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	return &sftpFile{
		c:        c,
		f:        f,
		FileInfo: info,
	}, nil
}

func SFTPOpen(c *sftp.Client, name string) (File, error) {
	f, err := c.Open(name)
	if err != nil {
		return nil, err
	}
	return warpSFTPFile(c, f)
}

func SFTPCreate(c *sftp.Client, name string) (File, error) {
	err := c.MkdirAll(filepath.Dir(name))
	if err != nil {
		return nil, err
	}
	f, err := c.Create(name)
	if err != nil {
		return nil, err
	}
	return warpSFTPFile(c, f)
}

var _ File = &sftpFile{}

type sftpFile struct {
	c *sftp.Client
	f *sftp.File
	os.FileInfo
}

func (s *sftpFile) Client() Client {
	return NewSFTPClient(s.c)
}

func (s *sftpFile) Chmod(mode os.FileMode) error {
	return s.f.Chmod(mode)
}

func (s *sftpFile) BodySize() int64 {
	if s.IsDir() {
		return -1
	}
	return s.Size()
}

func (s *sftpFile) Read(p []byte) (n int, err error) {
	return s.f.Read(p)
}

func (s *sftpFile) Write(p []byte) (n int, err error) {
	return s.f.Write(p)
}

func (s *sftpFile) Close() error {
	return s.f.Close()
}

func (s *sftpFile) Walk(fn filepath.WalkFunc) error {
	if !s.IsDir() {
		return NotDirError{s.Name()}
	}
	walker := s.c.Walk(s.Name())
	for walker.Step() {
		if err := fn(walker.Path(), walker.Stat(), walker.Err()); err != nil {
			return err
		}
	}
	return walker.Err()
}
