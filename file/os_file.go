package file

import (
	"os"
	"path/filepath"
)

func Create(name string) (File, error) {
	err := os.MkdirAll(filepath.Dir(name), 0755)
	if err != nil {
		return nil, err
	}
	f, err := os.Create(name)
	if err != nil {
		return nil, err
	}
	return wrapOsFile(f)
}

func Open(name string) (File, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	return wrapOsFile(f)
}

func wrapOsFile(f *os.File) (File, error) {
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	return &osfile{f: f, FileInfo: info}, nil
}

var _ File = &osfile{}

type osfile struct {
	f *os.File
	os.FileInfo
}

func (o *osfile) Client() Client {
	return NewOSClient()
}

func (o *osfile) Chmod(mode os.FileMode) error {
	return o.f.Chmod(mode)
}

func (o *osfile) BodySize() int64 {
	if o.IsDir() {
		return 0
	}
	return o.Size()
}

func (o *osfile) Read(p []byte) (n int, err error) {
	return o.f.Read(p)
}

func (o *osfile) Write(p []byte) (n int, err error) {
	return o.f.Write(p)
}

func (o *osfile) Close() error {
	return o.f.Close()
}

func (o *osfile) Walk(fn filepath.WalkFunc) error {
	if !o.IsDir() {
		return NotDirError{o.f.Name()}
	}
	return filepath.Walk(o.f.Name(), fn)
}
