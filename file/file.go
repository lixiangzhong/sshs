package file

import (
	"io"
	"os"
	"path/filepath"
)

type File interface {
	io.Reader
	io.Writer
	io.Closer
	os.FileInfo
	Walker
	Size
	Chmod(os.FileMode) error
	Client() Client
}

type Walker interface {
	Walk(walkFn filepath.WalkFunc) error
}

type Size interface {
	BodySize() int64
}
