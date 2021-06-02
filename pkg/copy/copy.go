package copy

import (
	"bufio"
	"io"
	"io/fs"
	"os"
	"time"

	"github.com/k0kubun/go-ansi"
	"github.com/spf13/afero"

	"github.com/schollz/progressbar/v3"
)

func New(src, dst afero.Fs) Copy {
	return Copy{
		src: src,
		dst: dst,
	}
}

type Copy struct {
	src afero.Fs
	dst afero.Fs
}

func (s *Copy) File(src, dst string, opts ...Option) error {
	srcf, err := s.src.Open(src)
	if err != nil {
		return err
	}
	defer srcf.Close()
	srcfi, err := srcf.Stat()
	if err != nil {
		return err
	}
	dstf, err := s.dst.OpenFile(dst, os.O_CREATE|os.O_RDWR|os.O_TRUNC, srcfi.Mode())
	if err != nil {
		return err
	}
	defer dstf.Close()
	var r io.Reader = bufio.NewReader(srcf)
	for _, op := range opts {
		r = op(r, srcfi)
	}
	_, err = io.Copy(dstf, r)
	if err != nil {
		return err
	}
	return err
}

func (c *Copy) Dir(src, dst string, opts ...Option) error {
	srcfs := afero.NewBasePathFs(c.src, src)
	dstfs := afero.NewBasePathFs(c.dst, dst)
	cc := Copy{src: srcfs, dst: dstfs}
	return fs.WalkDir(afero.NewIOFS(srcfs), ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		switch d.IsDir() {
		case true:
			fi, err := d.Info()
			if err != nil {
				return err
			}
			err = cc.dst.MkdirAll(path, fi.Mode())
		default:
			err = cc.File(path, path, opts...)
		}
		return err
	})
}

type Option func(io.Reader, fs.FileInfo) io.Reader

func ProgressBar() Option {
	return func(r io.Reader, fi fs.FileInfo) io.Reader {
		//bar := progressbar.DefaultBytes(fi.Size(), fi.Name())
		bar := progressbar.NewOptions64(fi.Size(),
			progressbar.OptionSetDescription("[cyan]"+fi.Name()+"[reset]"),
			progressbar.OptionEnableColorCodes(true),
			progressbar.OptionSetWriter(ansi.NewAnsiStdout()),
			progressbar.OptionShowBytes(true),
			progressbar.OptionThrottle(65*time.Millisecond),
			progressbar.OptionFullWidth(),
			progressbar.OptionShowCount(),
			progressbar.OptionOnCompletion(func() {
				os.Stdout.WriteString("\n")
			}),
			progressbar.OptionSetTheme(progressbar.Theme{
				Saucer:        "[green]=[reset]",
				SaucerHead:    "[yellow]>[reset]",
				SaucerPadding: " ",
				BarStart:      "[",
				BarEnd:        "]",
			}),
			progressbar.OptionSetRenderBlankState(true),
		)
		rr := progressbar.NewReader(r, bar)
		return &rr
	}
}
