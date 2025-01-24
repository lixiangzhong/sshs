package copy

import (
	"bufio"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
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

func (s *Copy) File(ctx context.Context, src, dst string, opts ...Option) error {
	srcf, err := s.src.Open(src)
	if err != nil {
		return err
	}
	defer srcf.Close()
	srcfi, err := srcf.Stat()
	if err != nil {
		return err
	}
	if fi, err := s.dst.Stat(dst); err == nil {
		if fi.IsDir() {
			dst = filepath.Join(dst, srcfi.Name())
		}
	}
	dstf, err := s.dst.OpenFile(dst, os.O_CREATE|os.O_RDWR|os.O_TRUNC, srcfi.Mode())
	if err != nil {
		return err
	}
	defer dstf.Close()
	var r io.Reader = bufio.NewReader(srcf)
	var w io.WriteCloser = dstf
	for _, op := range opts {
		w, r = op(w, r, srcfi)
		defer w.Close()
	}
	_, err = io.Copy(w, r)
	if err != nil {
		return err
	}
	return s.dst.Chtimes(dst, srcfi.ModTime(), srcfi.ModTime())
}

func (c *Copy) Dir(ctx context.Context, src, dst string, opts ...Option) error {
	srcfs := afero.NewBasePathFs(c.src, src)
	dstfs := afero.NewBasePathFs(c.dst, dst)
	cc := New(srcfs, dstfs)
	return fs.WalkDir(afero.NewIOFS(srcfs), ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		switch d.IsDir() {
		case true:
			fi, err := d.Info()
			if err != nil {
				return err
			}
			return cc.dst.MkdirAll(path, fi.Mode())
		default:
			return cc.File(ctx, path, path, opts...)
		}
	})
}

type Option func(io.WriteCloser, io.Reader, fs.FileInfo) (io.WriteCloser, io.Reader)

func ProgressBar() Option {
	return func(w io.WriteCloser, r io.Reader, fi fs.FileInfo) (io.WriteCloser, io.Reader) {
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
		return w, &rr
	}
}

func GzipCompress() Option {
	return func(w io.WriteCloser, r io.Reader, fi fs.FileInfo) (io.WriteCloser, io.Reader) {
		buffer := bufio.NewWriterSize(w, 64<<10)
		gw, err := gzip.NewWriterLevel(buffer, gzip.BestSpeed)
		if err != nil {
			return w, r
		}
		return &struct {
			io.Writer
			io.Closer
		}{
			Writer: gw,
			Closer: CloserFunc(func() error {
				return errors.Join(gw.Close(), buffer.Flush())
			}),
		}, r
	}
}

type CloserFunc func() error

func (f CloserFunc) Close() error {
	return f()
}
