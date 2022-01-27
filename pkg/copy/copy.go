package copy

import (
	"bufio"
	"context"
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
	dstf, err := s.dst.OpenFile(dst, os.O_CREATE|os.O_RDWR|os.O_TRUNC, srcfi.Mode())
	if err != nil {
		return err
	}
	defer dstf.Close()
	var r io.Reader = bufio.NewReader(srcf)
	for _, op := range opts {
		r = op(r, srcfi)
	}
	_, err = ContextIoCopy(ctx, dstf, r)
	if err != nil {
		return err
	}
	return s.dst.Chtimes(dst, srcfi.ModTime(), srcfi.ModTime())
}

func ContextIoCopy(ctx context.Context, dst io.Writer, src io.Reader) (int64, error) {
	type tmp struct {
		n   int64
		err error
	}
	ch := make(chan tmp, 1)
	go func() {
		n, err := io.Copy(dst, src)
		ch <- tmp{n: n, err: err}
		close(ch)
	}()
	select {
	case tmp := <-ch:
		return tmp.n, tmp.err
	case <-ctx.Done():
		return 0, ctx.Err()
	}
}

func (c *Copy) Dir(ctx context.Context, src, dst string, opts ...Option) error {
	srcfs := afero.NewBasePathFs(c.src, src)
	dstfs := afero.NewBasePathFs(c.dst, dst)
	cc := New(srcfs, dstfs)
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
			err = cc.File(ctx, path, path, opts...)
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
