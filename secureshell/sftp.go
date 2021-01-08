package secureshell

import (
	"io"
	"log"
	"os"
	"path/filepath"
	"sshs/file"
	"sshs/progress"
	"strings"

	"github.com/pkg/errors"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

func SftpClient(c *ssh.Client, opts ...sftp.ClientOption) (*sftp.Client, error) {
	return sftp.NewClient(c, opts...)
}

type readerWrapper func(io.Reader) io.Reader

func barProgress(bar *progress.Bar, f file.File) readerWrapper {
	bar.Add(f.Name(), int(f.BodySize()))
	return func(r io.Reader) io.Reader {
		return io.TeeReader(f, bar)
	}
}

func Scp(remote *sftp.Client, recursively bool, src string, dst string) error {
	log.Println("debug", recursively, src, dst)
	sendToRemote := strings.HasPrefix(dst, ":")
	recvFromRemote := strings.HasPrefix(src, ":")
	if sendToRemote == recvFromRemote {
		return errors.New("invalid: src and dst")
	}
	if idx := strings.LastIndex(src, ":"); idx >= 0 {
		src = src[idx+1:]
	}
	if idx := strings.LastIndex(dst, ":"); idx >= 0 {
		dst = dst[idx+1:]
	}
	sftpcli := file.NewSFTPClient(remote)
	oscli := file.NewOSClient()
	bar := progress.NewBar()
	defer bar.Close()
	if sendToRemote {
		f, err := oscli.Open(src)
		if err != nil {
			return err
		}
		if f.IsDir() {
			if recursively {
				return scpDir(sftpcli, f, dst)
			} else {
				return errors.New(src + " is a directory")
			}
		}
		return scp(sftpcli, f, dst, barProgress(bar, f))
	} else {
		f, err := sftpcli.Open(src)
		if err != nil {
			return err
		}
		if f.IsDir() {
			if recursively {
				return scpDir(oscli, f, dst)
			} else {
				return errors.New(src + " is a directory")
			}
		}
		return scp(oscli, f, dst, barProgress(bar, f))
	}
}

func scp(dstclient file.Client, src file.File, dst string, rwraper ...readerWrapper) error {
	if src.IsDir() {
		return dstclient.MkdirAll(dst, src.Mode())
	} else {
		if strings.HasSuffix(dst, "/") {
			dst = filepath.Join(dst, filepath.Base(src.Name()))
		}
	}
	f, err := dstclient.Create(dst)
	if err != nil {
		return err
	}
	defer f.Close()
	var r io.Reader = src
	for _, wrap := range rwraper {
		r = wrap(r)
	}
	_, err = io.Copy(f, r)
	if err != nil {
		return err
	}
	return f.Chmod(src.Mode())
}

func scpDir(dstclient file.Client, source file.File, target string) error {
	if !source.IsDir() {
		return errors.New(source.Name() + " not a directory")
	}
	bar := progress.NewBar()
	defer bar.Close()
	base := source.Name()
	err := source.Walk(func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		src, err := source.Client().Open(path)
		if err != nil {
			return err
		}
		defer src.Close()

		rel, err := filepath.Rel(base, path)
		if err != nil {
			return err
		}
		remote := filepath.Join(target, rel)
		return scp(dstclient, src, remote, barProgress(bar, src))
	})
	return err
}
