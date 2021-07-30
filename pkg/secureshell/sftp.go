package secureshell

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/lixiangzhong/sshs/pkg/copy"

	"github.com/pkg/sftp"
	"github.com/spf13/afero"
	"github.com/spf13/afero/sftpfs"
	"golang.org/x/crypto/ssh"
)

func SftpClient(c *ssh.Client, opts ...sftp.ClientOption) (*sftp.Client, error) {
	return sftp.NewClient(c, opts...)
}

func Scp(ctx context.Context, remote *sftp.Client, recursively bool, src string, dst string) error {
	workdir, err := os.Getwd()
	if err != nil {
		return err
	}
	var cp copy.Copy
	if strings.Contains(src, ":") { //remote to local
		src = src[1:]
		cp = copy.New(sftpfs.New(remote), afero.NewOsFs())
		if !filepath.IsAbs(dst) {
			dst = filepath.Join(workdir, dst)
		}
	} else {
		dst = dst[1:]
		cp = copy.New(afero.NewOsFs(), sftpfs.New(remote))
		if !filepath.IsAbs(src) {
			src = filepath.Join(workdir, src)
		}
	}
	if recursively { //传输目录
		err = cp.Dir(ctx, src, dst, copy.ProgressBar())
	} else {
		err = cp.File(ctx, src, dst, copy.ProgressBar())
	}
	return err
}
