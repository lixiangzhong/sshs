module github.com/lixiangzhong/sshs

go 1.15

require (
	github.com/k0kubun/go-ansi v0.0.0-20180517002512-3bf9e2903213
	github.com/manifoldco/promptui v0.8.0
	github.com/pkg/sftp v1.12.0
	github.com/schollz/progressbar/v3 v3.8.0
	github.com/spf13/afero v0.0.0-00010101000000-000000000000
	github.com/urfave/cli/v2 v2.3.0
	golang.org/x/crypto v0.0.0-20210506145944-38f3c27a63bf
	gopkg.in/yaml.v2 v2.2.3
)

replace github.com/spf13/afero => github.com/lixiangzhong/afero v1.6.1-0.20210608025232-5b44be244d8a
