module sshs

go 1.15

require (
	github.com/manifoldco/promptui v0.8.0
	github.com/pkg/errors v0.9.1
	github.com/pkg/sftp v1.12.0
	github.com/schollz/progressbar/v3 v3.7.6
	github.com/spf13/afero v0.0.0-00010101000000-000000000000
	//github.com/spf13/afero v1.6.0
	github.com/urfave/cli/v2 v2.3.0
	golang.org/x/crypto v0.0.0-20210220033148-5ea612d1eb83
	gopkg.in/yaml.v2 v2.2.3
)

replace github.com/spf13/afero => github.com/lixiangzhong/afero v1.6.1-0.20210527074456-5dc5331f477a
