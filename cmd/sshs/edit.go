package main

import (
	"io"
	"os"
	"os/exec"

	"github.com/urfave/cli/v2"
)

func EditAction(c *cli.Context) error {
	filenames := configFileList(".sshs.store", ".sshs.yaml", "sshs.yaml", ".sshw.yaml", "sshw.yaml")
	for _, filename := range filenames {
		err := func(filename string) error {
			//todo 加密存储
			f, err := os.Open(filename)
			if err != nil {
				return err
			}
			defer f.Close()
			b, err := io.ReadAll(f)
			if err != nil {
				return err
			}
			b, err = Edit(b)
			if err != nil {
				return err
			}
			fi, err := f.Stat()
			if err != nil {
				return err
			}
			return os.WriteFile(filename, b, fi.Mode())
		}(filename)
		if err != nil {
			continue
		}
		break
	}
	return nil
}

func Edit(b []byte) ([]byte, error) {
	editor := os.Getenv("EDITOR")
	if editor == "" {
		// 检查vim是否存在
		_, err := exec.LookPath("vim")
		if err == nil {
			editor = "vim"
		} else {
			editor = "vi"
		}
	}

	tempDir := os.TempDir()
	tempFile, err := os.CreateTemp(tempDir, "edit-*.content")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tempFile.Name())

	if _, err := tempFile.Write(b); err != nil {
		return nil, err
	}
	tempFile.Close()

	cmd := exec.Command(editor, tempFile.Name())
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return nil, err
	}

	return os.ReadFile(tempFile.Name())
}
