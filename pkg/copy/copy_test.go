package copy

import (
	"context"
	"testing"

	"github.com/spf13/afero"
)

func TestCopyDirExcludes(t *testing.T) {
	srcFs := afero.NewMemMapFs()
	dstFs := afero.NewMemMapFs()

	_ = srcFs.MkdirAll("src/sub", 0755)
	_ = afero.WriteFile(srcFs, "src/a.txt", []byte("a"), 0644)
	_ = afero.WriteFile(srcFs, "src/.DS_Store", []byte("ds"), 0644)
	_ = afero.WriteFile(srcFs, "src/sub/b.txt", []byte("b"), 0644)
	_ = afero.WriteFile(srcFs, "src/sub/.DS_Store", []byte("ds"), 0644)
	_ = afero.WriteFile(srcFs, "src/sub/ignore.tmp", []byte("tmp"), 0644)

	cp := New(srcFs, dstFs)
	cp.SetExcludes([]string{".DS_Store", "*.tmp"})

	err := cp.Dir(context.Background(), "src", "dst")
	if err != nil {
		t.Fatalf("Dir failed: %v", err)
	}

	if exists, _ := afero.Exists(dstFs, "dst/a.txt"); !exists {
		t.Errorf("expected dst/a.txt to exist")
	}
	if exists, _ := afero.Exists(dstFs, "dst/sub/b.txt"); !exists {
		t.Errorf("expected dst/sub/b.txt to exist")
	}
	if exists, _ := afero.Exists(dstFs, "dst/.DS_Store"); exists {
		t.Errorf("expected dst/.DS_Store to be excluded")
	}
	if exists, _ := afero.Exists(dstFs, "dst/sub/.DS_Store"); exists {
		t.Errorf("expected dst/sub/.DS_Store to be excluded")
	}
	if exists, _ := afero.Exists(dstFs, "dst/sub/ignore.tmp"); exists {
		t.Errorf("expected dst/sub/ignore.tmp to be excluded")
	}
}
