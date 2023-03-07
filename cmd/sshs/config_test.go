package main

import (
	"testing"
)

func Test_configFileList(t *testing.T) {
	list := configFileList("1", "2")
	t.Log(list)
}
