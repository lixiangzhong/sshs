package main

import (
	"bytes"
	"io"
	"io/ioutil"
	"sshs/progress"
)

func main() {
	buf := bytes.NewBufferString("")
	bar := progress.NewBar()
	bar.Add("testname", buf.Len())
	r := io.TeeReader(buf, bar)
	io.CopyBuffer(ioutil.Discard, r, make([]byte, 4))
	buf.WriteString("123")
	bar.Add("xxx", buf.Len())
	io.CopyBuffer(ioutil.Discard, r, make([]byte, 4))
	bar.Close()
}
