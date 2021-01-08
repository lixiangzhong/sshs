package progress

import (
	"fmt"
	"io"

	"github.com/gosuri/uiprogress"
)

var _ io.Writer = &Bar{}

func NewBar() *Bar {
	b := &Bar{
		p: uiprogress.New(),
	}
	b.p.Start()
	return b
}

type Bar struct {
	p       *uiprogress.Progress
	bar     *uiprogress.Bar
	current int
}

func (b *Bar) Write(p []byte) (int, error) {
	n := len(p)
	b.current += n
	err := b.bar.Set(b.current)
	return n, err
}

func (b *Bar) Close() error {
	b.p.Stop()
	return nil
}

func (b *Bar) Add(name string, total int) {
	b.bar = b.p.AddBar(total).PrependFunc(func(b *uiprogress.Bar) string {
		return fmt.Sprintf("%s(%d/%d)", name, b.Current(), total)
	}).AppendFunc(func(b *uiprogress.Bar) string {
		return fmt.Sprintf("%v", b.CompletedPercentString())
	})
	b.current = 0
}
