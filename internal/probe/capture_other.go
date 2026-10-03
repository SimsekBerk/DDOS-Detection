//go:build !darwin

package probe

import (
	"errors"
	"time"
)

type capture struct{}

func openCapture(string, int, bool) (*capture, error) {
	return nil, errors.New("ddos-probe şu an yalnızca macOS'ta çalışıyor; Linux'ta softflowd/pmacct veya router export kullanın")
}

func (c *capture) read(func([]byte, int, time.Time)) error { return nil }
func (c *capture) drops() uint64                           { return 0 }
func (c *capture) close() error                            { return nil }
