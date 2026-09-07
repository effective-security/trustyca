package appcontainer

import (
	"io"
	"sync"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/xlog"
)

// Closer provides a closer interface
type Closer struct {
	closers []io.Closer
	closed  bool
	lock    sync.RWMutex
}

// NewCloser returns new instance of a closer
func NewCloser(capacity int) *Closer {
	return &Closer{
		closers: make([]io.Closer, 0, capacity),
	}
}

// OnClose adds a closer to be called when application exists
func (a *Closer) OnClose(closer io.Closer) {
	if closer == nil {
		return
	}

	a.lock.Lock()
	defer a.lock.Unlock()

	a.closers = append(a.closers, closer)
}

// Close implements Closer interface to clean up resources
func (a *Closer) Close() error {
	a.lock.Lock()
	defer a.lock.Unlock()

	if a.closed {
		return errors.New("already closed")
	}

	var lastErr error
	a.closed = true
	// close in reverse order
	for i := len(a.closers) - 1; i >= 0; i-- {
		closer := a.closers[i]
		if closer != nil {
			err := closer.Close()
			if err != nil {
				lastErr = err
				logger.KV(xlog.ERROR, "err", err.Error())
			}
		}
	}

	return lastErr
}
