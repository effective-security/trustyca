package appcontainer

import (
	"testing"

	"github.com/cockroachdb/errors"
	"github.com/stretchr/testify/assert"
)

func TestCloser(t *testing.T) {
	c := NewCloser(10)

	c.OnClose(&closer{closed: false})
	c.OnClose(&closer{closed: true})
	err := c.Close()
	assert.EqualError(t, err, "already closed")
	assert.EqualError(t, err, "already closed")
}

type closer struct {
	closed bool
}

func (c *closer) Close() error {
	if c.closed {
		return errors.New("already closed")
	}
	c.closed = true
	return nil
}
