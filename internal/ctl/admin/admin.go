package admin

import (
	"context"
	"io"

	"github.com/effective-security/porto/pkg/retriable"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/privpb"
)

type App interface {
	// Context returns the context for the application
	Context() context.Context
	// Writer returns a writer for control output
	Writer() io.Writer
	// ErrWriter returns a writer for error output
	ErrWriter() io.Writer
	// Reader is the source to read from, typically set to os.Stdin
	Reader() io.Reader
	// Print prints the value to the writer
	Print(value any) error

	HTTPClient(skipAuth bool) (*retriable.Client, error)
	AuthClient(skipAuth bool) (pb.AuthServer, error)
	StatusClient() (pb.StatusServer, error)
	OrgsClient() (pb.OrgsServer, error)
	AdminClient() (privpb.AdminServer, error)
}
