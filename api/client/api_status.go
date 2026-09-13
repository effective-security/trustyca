package client

import (
	"context"

	"github.com/effective-security/porto/pkg/retriable"
	"github.com/effective-security/trustyca/api/pb"
)

// HTTPStatusClient provides Status over legacy HTTP
type HTTPStatusClient struct {
	client retriable.HTTPClient
}

// NewHTTPStatusClient returns legacy HTTP client
func NewHTTPStatusClient(client retriable.HTTPClient) *HTTPStatusClient {
	return &HTTPStatusClient{client: client}
}

// Version returns ServerVersion
func (c *HTTPStatusClient) Version(ctx context.Context) (*pb.ServerVersion, error) {
	r := new(pb.ServerVersion)
	_, _, err := c.client.Get(ctx, pb.Status_Version_FullMethodName, r)
	if err != nil {
		return nil, err
	}
	return r, err
}

// Status returns ServerStatusResponse
func (c *HTTPStatusClient) Status(ctx context.Context) (*pb.ServerStatusResponse, error) {
	r := new(pb.ServerStatusResponse)
	_, _, err := c.client.Get(ctx, pb.Status_Server_FullMethodName, r)
	if err != nil {
		return nil, err
	}
	return r, err
}

// AuthURL returns AuthURLResponse
func (c *HTTPStatusClient) AuthURL(ctx context.Context, email string) (*pb.AuthProvidersResponse, error) {
	r := new(pb.AuthProvidersResponse)
	var err error
	if email == "" {
		_, _, err = c.client.Get(ctx, pb.PathForAuthProviders, r)
	} else {
		_, _, err = c.client.Post(ctx, pb.PathForAuthProviders, &pb.AuthProvidersRequest{Email: email}, r)
	}

	if err != nil {
		return nil, err
	}
	return r, err
}
