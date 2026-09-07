package testutils

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/porto/xhttp/header"
	"github.com/effective-security/porto/xhttp/identity"
	"github.com/effective-security/trustyca/internal/authctx"
)

// CreateRequest helper
func CreateRequest(method string, url string, req any, user identity.Identity) (*httptest.ResponseRecorder, *http.Request, error) {
	var body io.Reader
	if req != nil {
		js, err := json.Marshal(req)
		if err != nil {
			return nil, nil, errors.WithStack(err)
		}
		body = bytes.NewReader(js)
	}

	r, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}
	// set test RequestID
	r.Header.Set(header.XCorrelationID, "123456")

	if user != nil {
		r = identity.WithTestIdentity(r, user) // legacy way
		rc := identity.NewRequestContext(user, "")
		r = r.WithContext(authctx.NewTrustyCtx(r.Context(), rc))
	}
	return httptest.NewRecorder(), r, nil
}
