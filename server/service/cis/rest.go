package cis

import (
	"encoding/base64"
	"io"
	"net/http"
	"net/url"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/porto/restserver"
	"github.com/effective-security/porto/xhttp/header"
	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/effective-security/porto/xhttp/marshal"
	"golang.org/x/crypto/ocsp"
)

func (s *Service) IssuerHandler() restserver.Handle {
	return func(w http.ResponseWriter, r *http.Request, p restserver.Params) {
		// TODO
		/*
			ikid := p.ByName("issuer_id")

				// if strings.HasSuffix(ikid, ".crl") {
				// 	ikid = ikid[0 : len(ikid)-4]
				// }

			logger.KV(xlog.TRACE, "ikid", ikid)

			ctx := r.Context()
			m, err := s.db.GetCrl(ctx, ikid)
			if err != nil {
				if xdb.IsNotFoundError(err) {
					// metrics for Not Found
					metricskey.AIADownloadFailCrl.IncrCounter(1)
					marshal.WriteJSON(w, r, httperror.NotFound("unable to locate CRL"))

				} else {
					marshal.WriteJSON(w, r, httperror.Unexpected("unable to locate CRL").WithCause(err))
				}
				return
			}

			block, _ := pem.Decode([]byte(m.Pem))

			metricskey.AIADownloadSuccessCrl.IncrCounter(1)

			wh := w.Header()
			wh.Set(header.ContentType, "application/pkix-crl")
			wh.Set("Cache-Control", "no-store")
			wh.Set("Pragma", "no-cache")
			_, _ = w.Write(block.Bytes)
		*/
	}
}

func (s *Service) CRLHandler() restserver.Handle {
	return func(w http.ResponseWriter, r *http.Request, p restserver.Params) {
		// TODO
		/*
			skid := p.ByName("subject_id")

				// if strings.HasSuffix(skid, ".crt") {
				// 	skid = skid[0 : len(skid)-4]
				// }

			logger.KV(xlog.TRACE, "skid", skid)

			ctx := r.Context()
			list, err := s.db.GetCertificatesBySKID(ctx, skid)
			if err != nil {
				if xdb.IsNotFoundError(err) {
					// metrics for Not Found
					metricskey.AIADownloadFailCert.IncrCounter(1)
					marshal.WriteJSON(w, r, httperror.NotFound("unable to locate certificate"))

				} else {
					marshal.WriteJSON(w, r, httperror.Unexpected("unable to locate certificate").WithCause(err))
				}
				return
			} else if len(list) == 0 {
				marshal.WriteJSON(w, r, httperror.NotFound("unable to locate certificate"))
				return
			}

			block, _ := pem.Decode([]byte(list[0].Pem))
			metricskey.AIADownloadSuccessCert.IncrCounter(1)

			w.Header().Set(header.ContentType, "application/pkix-cert")
			_, _ = w.Write(block.Bytes)
		*/
	}
}

// GetOcspHandler returns OCSP via GET
func (s *Service) GetOcspHandler() restserver.Handle {
	return func(w http.ResponseWriter, r *http.Request, p restserver.Params) {
		query := p.ByName("body")
		base64Request, err := url.QueryUnescape(query)
		if err != nil {
			marshal.WriteJSON(w, r, httperror.InvalidRequest("unable to parse query"))
			return
		}

		// url.QueryUnescape not only unescapes %2B escaping, but it additionally
		// turns the resulting '+' into a space, which makes base64 decoding fail.
		// So we go back afterwards and turn ' ' back into '+'. This means we
		// accept some malformed input that includes ' ' or %20, but that's fine.
		base64RequestBytes := []byte(base64Request)
		for i := range base64RequestBytes {
			if base64RequestBytes[i] == ' ' {
				base64RequestBytes[i] = '+'
			}
		}
		// In certain situations a UA may construct a request that has a double
		// slash between the host name and the base64 request body due to naively
		// constructing the request URL. In that case strip the leading slash
		// so that we can still decode the request.
		if len(base64RequestBytes) > 0 && base64RequestBytes[0] == '/' {
			base64RequestBytes = base64RequestBytes[1:]
		}
		requestBody, err := base64.StdEncoding.DecodeString(string(base64RequestBytes))
		if err != nil {
			marshal.WriteJSON(w, r, httperror.InvalidRequest("unable to parse request"))
			return
		}
		s.ocspResponse(w, r, requestBody)
	}
}

// maxOCSPRequestSize bounds the body of an OCSP POST (RFC 6960 A.1): a
// request is a few hundred bytes, one with a nonce or several certificates
// a few kilobytes, and the responder is public
const maxOCSPRequestSize = 8 * 1024

// OCSPHandler answers an OCSP request posted as the body, which is read up
// to maxOCSPRequestSize whatever the request declares
func (s *Service) OCSPHandler() restserver.Handle {
	return func(w http.ResponseWriter, r *http.Request, p restserver.Params) {
		requestBody, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxOCSPRequestSize))
		if err != nil {
			var tooLarge *http.MaxBytesError
			if errors.As(err, &tooLarge) {
				marshal.WriteJSON(w, r, httperror.RequestTooLarge("request exceeds %d bytes", maxOCSPRequestSize))
				return
			}
			marshal.WriteJSON(w, r, httperror.Unexpected("unable to read request"))
			return
		}

		s.ocspResponse(w, r, requestBody)
	}
}

/* TODO
var (
	malformedRequestErrorResponse = []byte{0x30, 0x03, 0x0A, 0x01, 0x01}
	internalErrorErrorResponse    = []byte{0x30, 0x03, 0x0A, 0x01, 0x02}
	//tryLaterErrorResponse         = []byte{0x30, 0x03, 0x0A, 0x01, 0x03}
	//sigRequredErrorResponse       = []byte{0x30, 0x03, 0x0A, 0x01, 0x05}
	unauthorizedErrorResponse = []byte{0x30, 0x03, 0x0A, 0x01, 0x06}
)
*/

// OCSPResponder represents the logical source of OCSP responses, i.e.,
// the logic that actually chooses a response based on a request.
// In order to create an actual responder, wrap one of these in a Responder
// object and pass it to http.Handle.
// By default the Responder will set the headers:
//
// Cache-Control to "max-age=(response.NextUpdate-now), public, no-transform, must-revalidate",
// Last-Modified to response.ThisUpdate,
// Expires to response.NextUpdate,
// ETag to the SHA256 hash of the response,
// Content-Type to application/ocsp-response.
//
// To override these headers, or set extra headers,
// OCSPResponder should return a http.Header with the headers to override,
// or nil otherwise.
type OCSPResponder interface {
	Response(*ocsp.Request) ([]byte, http.Header, error)
}

func (s *Service) ocspResponse(w http.ResponseWriter, r *http.Request, requestBody []byte) {
	// All responses after this point will be OCSP.
	// We could check for the content type of the request, but that
	// seems unnecessariliy restrictive.
	wh := w.Header()
	wh.Set(header.ContentType, "application/ocsp-response")
	wh.Set("Cache-Control", "no-store")
	wh.Set("Pragma", "no-cache")

	/* TODO
	res, err := s.ca.SignOCSP(r.Context(), &pb.OCSPRequest{Der: requestBody})
	if err != nil {
		logger.ContextKV(r.Context(), xlog.WARNING, "err", err.Error())
		metricskey.AIADownloadFailOCSP.IncrCounter(1)

		switch httperror.Status(err) {
		case http.StatusBadRequest:
			_, _ = w.Write(malformedRequestErrorResponse)
			return
		case http.StatusNotFound:
			_, _ = w.Write(unauthorizedErrorResponse)
			return
		}

		_, _ = w.Write(internalErrorErrorResponse)
		return
	}

	metricskey.AIADownloadSuccessOCSP.IncrCounter(1)

	_, _ = w.Write(res.Der)
	*/
}
