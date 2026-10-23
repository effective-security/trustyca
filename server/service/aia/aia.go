package aia

import (
	"context"
	"encoding/base64"
	"encoding/pem"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/porto/restserver"
	"github.com/effective-security/porto/xhttp/header"
	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/effective-security/porto/xhttp/marshal"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/trustyca/internal/metricskey"
	"github.com/effective-security/xdb"
	"github.com/effective-security/xlog"
	"golang.org/x/crypto/ocsp"
)

// The media types of the binary routes (RFC 2585, RFC 6960)
const (
	contentTypeCert         = "application/pkix-cert"
	contentTypeCRL          = "application/pkix-crl"
	contentTypeOCSPResponse = "application/ocsp-response"
)

// The headers of the cacheable responses that porto does not name
const (
	headerETag         = "ETag"
	headerExpires      = "Expires"
	headerIfNoneMatch  = "If-None-Match"
	headerLastModified = "Last-Modified"
	headerPragma       = "Pragma"
)

// The Cache-Control of the responses: an issuer certificate never changes
// for its key identifier (certMaxAge), a CRL and an OCSP response are
// valid until their NextUpdate, and an error is not cached
const (
	cacheControlPublic  = "public, no-transform, must-revalidate, max-age="
	cacheControlNoStore = "no-store"
	pragmaNoCache       = "no-cache"
	certMaxAge          = 24 * time.Hour
)

// The route parameters of the binary routes
const (
	paramIKID = "ikid"
	paramBody = "body"
)

// cacheMetricOCSP is the type tag of the cache metrics of OCSP responses
const cacheMetricOCSP = "ocsp"

// maxOCSPRequestSize bounds the body of an OCSP POST (RFC 6960 A.1): a
// request is a few hundred bytes, one with a nonce or several certificates
// a few kilobytes, and the responder is public
const maxOCSPRequestSize = 8 * 1024

// caCallTimeout bounds the forwarding of an OCSP request to the CA
const caCallTimeout = 15 * time.Second

// IssuerHandler serves the certificate of the issuer with the key
// identifier in DER, the AIA caIssuers URL of the certificates it issued
func (s *Service) IssuerHandler() restserver.Handle {
	return func(w http.ResponseWriter, r *http.Request, p restserver.Params) {
		ikid := p.ByName(paramIKID)
		row, err := s.issuedIssuer(r.Context(), ikid)
		if err != nil {
			metricskey.AIADownloadFailCert.IncrCounter(1)
			marshal.WriteJSON(w, r, err)
			return
		}
		der, err := derOf(row.Pem)
		if err != nil {
			metricskey.AIADownloadFailCert.IncrCounter(1)
			logger.ContextKV(r.Context(), xlog.ERROR,
				"reason", "invalid_issuer_pem",
				"ikid", ikid,
				"err", err.Error())
			marshal.WriteJSON(w, r, httperror.Unexpected("unable to decode certificate"))
			return
		}
		metricskey.AIADownloadSuccessCert.IncrCounter(1)
		now := time.Now()
		writeCacheable(w, r, contentTypeCert, der, row.NotBefore.UTC(), now.Add(certMaxAge))
	}
}

// CRLHandler serves the current CRL of the issuer with the key identifier
// in DER, the CRL Distribution Point of the certificates it issued
func (s *Service) CRLHandler() restserver.Handle {
	return func(w http.ResponseWriter, r *http.Request, p restserver.Params) {
		ikid := p.ByName(paramIKID)
		row, err := s.db.GetCrl(r.Context(), ikid)
		if err != nil {
			metricskey.AIADownloadFailCrl.IncrCounter(1)
			if xdb.IsNotFoundError(err) {
				marshal.WriteJSON(w, r, httperror.NotFound("CRL not found"))
				return
			}
			marshal.WriteJSON(w, r, httperror.Unexpected("unable to find CRL").WithCause(err))
			return
		}
		der, err := derOf(row.Pem)
		if err != nil {
			metricskey.AIADownloadFailCrl.IncrCounter(1)
			logger.ContextKV(r.Context(), xlog.ERROR,
				"reason", "invalid_crl_pem",
				"ikid", ikid,
				"err", err.Error())
			marshal.WriteJSON(w, r, httperror.Unexpected("unable to decode CRL"))
			return
		}
		metricskey.AIADownloadSuccessCrl.IncrCounter(1)
		writeCacheable(w, r, contentTypeCRL, der, row.ThisUpdate.UTC(), row.NextUpdate.UTC())
	}
}

// issuedIssuer returns the issuer with the key identifier when it has a
// certificate; a Pending issuer, which has none, is not found
func (s *Service) issuedIssuer(ctx context.Context, ikid string) (*model.Issuer, error) {
	row, err := s.db.GetIssuerBySKID(ctx, ikid)
	if err != nil {
		if xdb.IsNotFoundError(err) {
			return nil, httperror.NotFound("issuer not found")
		}
		return nil, httperror.Unexpected("unable to find issuer").WithCause(err)
	}
	if row.Status == pb.IssuerStatus_Pending || row.Pem == "" {
		return nil, httperror.NotFound("issuer not found")
	}
	return row, nil
}

// GetOcspHandler answers an OCSP request sent as the URL-encoded base64 of
// its DER encoding in the path (RFC 6960 A.1); the issuer segment of the
// route by issuer is not needed to answer, the request carries the issuer
func (s *Service) GetOcspHandler() restserver.Handle {
	return func(w http.ResponseWriter, r *http.Request, p restserver.Params) {
		query := p.ByName(paramBody)
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

// ocspResponse answers a DER OCSP request: from the cache while the cached
// response is before its NextUpdate, else with the response the CA signs,
// which is cached. Every answer is an OCSP response (RFC 6960 section
// 4.2.1): a request that does not parse is malformedRequest with 400, an
// issuer the CA does not serve is unauthorized with 404, a CA that cannot
// be reached is tryLater with 503, and any other failure is internalError
// with 500; the error responses are not cached.
func (s *Service) ocspResponse(w http.ResponseWriter, r *http.Request, requestBody []byte) {
	ctx := r.Context()
	wh := w.Header()
	wh.Set(header.ContentType, contentTypeOCSPResponse)

	ocspReq, err := ocsp.ParseRequest(requestBody)
	if err != nil || ocspReq.SerialNumber == nil {
		metricskey.AIADownloadFailOCSP.IncrCounter(1)
		writeOCSPError(w, http.StatusBadRequest, ocsp.MalformedRequestErrorResponse)
		return
	}
	serial := ocspReq.SerialNumber.String()

	now := time.Now()
	key := keyOf(requestBody)
	if e, ok := s.cache.get(key, now); ok {
		metricskey.AIACacheHit.IncrCounter(1, cacheMetricOCSP)
		metricskey.AIADownloadSuccessOCSP.IncrCounter(1)
		writeCacheable(w, r, contentTypeOCSPResponse, e.der, e.thisUpdate, e.nextUpdate)
		return
	}
	metricskey.AIACacheMiss.IncrCounter(1, cacheMetricOCSP)

	ca, err := s.signer()
	if err != nil {
		metricskey.AIADownloadFailOCSP.IncrCounter(1)
		logger.ContextKV(ctx, xlog.ERROR,
			"reason", "backend",
			"serial", serial,
			"err", err.Error())
		writeOCSPError(w, http.StatusServiceUnavailable, ocsp.TryLaterErrorResponse)
		return
	}
	cctx, cancel := context.WithTimeout(ctx, caCallTimeout)
	defer cancel()
	res, err := ca.SignOCSP(cctx, &pb.OCSPRequest{Der: requestBody})
	if err != nil {
		metricskey.AIADownloadFailOCSP.IncrCounter(1)
		status := httperror.Status(err)
		logger.ContextKV(ctx, xlog.WARNING,
			"reason", "sign_ocsp",
			"serial", serial,
			"status", status,
			"err", err.Error())
		switch status {
		case http.StatusBadRequest:
			writeOCSPError(w, http.StatusBadRequest, ocsp.MalformedRequestErrorResponse)
		case http.StatusNotFound:
			writeOCSPError(w, http.StatusNotFound, ocsp.UnauthorizedErrorResponse)
		case http.StatusServiceUnavailable, http.StatusRequestTimeout, http.StatusGatewayTimeout, http.StatusTooManyRequests:
			writeOCSPError(w, http.StatusServiceUnavailable, ocsp.TryLaterErrorResponse)
		default:
			writeOCSPError(w, http.StatusInternalServerError, ocsp.InternalErrorErrorResponse)
		}
		return
	}
	metricskey.AIADownloadSuccessOCSP.IncrCounter(1)

	// the validity of the response decides the caching; the signature is
	// the CA's and is not verified here
	parsed, err := ocsp.ParseResponse(res.Der, nil)
	if err != nil {
		logger.ContextKV(ctx, xlog.ERROR,
			"reason", "invalid_ocsp_response",
			"serial", serial,
			"err", err.Error())
		wh.Set(header.CacheControl, cacheControlNoStore)
		wh.Set(headerPragma, pragmaNoCache)
		_, _ = w.Write(res.Der)
		return
	}
	e := &ocspEntry{
		der:        res.Der,
		thisUpdate: parsed.ThisUpdate,
		nextUpdate: parsed.NextUpdate,
		etag:       etagOf(res.Der),
	}
	if now.Before(e.nextUpdate) {
		s.cache.add(key, e)
	}
	writeCacheable(w, r, contentTypeOCSPResponse, e.der, e.thisUpdate, e.nextUpdate)
}

// writeOCSPError writes an OCSP error response with the HTTP status; it is
// never cached
func writeOCSPError(w http.ResponseWriter, status int, response []byte) {
	wh := w.Header()
	wh.Set(header.ContentType, contentTypeOCSPResponse)
	wh.Set(header.CacheControl, cacheControlNoStore)
	wh.Set(headerPragma, pragmaNoCache)
	w.WriteHeader(status)
	_, _ = w.Write(response)
}

// writeCacheable writes a body that is valid from lastModified until
// expires: Cache-Control allows public caches to keep it until then (or
// forbids caching when it has expired), Last-Modified and Expires carry the
// two times, and ETag is the hash of the body, which a conditional request
// gets Not Modified for
func writeCacheable(w http.ResponseWriter, r *http.Request, contentType string, body []byte, lastModified, expires time.Time) {
	etag := etagOf(body)
	wh := w.Header()
	wh.Set(header.ContentType, contentType)
	wh.Set(headerETag, etag)
	wh.Set(headerLastModified, lastModified.UTC().Format(http.TimeFormat))
	wh.Set(headerExpires, expires.UTC().Format(http.TimeFormat))
	if maxAge := time.Until(expires); maxAge > 0 {
		wh.Set(header.CacheControl, cacheControlPublic+strconv.FormatInt(int64(maxAge/time.Second), 10))
	} else {
		wh.Set(header.CacheControl, cacheControlNoStore)
		wh.Set(headerPragma, pragmaNoCache)
	}
	if r.Header.Get(headerIfNoneMatch) == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	_, _ = w.Write(body)
}

// derOf returns the DER encoding of the first block of a PEM encoding
func derOf(pemText string) ([]byte, error) {
	block, _ := pem.Decode([]byte(pemText))
	if block == nil {
		return nil, errors.New("no PEM block")
	}
	return block.Bytes, nil
}
