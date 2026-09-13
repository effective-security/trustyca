package cis

import (
	"net/http"

	"github.com/effective-security/porto/restserver"
)

func (s *Service) IssuerHandler() restserver.Handle {
	return func(w http.ResponseWriter, r *http.Request, p restserver.Params) {
		// TODO
	}
}

func (s *Service) CRLHandler() restserver.Handle {
	return func(w http.ResponseWriter, r *http.Request, p restserver.Params) {
		// TODO
	}
}

func (s *Service) OCSPHandler() restserver.Handle {
	return func(w http.ResponseWriter, r *http.Request, p restserver.Params) {
		// TODO
	}
}
