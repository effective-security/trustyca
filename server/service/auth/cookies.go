package auth

import (
	"net/http"
	"time"

	"github.com/effective-security/porto/gserver/roles"
	"github.com/effective-security/porto/restserver"
	"github.com/effective-security/xpki/certutil"
)

// RemoveCookieHandler returns handler for removing the auth cookie
func (s *Service) RemoveCookieHandler() restserver.Handle {
	return func(w http.ResponseWriter, r *http.Request, _ restserver.Params) {
		ccfg := s.server.Configuration().IdentityMap.GetCookiesConfig()
		resetAuthCookie(w, ccfg)
		w.WriteHeader(http.StatusNoContent)
	}
}

func setAuthCookie(w http.ResponseWriter, cfg roles.CookiesConfig, token string, validFor time.Duration) {
	maxAge := 0
	if validFor > 0 {
		maxAge = int(validFor.Seconds())
	}

	if cfg.Auth != "" {
		http.SetCookie(w, &http.Cookie{
			Name:     cfg.Auth,
			Value:    token,
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteNoneMode,
			MaxAge:   maxAge,
			Domain:   cfg.Domain,
		})
	}
	if cfg.CSRF != "" {
		http.SetCookie(w, &http.Cookie{
			Name:     cfg.CSRF,
			Value:    certutil.RandomString(32),
			Path:     "/",
			HttpOnly: false,
			Secure:   true,
			SameSite: http.SameSiteNoneMode,
			MaxAge:   maxAge,
			Domain:   cfg.Domain,
		})
	}
}

func resetAuthCookie(w http.ResponseWriter, cfg roles.CookiesConfig) {
	if cfg.Auth != "" {
		http.SetCookie(w, &http.Cookie{
			Name:     cfg.Auth,
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteNoneMode,
			MaxAge:   -1,
			Domain:   cfg.Domain,
		})
	}
	if cfg.CSRF != "" {
		http.SetCookie(w, &http.Cookie{
			Name:     cfg.CSRF,
			Value:    certutil.RandomString(32),
			Path:     "/",
			HttpOnly: false,
			Secure:   true,
			SameSite: http.SameSiteNoneMode,
			MaxAge:   -1,
			Domain:   cfg.Domain,
		})
	}
}
