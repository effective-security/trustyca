package ui

import (
	"bytes"
	"embed"
	"html/template"
	"net/http"
	"strings"

	"github.com/effective-security/porto/restserver"
	"github.com/effective-security/porto/xhttp/header"
	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/effective-security/porto/xhttp/marshal"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/xlog"
)

//go:embed static/*.html
var staticFS embed.FS

// pages holds every template in static/: the shared layout partials
// and one template per page, addressed by file name.
var pages = template.Must(template.ParseFS(staticFS, "static/*.html"))

// Template names, as the files in static/
const (
	indexPage         = "index.html"
	loginPage         = "login.html"
	authenticatedPage = "authenticated.html"
	paymentPage       = "payment.html"
)

// pageTitles provides the <title> for each page
var pageTitles = map[string]string{
	indexPage:         "Trusty",
	loginPage:         "Login",
	authenticatedPage: "Authenticated",
	paymentPage:       "Payment",
}

// pagesByPath maps a route to the page template it renders
var pagesByPath = map[string]string{
	"/":                         indexPage,
	pb.PathForLoginPage:         loginPage,
	pb.PathForAuthenticatedPage: authenticatedPage,
	pb.PathForPaymentPage:       paymentPage,
}

var alive = []byte("ALIVE")

// pageData is passed to the page templates.
// Only public, non-secret configuration values belong here,
// as they are rendered into the HTML sent to the browser.
type pageData struct {
	Title string
	// RecaptchaSiteKey is the reCAPTCHA v3 site key; empty disables reCAPTCHA on the login page
	RecaptchaSiteKey string
	// StripePublishableKey is the Stripe publishable key for Stripe.js; empty disables the checkout widget
	StripePublishableKey string
}

func (s *Service) pageData(name string) pageData {
	d := pageData{
		Title: pageTitles[name],
	}
	if s.cfg != nil {
		d.RecaptchaSiteKey = s.cfg.Auth.RecaptchaSiteKey
		// TODO: payments?
		// if s.cfg.TrustyRA.Payments != nil {
		// 	d.StripePublishableKey = s.cfg.Trusty.Payments.PublishableKey
		// }
	}
	return d
}

// indexHandler handles "/".
// Browsers, which accept text/html, get the index page;
// load balancers and CLI tools get the plain ALIVE status
// that this path has always returned.
func (s *Service) indexHandler() restserver.Handle {
	return func(w http.ResponseWriter, r *http.Request, _ restserver.Params) {
		if acceptsHTML(r) {
			s.renderPage(w, r, indexPage)
			return
		}
		w.Header().Set(header.ContentType, header.TextPlain)
		_, _ = w.Write(alive)
	}
}

// PageHandler renders the page registered for the route path.
// An unknown path renders nothing and responds with an error.
func (s *Service) PageHandler(path string) restserver.Handle {
	name := pagesByPath[path]
	return func(w http.ResponseWriter, r *http.Request, _ restserver.Params) {
		s.renderPage(w, r, name)
	}
}

func (s *Service) renderPage(w http.ResponseWriter, r *http.Request, name string) {
	// render to a buffer first, so a template error
	// does not leave a half-written page behind a 200 status
	var buf bytes.Buffer
	err := pages.ExecuteTemplate(&buf, name, s.pageData(name))
	if err != nil {
		logger.ContextKV(r.Context(), xlog.ERROR, "reason", "render_page", "page", name, "err", err.Error())
		marshal.WriteJSON(w, r, httperror.Unexpected("failed to render page"))
		return
	}

	wh := w.Header()
	wh.Set(header.ContentType, "text/html; charset=utf-8")
	// the pages embed configuration values, do not let proxies cache them
	wh.Set("Cache-Control", "no-store")
	_, _ = w.Write(buf.Bytes())
}

func acceptsHTML(r *http.Request) bool {
	return strings.Contains(r.Header.Get(header.Accept), "text/html")
}
