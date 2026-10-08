package command

import (
	"context"
	"crypto"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/porto/pkg/retriable"
	"github.com/effective-security/porto/xhttp/header"
	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/effective-security/porto/xhttp/marshal"
	"github.com/effective-security/trustyca/api/cli/command/uname"
	"github.com/effective-security/trustyca/api/client"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/x/slices"
	"github.com/effective-security/x/urlutil"
	"github.com/effective-security/xlog"
	"github.com/effective-security/xpki/certutil"
	"github.com/effective-security/xpki/jwt/dpop"
	"golang.org/x/oauth2"
	"google.golang.org/protobuf/types/known/emptypb"
)

var logger = xlog.NewPackageLogger("github.com/effective-security/trustyca/cli", "command")

// AuthCmd is the parent for auth command
type AuthCmd struct {
	Providers ProvidersCmd `cmd:"" help:"print ID providers"`
	Login     LoginCmd     `cmd:"" help:"login to the server"`
	UI        UICmd        `cmd:"" help:"login to the server via its web login page"`
	Claims    UserinfoCmd  `cmd:"" help:"print OAuth token claims"`
	Usertoken UserTokenCmd `cmd:"" help:"print user token"`
	Revoke    RevokeCmd    `cmd:"" help:"revoke user token"`
	Org       SelectOrgCmd `cmd:"" help:"select the org for the session and store the new token"`
	Allowed   AllowedCmd   `cmd:"" help:"print allowed methods"`
	Scope     ScopeCmd     `cmd:"" help:"print the caller scope and method access rules"`
}

// AllowedCmd prints allowed methods
type AllowedCmd struct {
}

// Run the command
func (a *AllowedCmd) Run(app App) error {
	client, err := app.AuthClient(false)
	if err != nil {
		return err
	}
	res, err := client.GetAllowedMethods(app.Context(), &emptypb.Empty{})
	if err != nil {
		return err
	}
	w := app.Writer()
	for _, si := range res.Allowed {
		fmt.Fprintf(w, "%s:\n", si.Service)
		for _, method := range si.Methods {
			fmt.Fprintf(w, "  %s\n", method.Key)
		}
	}

	return nil
}

// ScopeCmd prints the caller scope
type ScopeCmd struct {
	Methods bool `help:"print the access rules of every method"`
}

// Run the command
func (a *ScopeCmd) Run(app App) error {
	client, err := app.AuthClient(false)
	if err != nil {
		return err
	}
	res, err := client.GetCallerScope(app.Context(), &emptypb.Empty{})
	if err != nil {
		return err
	}
	if !a.Methods {
		res.Methods = nil
	}
	return app.Print(res)
}

// SelectOrgCmd selects the org and stores the token issued for it
type SelectOrgCmd struct {
	OrgID   string `kong:"arg" help:"the ID of the org to select, see 'org list'"`
	NoStore bool   `help:"Specifies to not store the token in the local storage"`
}

// Run the command
func (a *SelectOrgCmd) Run(app App) error {
	client, err := app.AuthClient(false)
	if err != nil {
		return err
	}
	res, err := client.SelectOrg(app.Context(), &pb.SelectOrgRequest{OrgID: a.OrgID})
	if err != nil {
		return err
	}
	if !a.NoStore && res.Token != nil && res.Token.AccessToken != "" {
		hc, err := app.HTTPClient(true)
		if err != nil {
			return err
		}
		vals := url.Values{
			"access_token": {res.Token.AccessToken},
		}
		if res.Token.Jkt != "" {
			vals["dpop_jkt"] = []string{res.Token.Jkt}
		}
		if exp, err := time.Parse(time.RFC3339, res.Token.ExpiresAt); err == nil {
			vals["exp"] = []string{strconv.FormatInt(exp.Unix(), 10)}
		}
		_, err = hc.Storage().SaveAuthToken(vals.Encode())
		if err != nil {
			return errors.WithMessage(err, "unable to store token")
		}
	}
	return app.Print(res)
}

// RevokeCmd revokes user token
type RevokeCmd struct {
}

// Run the command
func (a *RevokeCmd) Run(app App) error {
	client, err := app.AuthClient(false)
	if err != nil {
		return err
	}

	_, err = client.RevokeToken(app.Context(), &emptypb.Empty{})
	if err != nil {
		return err
	}
	fmt.Fprintln(app.Writer(), "token revoked")

	return nil
}

// ProvidersCmd prints ID providers
type ProvidersCmd struct {
	Email string `help:"Specifies idpuser.email parameter"`
}

// Run the command
func (a *ProvidersCmd) Run(app App) error {
	client, err := app.AuthClient(true)
	if err != nil {
		return err
	}

	res, err := client.GetProviders(app.Context(), &pb.AuthProvidersRequest{
		Email: a.Email,
	})
	if err != nil {
		return err
	}
	app.Print(res)

	return nil
}

// UserinfoCmd prints caller id from the server
type UserinfoCmd struct {
}

// Run the command
func (a *UserinfoCmd) Run(app App) error {
	client, err := app.HTTPClient(false)
	if err != nil {
		return err
	}

	_, _, err = client.Get(app.Context(), pb.PathForAuthUserinfo, app.Writer())
	if err != nil {
		return err
	}

	return nil
}

// UserTokenCmd returns UserToken
type UserTokenCmd struct {
}

// Run the command
func (a *UserTokenCmd) Run(app App) error {
	client, err := app.AuthClient(false)
	if err != nil {
		return err
	}
	res, err := client.GetUserToken(app.Context(), &emptypb.Empty{})
	if err != nil {
		return err
	}

	app.Print(res)

	return nil
}

// LoginCmd starts login to the server
type LoginCmd struct {
	Provider string `kong:"arg" required:"" help:"provider type: google|github|... or email address"`
	DpopKey  string `help:"DPoP key label"`
	NoStore  bool   `help:"Specifies to not store token in the local storage"`
	Code     bool   `help:"Specifies to use code for token exchange" default:"true"`
	Hint     string `help:"Specifies Email login_hint parameter"`

	ListenPort int  `hidden:"" default:"38987"`
	NoBrowser  bool `help:"Specifies to disable opening browser"`
}

// Run the command
func (a *LoginCmd) Run(app App) error {
	c, err := app.HTTPClient(true)
	if err != nil {
		return err
	}

	var provider pb.IDP_Enum
	var email string
	if strings.Contains(a.Provider, "@") {
		email = a.Provider
	} else {
		provider = pb.IDPFromString(a.Provider)
		if provider == pb.IDP_Undefined {
			return errors.Errorf("unsupported provider: %s", a.Provider)
		}
	}

	urlRes, err := client.NewHTTPStatusClient(c).AuthURL(app.Context(), email)
	if err != nil {
		return err
	}

	if email == "" && provider != pb.IDP_Undefined && !slices.Contains(urlRes.Providers, provider) {
		return errors.Errorf("unsupported provider: choose from: %v", urlRes.Providers)
	}

	redirURL := fmt.Sprintf("http://localhost:%d/login", a.ListenPort)
	if a.NoBrowser {
		redirURL = c.CurrentHost() + pb.PathForAuthDone
	}
	conf := &oauth2.Config{
		ClientID:    "trustyca",
		RedirectURL: redirURL, // o.RedirectURL,
		Scopes:      []string{"openid", "email", "profile"},
		Endpoint: oauth2.Endpoint{
			AuthURL: urlRes.AuthURL,
		},
	}
	if a.DpopKey != "" {
		if a.DpopKey == "default" {
			keys, err := c.Storage().ListKeys()
			if err != nil {
				return errors.WithMessagef(err, "unable to list keys")
			}
			if len(keys) > 0 {
				a.DpopKey = keys[0].Thumbprint
			}
		}
		conf.Scopes = append(conf.Scopes, "dpop")
	}

	rt := "token"
	if a.Code {
		rt = "code"
	}

	codeVerifier := certutil.RandomString(48)
	opts := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("response_mode", "form_post"),
		oauth2.SetAuthURLParam("response_type", rt),
		oauth2.SetAuthURLParam("nonce", certutil.RandomString(8)),
	}
	if email != "" {
		opts = append(opts, oauth2.SetAuthURLParam("idpuser.email", email))
	} else {
		opts = append(opts, oauth2.SetAuthURLParam("provider", a.Provider))
	}
	if a.Hint != "" {
		opts = append(opts, oauth2.SetAuthURLParam("login_hint", a.Hint))
	}
	if a.Code {
		opts = append(opts,
			oauth2.SetAuthURLParam("code_challenge", certutil.SHA256Base64([]byte(codeVerifier))),
			oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		)
	}
	startURL := conf.AuthCodeURL(
		"", // no state
		opts...,
	)

	// if Key is provided, add DPoP to the request
	if a.DpopKey != "" {
		key, _, err := c.Storage().LoadKey(a.DpopKey)
		if err != nil {
			return errors.WithMessagef(err, "unable to load key")
		}
		signer, err := dpop.NewSigner(key.Key.(crypto.Signer))
		if err != nil {
			return errors.WithMessagef(err, "unable to create DPoP signer")
		}

		r, _ := http.NewRequest(http.MethodGet, startURL, nil)
		dpop, err := dpop.ForRequest(signer, r, nil)
		if err != nil {
			return err
		}
		// Add DPoP to the query string
		startURL += "&dpop=" + dpop
		logger.KV(xlog.DEBUG, "dpop", "signed", "url", startURL)
	}

	if a.NoBrowser {
		fmt.Fprintf(app.Writer(), "open auth URL in browser:\n%s\n", startURL)
		return nil
	}

	s := &svcState{
		writer:       app.Writer(),
		noStore:      a.NoStore,
		dpopKey:      a.DpopKey,
		listenPort:   a.ListenPort,
		responseType: rt,
		client:       c,
		codeVerifier: codeVerifier,
		done:         make(chan struct{}),
	}
	return s.waitForLogin(app.Context(), startURL)
}

// UICmd logs in via the server's web login page:
// the browser opens PathForLoginPage, where the user picks the ID provider,
// and the OAuth flow completes at the local listener like LoginCmd.
type UICmd struct {
	NoStore bool `help:"Specifies to not store token in the local storage"`

	ListenPort int  `hidden:"" default:"38987"`
	NoBrowser  bool `help:"Specifies to disable opening browser"`
}

// Run the command
func (a *UICmd) Run(app App) error {
	c, err := app.HTTPClient(true)
	if err != nil {
		return err
	}

	host := c.CurrentHost()
	authenticatedURL := host + pb.PathForAuthenticatedPage

	q := url.Values{
		"nonce": {certutil.RandomString(8)},
	}
	if a.NoBrowser {
		// without the local listener the token is shown
		// on the server's authenticated page
		q.Set("redirect_uri", authenticatedURL)
		q.Set("response_type", pb.OAuthResponseTypeToken)
		q.Set("response_mode", "fragment")

		fmt.Fprintf(app.Writer(), "open login URL in browser:\n%s\n", loginPageURL(host, q))
		return nil
	}

	codeVerifier := certutil.RandomString(48)
	q.Set("redirect_uri", fmt.Sprintf("http://localhost:%d/login", a.ListenPort))
	q.Set("response_type", pb.OAuthResponseTypeCode)
	q.Set("response_mode", "query")
	q.Set("code_challenge", certutil.SHA256Base64([]byte(codeVerifier)))
	q.Set("code_challenge_method", "S256")

	s := &svcState{
		writer:       app.Writer(),
		noStore:      a.NoStore,
		listenPort:   a.ListenPort,
		doneURL:      authenticatedURL,
		responseType: pb.OAuthResponseTypeCode,
		client:       c,
		codeVerifier: codeVerifier,
		done:         make(chan struct{}),
	}
	return s.waitForLogin(app.Context(), loginPageURL(host, q))
}

// loginPageURL returns the server's login page URL with the parameters
// the page passes through to the authorize end-point
func loginPageURL(host string, q url.Values) string {
	return host + pb.PathForLoginPage + "?" + q.Encode()
}

// loginShutdownTimeout bounds the wait for the last response
// to reach the browser once the login completes
const loginShutdownTimeout = 5 * time.Second

// waitForLogin serves the local callback listener, opens startURL in the
// browser and blocks until the callback completes the login.
func (s *svcState) waitForLogin(ctx context.Context, startURL string) error {
	// bind before opening the browser: a busy port must fail the command,
	// not send the browser to whatever else listens on it
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", s.listenPort))
	if err != nil {
		return errors.WithMessagef(err, "unable to listen on port %d, use --listen-port to choose another one", s.listenPort)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/login", s.loginHandler)
	mux.HandleFunc("/login/done", s.loginHandler)
	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	serveErr := make(chan error, 1)
	go func() {
		serveErr <- srv.Serve(ln)
	}()
	defer func() {
		// Shutdown waits for the handler that completed the login,
		// so its page reaches the browser before the process exits
		sctx, cancel := context.WithTimeout(context.Background(), loginShutdownTimeout)
		defer cancel()
		if err := srv.Shutdown(sctx); err != nil {
			logger.KV(xlog.DEBUG, "reason", "shutdown", "err", err.Error())
		}
		// Shutdown misses the listener if Serve has not started yet
		_ = ln.Close()
	}()

	err = openBrowserFn(startURL)
	if err != nil {
		return err
	}

	select {
	case <-s.done:
		return s.err
	case err = <-serveErr:
		return errors.WithMessage(err, "login listener stopped")
	case <-ctx.Done():
		return errors.WithStack(ctx.Err())
	}
}

type svcState struct {
	writer     io.Writer
	noStore    bool
	dpopKey    string
	listenPort int
	// doneURL is the page the browser is sent to once the token is received;
	// empty means the local /login/done page
	doneURL      string
	responseType string
	client       *retriable.Client
	codeVerifier string

	// done is closed when the login completes, err is its result
	done     chan struct{}
	doneOnce sync.Once
	err      error
}

// complete records the login result and releases the waiting command.
// Only the first call counts, so a reloaded page does not change the result.
func (s *svcState) complete(err error) {
	s.doneOnce.Do(func() {
		s.err = err
		close(s.done)
	})
}

func (s *svcState) loginHandler(w http.ResponseWriter, r *http.Request) {
	var err error
	done := r.URL.Path == "/login/done"
	defer func() {
		if done || err != nil {
			s.complete(err)
		}
	}()

	if done {
		_, _ = w.Write([]byte(`<body onload="window.close()">` +
			`<h2>Authenticated! You may close the browser now.</h2>` +
			`</body>`))
		return
	}

	var (
		token     string
		expiresIn string
		errCode   string
		errDescr  string
	)
	if r.Method == http.MethodPost {
		err = r.ParseForm()
		if err != nil {
			err = httperror.InvalidRequest("unable to parse response body")
			marshal.WriteJSON(w, r, err)
			return
		}

		token = r.Form.Get(s.responseType)
		expiresIn = r.Form.Get("expires_in")
		errCode = r.Form.Get("error")
		errDescr = r.Form.Get("error_description")
	} else {
		vals := r.URL.Query()
		token = urlutil.GetValue(vals, s.responseType)
		expiresIn = urlutil.GetValue(vals, "expires_in")
		errCode = urlutil.GetValue(vals, "error")
		errDescr = urlutil.GetValue(vals, "error_description")
	}
	if errCode != "" {
		err = httperror.New(http.StatusInternalServerError, errCode, "%s", errDescr)
		marshal.WriteJSON(w, r, err)
		return
	}

	if token == "" {
		err = httperror.InvalidRequest("missing token parameter")
		marshal.WriteJSON(w, r, err)
		return
	}

	if s.responseType == pb.OAuthResponseTypeCode {
		var res pb.Token
		_, _, err = s.client.Post(context.Background(), pb.Auth_ExchangeCode_FullMethodName, &pb.ExchangeCodeRequest{
			Code:     token,
			Verifier: s.codeVerifier,
		}, &res)
		if err != nil {
			//logger.KV(xlog.ERROR, "reason", "exchange_code", "err", err.Error())
			err = httperror.New(http.StatusUnauthorized, "unauthorized", "failed to exchange code: %s", err.Error())
			marshal.WriteJSON(w, r, err)
			return
		}
		token = res.AccessToken
		expiresIn = strconv.FormatInt(int64(res.ExpiresIn), 10)
	}

	w.Header().Set(header.ContentType, header.TextPlain)
	fmt.Fprintf(s.writer, "Authenticated! You can close the browser now.\n")

	if s.noStore {
		// the token is shown in the browser, nothing else to wait for
		done = true
		fmt.Fprintf(w, "\nTo use the token with the server, run:\nexport TRUSTYCA_AUTH_TOKEN=%s\n", token)
		return
	}

	vals := url.Values{
		"access_token": {token},
	}
	if s.dpopKey != "" {
		vals["dpop_jkt"] = []string{s.dpopKey}
	}
	if expiresIn != "" {
		ux, err := strconv.ParseInt(expiresIn, 10, 64)
		if err == nil {
			exp := time.Now().Add(time.Duration(ux) * time.Second).Unix()
			vals["exp"] = []string{strconv.FormatInt(exp, 10)}
		}
	}

	fn, err := s.client.Storage().SaveAuthToken(vals.Encode())
	if err != nil {
		// the login fails here, so the browser gets the error
		// instead of a redirect to the listener that is shutting down
		err = errors.WithMessage(err, "unable to store token")
		marshal.WriteJSON(w, r, httperror.Unexpected("%s", err.Error()))
		return
	}
	logger.KV(xlog.DEBUG, "token_saved", fn)

	doneURL := s.doneURL
	if doneURL == "" {
		doneURL = fmt.Sprintf("http://localhost:%d/login/done", s.listenPort)
	} else {
		// the server's page does not call back to this listener,
		// so the login is complete once the browser is redirected
		done = true
	}
	http.Redirect(w, r, doneURL, http.StatusSeeOther)
}

// override in unittest
var openBrowserFn = openBrowser

func openBrowser(startURL string) error {
	execCommand := "xdg-open"

	uname, err := uname.GenInfo()
	if err == nil && strings.Contains(uname.Release, "WSL") {
		execCommand = "wsl-open"
	} else if runtime.GOOS == "darwin" {
		execCommand = "open"
	}

	logger.KV(xlog.DEBUG, "open", execCommand, "url", startURL, "runtime", runtime.GOOS, "uname", uname)

	err = exec.Command(execCommand, startURL).Start()
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}
