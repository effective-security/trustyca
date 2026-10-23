package auth

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/porto/restserver"
	"github.com/effective-security/porto/xhttp/header"
	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/effective-security/porto/xhttp/marshal"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/db/model"
	"github.com/effective-security/trustyca/internal/events"
	"github.com/effective-security/trustyca/internal/metricskey"
	"github.com/effective-security/x/urlutil"
	"github.com/effective-security/x/values"
	"github.com/effective-security/xlog"
	"github.com/effective-security/xpki/certutil"
	"github.com/effective-security/xpki/dataprotection"
	"github.com/effective-security/xpki/jwt"
	"github.com/effective-security/xpki/jwt/dpop"
	"github.com/effective-security/xpki/jwt/oauth2client"
	"golang.org/x/oauth2"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
	"google.golang.org/grpc/codes"
)

const (
	DefaultTokenTTL   = 48 * time.Hour
	DefaultOTCSeconds = 30

	// claimProvider is the claim of a token that names the identity
	// provider of the login, by the name of its pb.IDP_Enum value
	claimProvider = "provider"
)

// GetProviders returns the list of supported providers
func (s *Service) GetProviders(ctx context.Context, req *pb.AuthProvidersRequest) (*pb.AuthProvidersResponse, error) {
	res := &pb.AuthProvidersResponse{
		AuthURL: s.cfg.Auth.AuthURL,
	}

	email := strings.ToLower(strings.TrimSpace(req.Email))
	if email == "" {
		res.ProviderNames = s.oauthProvider.ClientNames()
	} else {
		cl, err := s.AuthProviderForEmail(ctx, email)
		if err != nil {
			return nil, err
		}
		res.ProviderNames = []string{cl.Config().ProviderID}
	}
	res.Providers = pb.IDPFromSlice(res.ProviderNames)

	// if res.AuthURL == "" {
	// 	// TODO: for proto
	// 	//res.AuthURL = urlutil.GetPublicEndpointURL(r, v1auth.PathForAuthorize).String()
	// }
	return res, nil
}

// AuthProvidersHandler handles pb.PathForAuthProviders endpoint
func (s *Service) AuthProvidersHandler() restserver.Handle {
	return func(w http.ResponseWriter, r *http.Request, _ restserver.Params) {
		var email string
		if r.Method == http.MethodPost {
			var req pb.AuthProvidersRequest
			err := marshal.DecodeBody(w, r, &req)
			if err != nil {
				return
			}
			email = strings.ToLower(strings.TrimSpace(req.Email))
		}
		ctx := r.Context()

		res := &pb.AuthProvidersResponse{
			AuthURL: s.cfg.Auth.AuthURL,
		}
		if email == "" {
			res.ProviderNames = s.oauthProvider.ClientNames()
		} else {
			cl, err := s.AuthProviderForEmail(ctx, email)
			if err != nil {
				marshal.WriteJSON(w, r, err)
				return
			}
			res.ProviderNames = []string{cl.Config().ProviderID}
		}
		res.Providers = pb.IDPFromSlice(res.ProviderNames)

		if res.AuthURL == "" {
			res.AuthURL = urlutil.GetPublicEndpointURL(r, pb.PathForAuthorize).String()
		}

		marshal.WriteJSON(w, r, res)
	}
}

// CallbackHandler handles pb.PathForAuthCallback
func (s *Service) CallbackHandler() restserver.Handle {
	return func(w http.ResponseWriter, r *http.Request, _ restserver.Params) {
		var (
			code     string
			state    string
			idToken  string
			errCode  string
			errDescr string
		)

		ctx := r.Context()

		//logger.ContextKV(ctx, xlog.DEBUG, "method", r.Method, "url", r.URL, "remote", r.RemoteAddr /*, "header", r.Header*/)

		wh := w.Header()
		wh.Set("Cache-Control", "no-store")
		wh.Set("Pragma", "no-cache")

		if r.Method == http.MethodPost {
			err := r.ParseForm()
			if err != nil {
				marshal.WriteJSON(w, r, httperror.InvalidRequest("unable to parse response body").WithCause(err))
				return
			}

			code = r.Form.Get("code")
			state = r.Form.Get("state")
			errCode = r.Form.Get(pb.OAuthParamError)
			errDescr = r.Form.Get(pb.OAuthParamErrorDescription)
		} else {
			vals := r.URL.Query()
			code = urlutil.GetValue(vals, "code")
			state = urlutil.GetValue(vals, "state")
			errCode = urlutil.GetValue(vals, pb.OAuthParamError)
			errDescr = urlutil.GetValue(vals, pb.OAuthParamErrorDescription)
		}

		var (
			st    State
			stErr error
		)
		if state == "" {
			stErr = httperror.InvalidRequest("missing state parameter")
		} else if err := s.Unprotect(ctx, state, &st); err != nil {
			stErr = httperror.InvalidRequest("failed to decrypt state").WithCause(err)
		}

		if errCode != "" {
			idpErr := httperror.FromOAuth(errCode, "OAuth provider error: "+cmp.Or(errDescr, errCode))
			if stErr != nil {
				// without the state the redirect URI of the client is unknown
				marshal.WriteJSON(w, r, idpErr)
				return
			}
			writeOauthError(w, r, &st, idpErr)
			return
		}
		if stErr != nil {
			marshal.WriteJSON(w, r, stErr)
			return
		}

		// the state is decoded: every failure from here on is answered on
		// the redirect URI of the client
		if time.Since(time.Unix(st.IssuedAt, 0)) > 5*time.Minute {
			writeOauthError(w, r, &st, httperror.InvalidRequest("invalid state"))
			return
		}

		logger.ContextKV(ctx, xlog.DEBUG,
			"provider", st.Provider,
			"redirect", st.RedirectURL,
		)

		if st.ResponseType != pb.OAuthResponseTypeToken &&
			st.ResponseType != pb.OAuthResponseTypeCode &&
			st.ResponseType != pb.OAuthResponseTypeCookie {
			writeOauthError(w, r, &st, httperror.FromOAuth(pb.OAuthErrorUnsupportedResponseType,
				fmt.Sprintf("unsupported response_type: '%s'", st.ResponseType)))
			return
		}

		if code == "" {
			writeOauthError(w, r, &st, httperror.InvalidRequest("missing code parameter"))
			return
		}

		s.handleToken(w, r, code, idToken, &st)
	}
}

func (s *Service) handleToken(w http.ResponseWriter, r *http.Request, code, idToken string, st *State) {
	ctx := r.Context()
	prov, _ := s.AuthProvider(ctx, st.Provider)
	if prov == nil && st.Email != "" {
		prov, _ = s.AuthProviderForEmail(ctx, st.Email)
	}
	if prov == nil {
		writeOauthError(w, r, st, httperror.InvalidRequest("unsupported provider: %s", st.Provider))
		return
	}

	var (
		conf  *oauth2.Config
		token *oauth2.Token
		err   error
	)

	if st.Provider == pb.IDP_Local {
		if !s.isLocal() {
			writeOauthError(w, r, st, httperror.InvalidRequest("unsupported provider: %s", st.Provider))
			return
		}
		token = &oauth2.Token{
			Expiry: time.Now().Add(DefaultTokenTTL),
		}
	} else {
		o := prov.Config()
		conf = &oauth2.Config{
			ClientID:     o.ClientID,
			ClientSecret: o.ClientSecret,
			RedirectURL:  urlutil.GetPublicEndpointURL(r, pb.PathForAuthCallback).String(),
			Scopes:       o.Scopes, // TODO: scopes from the state?
			Endpoint: oauth2.Endpoint{
				AuthURL:  o.AuthURL,
				TokenURL: o.TokenURL,
			},
		}

		// the exchange uses the client of the context, which is bounded
		token, err = conf.Exchange(context.WithValue(ctx, oauth2.HTTPClient, idpClient()), code)
		if err != nil {
			err = errors.WithStack(err)
			logger.KV(xlog.ERROR,
				"reason", "exchange",
				"redirect_url", conf.RedirectURL,
				"token_url", o.TokenURL,
				"err", err.Error())
			writeOauthError(w, r, st, httperror.Forbidden("authorization failed: unable to exchange token").WithContext(ctx))
			return
		}

		logger.KV(xlog.DEBUG,
			"redirect_url", conf.RedirectURL,
			"provider", st.Provider,
			//"token", *token,
		)

		if !token.Valid() {
			writeOauthError(w, r, st, httperror.Forbidden("retrieved invalid token"))
			return
		}
	}

	ui, idpClaims, err := s.GetUserInfo(ctx, st.Provider, prov.Config(), conf, token)
	if err != nil {
		writeOauthError(w, r, st, err)
		return
	}
	if st.Provider == pb.IDP_Local && st.Email != "" {
		// the local provider signs in the address the flow started with
		ui = localUserInfo(st.Email)
	}

	if st.Email != "" && !strings.EqualFold(ui.Email, st.Email) {
		writeOauthError(w, r, st, httperror.Forbidden("email mismatch: provider: %s", st.Provider))
		return
	}

	claims := jwt.MapClaims{
		"jti":         s.db.NextID().String(),
		claimProvider: st.Provider.String(),
		"iss":         s.JwtSigner.Issuer(),
	}

	if idpClaims != nil && idpClaims.String("login") != "" {
		claims["idp_login"] = idpClaims.String("login")
	}

	validFor := values.NumbersCoalesce(s.JwtSigner.TokenExpiry(), DefaultTokenTTL)
	if st.DPoPJwk != "" {
		// With DPoP make the token valid for 7 days
		validFor = 7 * 24 * time.Hour
	}

	if !token.Expiry.IsZero() {
		claims["idp_exp"] = token.Expiry.Unix()
	}

	// in this flow the token is login to the server
	audience := s.getAudience(st.DPoPJwk != "")

	logger.KV(xlog.NOTICE,
		"provider", st.Provider,
		"email", ui.Email,
		"audience", audience,
		"token_idp_expiry", token.Expiry,
		"token_valid_for", validFor.String())

	claimsFromUserInfo(claims, ui)
	jwt.SetClaimsExpiration(claims, validFor)
	if audience != "" {
		claims["aud"] = audience
	}
	if st.Nonce != "" {
		claims["nonce"] = st.Nonce
	}
	// if st.DPoPJwk is not empty, the DPoP is already verified
	// at Authorize call
	if st.DPoPJwk != "" {
		dpop.SetCnfClaim(claims, st.DPoPJwk)
	}

	var at, rt string
	login, u, err := s.db.LoginUser(ctx, &model.Login{
		Email:        ui.Email,
		Name:         ui.Name,
		ExternalID:   ui.ID,
		Provider:     st.Provider,
		AccessToken:  at,
		RefreshToken: rt,
	})
	if err != nil {
		writeOauthError(w, r, st, httperror.Unexpected("failed to login").WithCause(err).WithContext(ctx))
		return
	}

	metricskey.LoginCount.IncrCounter(1, ui.Email)

	claims["sub"] = u.ID.String()

	if login.Count == 1 {
		// ctx2 := xlog.ContextWithKV(context.Background(), xlog.ContextEntries(ctx)...)
		// go func() {
		// 	err := s.Emailer.SendNotification(ctx2,
		// 		"Notification: new login",
		// 		fmt.Sprintf("New login for user %s (%s) from %s", u.Name, u.Email, r.RemoteAddr),
		// 	)
		// 	if err != nil {
		// 		logger.KV(xlog.ERROR, "reason", "SendNotification", "err", err)
		// 	}
		// }()

		// LoginUser inserts the login and the user under one new ID, and on
		// a conflict each row keeps its own: only the first login of a new
		// user returns both with the same ID. The first login of an existing
		// user with another provider is not a sign-up.
		if login.ID.UInt64() == u.ID.UInt64() {
			events.New(ctx, ServiceName, pb.EventType_UserSignup, "User signed up").
				Reference(u.ID).
				Email(u.Email).
				Description("%s signed up with %s", u.Email, st.Provider.String()).
				Emit(s.db)
		}

		// This operation makes sense only for new users,
		// as existing users shall be added to Members directly
		accepted, err := s.db.AcceptInvites(ctx, u)
		if err != nil {
			logger.ContextKV(ctx, xlog.ERROR, "reason", "AcceptInvites", "err", err.Error())
		} else if len(accepted) > 0 {
			s.authorizer.InvalidateUser(ctx, u.ID.String())
			logger.ContextKV(ctx, xlog.INFO, "reason", "AcceptInvites", "count", len(accepted))
			for _, m := range accepted {
				events.New(ctx, ServiceName,
					values.Select(m.ProjectID.UInt64() == 0, pb.EventType_OrgMemberAccepted, pb.EventType_ProjectMemberAccepted),
					"Member accepted invitation").
					Org(m.OrgID).
					Project(m.ProjectID).
					Reference(u.ID).
					Email(u.Email).
					Description("%s accepted the invitation as %s", u.Email, m.Role.DisplayName()).
					Emit(s.db)
			}
		}
	}

	// select the initial org for the session; the token carries the org and
	// the resolved role, permissions are resolved from grants at request time
	sel := s.initialOrg(ctx, u)
	sel.setOrgClaims(claims)

	tokenStr, err := s.JwtSigner.Sign(ctx, claims)
	if err != nil {
		writeOauthError(w, r, st, httperror.Unexpected("failed to protect Access Token").WithCause(err))
		return
	}

	var vals url.Values

	switch st.ResponseType {
	case pb.OAuthResponseTypeCookie:
		// do not return access token in response, set Cookie instead
		vals = url.Values{
			"expires_in": []string{fmt.Sprintf("%d", int(validFor.Seconds()))},
			"cookie_set": []string{"true"},
		}
		ccfg := s.server.Configuration().IdentityMap.GetCookiesConfig()
		if csrf := ccfg.CSRF; csrf != "" {
			vals["csrf"] = []string{csrf}
		}
		setAuthCookie(w, ccfg, tokenStr, values.Select(st.RememberMe, validFor, 0))
	case pb.OAuthResponseTypeCode:
		otc := certutil.RandomString(32)
		protectedToken := OTCState{
			Token:               tokenStr,
			ExpiresIn:           uint32(validFor.Seconds()),
			CodeChallenge:       st.CodeChallenge,
			CodeChallengeMethod: st.CodeChallengeMethod,
		}
		data, err := dataprotection.ProtectObject(ctx, s.dataprotection, &protectedToken)
		if err != nil {
			writeOauthError(w, r, st, httperror.Unexpected("failed to protect Access Token").WithCause(err))
			return
		}
		err = s.cache.Set(ctx, fmt.Sprintf("/auth/otc/%s", otc), data, DefaultOTCSeconds*time.Second)
		if err != nil {
			writeOauthError(w, r, st, httperror.Unexpected("failed to set otc").WithCause(err))
			return
		}

		vals = url.Values{
			pb.OAuthResponseTypeCode: []string{otc},
			"expires_in":             []string{fmt.Sprintf("%d", DefaultOTCSeconds)},
		}
	default:
		vals = url.Values{
			pb.OAuthResponseTypeToken: []string{tokenStr},
			"expires_in":              []string{fmt.Sprintf("%d", int(validFor.Seconds()))},
		}

		if idToken != "" {
			vals["id_token"] = []string{idToken}
		}
	}

	// the session starts in the selected org, when the user has one
	signedIn := events.New(ctx, ServiceName, pb.EventType_UserSignedIn, "User signed in").
		Reference(u.ID).
		Email(u.Email)
	if sel != nil {
		signedIn.Org(sel.OrgID).
			Description("%s signed in with %s as %s", u.Email, st.Provider.String(), sel.Role.DisplayName())
	} else {
		signedIn.Description("%s signed in with %s without an org", u.Email, st.Provider.String())
	}
	signedIn.Emit(s.db)

	writeOauthResponse(w, r, st, vals)
}

// oauthErrorCodes are the error codes of an authorization response
// (RFC 6749 section 4.1.2.1)
var oauthErrorCodes = []string{
	pb.OAuthErrorInvalidRequest,
	pb.OAuthErrorUnauthorizedClient,
	pb.OAuthErrorAccessDenied,
	pb.OAuthErrorUnsupportedResponseType,
	pb.OAuthErrorInvalidScope,
	pb.OAuthErrorServerError,
	pb.OAuthErrorTemporarilyUnavailable,
}

// oauthErrorCode returns the OAuth error code of a failed login: the code of
// an error that already is one (an IdP error, an invalid request), else the
// code of its HTTP status
func oauthErrorCode(e *httperror.Error) string {
	switch {
	case slices.Contains(oauthErrorCodes, e.Code):
		return e.Code
	case e.HTTPStatus == http.StatusServiceUnavailable:
		return pb.OAuthErrorTemporarilyUnavailable
	case e.HTTPStatus >= http.StatusInternalServerError:
		return pb.OAuthErrorServerError
	case e.HTTPStatus == http.StatusUnauthorized, e.HTTPStatus == http.StatusForbidden:
		return pb.OAuthErrorAccessDenied
	default:
		return pb.OAuthErrorInvalidRequest
	}
}

// writeOauthError answers a login that fails after its state is decoded on
// the redirect URI of the client, in the response mode of the state, with
// the OAuth error code and description (RFC 6749 section 4.1.2.1): the
// console, the CLI listener and the authenticated page show the failure.
// The authorize request checked the redirect URI, and the state protects
// it. The cause stays in the server log; a server-side failure is described
// by its HTTP status text only, as marshal.WriteJSON does.
func writeOauthError(w http.ResponseWriter, r *http.Request, st *State, err error) {
	e := httperror.NewFromPb(err)
	code := oauthErrorCode(e)
	descr := e.Message
	sev := xlog.WARNING
	if e.HTTPStatus >= http.StatusInternalServerError {
		descr = http.StatusText(e.HTTPStatus)
		sev = xlog.ERROR
	}
	msg := e.Error()
	if cause := e.Cause(); cause != nil {
		msg += ": " + cause.Error()
	}
	logger.ContextKV(r.Context(), sev,
		"reason", "login_failed",
		"provider", st.Provider,
		"code", code,
		"err", msg)

	writeOauthResponse(w, r, st, url.Values{
		pb.OAuthParamError:            []string{code},
		pb.OAuthParamErrorDescription: []string{descr},
	})
}

func writeOauthResponse(w http.ResponseWriter, r *http.Request, st *State, vals url.Values) {
	if st.ResponseMode == "" || st.ResponseMode == "query" {
		url := st.RedirectURL + "?" + vals.Encode()
		http.Redirect(w, r, url, http.StatusSeeOther)
		return
	}
	if st.ResponseMode == "fragment" {
		url := st.RedirectURL + "#" + vals.Encode()
		http.Redirect(w, r, url, http.StatusSeeOther)
		return
	}

	// form_post
	w.Header().Add("Content-Type", "text/html;charset=UTF-8")
	writeAuthorizeFormPostResponse(w, st.RedirectURL, vals, formPostDefaultTemplate)
}

var formPostDefaultTemplate = template.Must(template.New("form_post").Parse(`<html>
   <head>
      <title>Submit This Form</title>
   </head>
   <body onload="javascript:document.forms[0].submit()">
      <form method="post" action="{{ .RedirURL }}">
         {{ range $key,$value := .Parameters }}
            {{ range $parameter:= $value}}
		      <input type="hidden" name="{{$key}}" value="{{$parameter}}"/>
            {{end}}
         {{ end }}
      </form>
   </body>
</html>`))

func writeAuthorizeFormPostResponse(w io.Writer, redirectURL string, parameters url.Values, template *template.Template) {
	_ = template.Execute(w, struct {
		RedirURL   string
		Parameters url.Values
	}{
		RedirURL:   redirectURL,
		Parameters: parameters,
	})
}

// tokenProvider returns the identity provider of the login a token comes
// from. The claim holds the name of the provider; IDPFromString also reads
// the number of the enum value, which older tokens carry.
func tokenProvider(claims jwt.MapClaims) pb.IDP_Enum {
	return pb.IDPFromString(claims.String(claimProvider))
}

func claimsFromUserInfo(claims jwt.MapClaims, ui *pb.UserInfo) {
	if ui.ID != "" {
		claims["sub"] = ui.ID
	}
	if ui.Name != "" {
		claims["name"] = ui.Name
	}
	if ui.Email != "" {
		claims["email"] = ui.Email
	}
	if ui.EmailVerified {
		claims["email_verified"] = true
	}
}

// localUser is the user the `local` provider signs in without an address
var localUser = &pb.UserInfo{
	ID:    "testuser",
	Email: "test@trustyca.io",
	Name:  "Trusty Test",
}

// localUserInfo returns the user the `local` provider signs in for email,
// already without the localEmailPrefix. The email is the external ID, so
// every local user has a login of its own.
func localUserInfo(email string) *pb.UserInfo {
	name, _, _ := strings.Cut(email, "@")
	return &pb.UserInfo{
		ID:            email,
		Email:         email,
		EmailVerified: true,
		Name:          name,
	}
}

// githubNoReplyDomain is the domain GitHub issues to users who keep their
// address private. Mail to it is discarded, so it is not usable for an account.
const githubNoReplyDomain = "@users.noreply.github.com"

// idpAPITimeout bounds every call of the callback to an IdP (the code
// exchange, the user info and the GitHub emails), so a slow IdP cannot hang
// a login
const idpAPITimeout = 10 * time.Second

// idpClient returns the HTTP client of the calls to an IdP
func idpClient() *http.Client {
	return &http.Client{Timeout: idpAPITimeout}
}

// getGithubEmail returns the user's primary verified email from GitHub.
// It prefers the primary address, and falls back to any other verified one.
// An empty string is returned when the account has no usable address.
func (s *Service) getGithubEmail(ctx context.Context, token *oauth2.Token) (string, error) {
	emailsURL := "https://api.github.com/user/emails"
	if s.BaseURL != nil {
		u, err := url.Parse(emailsURL)
		if err != nil {
			return "", errors.WithMessage(err, "unable to parse user emails URL")
		}
		u.Scheme = s.BaseURL.Scheme
		u.Host = s.BaseURL.Host
		emailsURL = u.String()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, emailsURL, nil)
	if err != nil {
		return "", errors.WithMessage(err, "unable to create user emails request")
	}
	req.Header.Add(header.Authorization, "Bearer "+token.AccessToken)

	resp, err := idpClient().Do(req)
	if err != nil {
		return "", errors.WithMessage(err, "unable to get user emails")
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", errors.WithMessage(err, "unable to read user emails")
	}
	if resp.StatusCode != http.StatusOK {
		return "", errors.Errorf("unable to get user emails from %s: %s: %s", emailsURL, resp.Status, string(body))
	}

	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	err = json.Unmarshal(body, &emails)
	if err != nil {
		return "", errors.WithMessage(err, "unable to decode user emails")
	}

	// primary is remembered whether or not it is usable, so a login that fails
	// here still names an address support can reach.
	fallback, primary := "", ""
	for _, e := range emails {
		addr := strings.ToLower(e.Email)
		if e.Primary {
			primary = addr
		}
		// An unverified address is not proven to be theirs, and mail to the
		// noreply one is discarded, so neither can own an organization.
		if !e.Verified || strings.HasSuffix(addr, githubNoReplyDomain) {
			continue
		}
		if e.Primary {
			return addr, nil
		}
		if fallback == "" {
			fallback = addr
		}
	}

	if fallback == "" {
		// The account has no address we can write to: either none is verified,
		// or the only verified one is the private noreply address. The primary
		// address is logged so support can reach whoever could not sign in,
		// even though we would not send to it ourselves.
		logger.ContextKV(ctx, xlog.WARNING,
			"reason", "no_usable_github_email",
			"primary", primary,
			"count", len(emails))
	}
	return fallback, nil
}

// GetUserInfo returns the user the IdP signed in with the token. A user the
// service cannot sign in (no verified email, no name) is PermissionDenied,
// a failed call to the IdP is Unavailable; the answer of the IdP stays in
// the cause, for the server log.
func (s *Service) GetUserInfo(ctx context.Context, idpType pb.IDP_Enum, cl *oauth2client.ClientConfig, _ *oauth2.Config, token *oauth2.Token) (*pb.UserInfo, jwt.MapClaims, error) {
	if idpType == pb.IDP_Local {
		return localUser, nil, nil
	}

	userInfoURL := cl.UserinfoURL
	if s.BaseURL != nil {
		u, err := url.Parse(userInfoURL)
		if err != nil {
			return nil, nil, httperror.NewGrpcFromCtx(ctx, codes.Internal, "invalid user info URL").WithCause(err)
		}
		u.Scheme = s.BaseURL.Scheme
		u.Host = s.BaseURL.Host
		userInfoURL = u.String()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, userInfoURL, nil)
	if err != nil {
		return nil, nil, httperror.NewGrpcFromCtx(ctx, codes.Internal, "invalid user info URL").WithCause(err)
	}
	req.Header.Add(header.Authorization, "Bearer "+token.AccessToken)

	resp, err := idpClient().Do(req)
	if err != nil {
		return nil, nil, httperror.NewGrpcFromCtx(ctx, codes.Unavailable, "unable to get user info").WithCause(err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, httperror.NewGrpcFromCtx(ctx, codes.Unavailable, "unable to decode user info").WithCause(err)
	}

	if resp.StatusCode != http.StatusOK {
		// the answer of the IdP is for the server log, not for the redirect
		// URI of the client
		return nil, nil, httperror.NewGrpcFromCtx(ctx, codes.Unavailable, "unable to get user info").
			WithCause(errors.Errorf("unable to get user info from %s: %s: %s", userInfoURL, resp.Status, string(body)))
	}

	var res jwt.MapClaims
	err = json.Unmarshal(body, &res)
	if err != nil {
		return nil, nil, httperror.NewGrpcFromCtx(ctx, codes.Unavailable, "unable to decode user info").WithCause(err)
	}

	logger.ContextKV(ctx, xlog.DEBUG, "userinfo", res)

	u := &pb.UserInfo{
		Email:         strings.ToLower(res.String("email")),
		EmailVerified: res.Bool("email_verified"),
		ID:            values.StringsCoalesce(res.String("login"), res.String("sub"), res.String("id")),
		Name:          values.StringsCoalesce(res.String("name"), res.String("given_name"), res.String("login")),
	}

	if idpType == pb.IDP_Github && u.Email == "" {
		// GitHub's /user returns a null email when the profile address is
		// private, and never returns email_verified at all. So /user/emails is
		// called on every GitHub login, not only when the profile address is
		// missing: it is the only source that says which address is verified,
		// and a profile address we cannot vouch for should not win over one we
		// can.
		email, err := s.getGithubEmail(ctx, token)
		if err != nil {
			logger.ContextKV(ctx, xlog.ERROR, "reason", "getGithubEmail", "err", err.Error())
		}
		if email != "" {
			u.Email = email
			u.EmailVerified = true
		}
	}

	if u.Email == "" {
		if idpType == pb.IDP_Github {
			return nil, nil, httperror.NewGrpcFromCtx(ctx, codes.PermissionDenied,
				"no verified email address: verify an email address in your GitHub account settings, then sign in again")
		}
		return nil, nil, httperror.NewGrpcFromCtx(ctx, codes.PermissionDenied, "email is required")
	}

	if u.Name == "" {
		parts := strings.Split(u.Email, "@")
		if len(parts) > 1 {
			titler := cases.Title(language.English)
			names := strings.Split(parts[0], ".")
			if len(names) > 1 {
				for i, name := range names {
					names[i] = titler.String(name)
				}
				u.Name = strings.Join(names, " ")
			} else {
				u.Name = titler.String(names[0])
			}
		} else {
			u.Name = u.Email
		}
	}

	if u.Name == "" {
		return nil, nil, httperror.NewGrpcFromCtx(ctx, codes.PermissionDenied, "name is required")
	}

	return u, res, nil
}

func (s *Service) ExchangeCode(ctx context.Context, req *pb.ExchangeCodeRequest) (*pb.Token, error) {
	if req.Code == "" || req.Verifier == "" {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.PermissionDenied, "invalid code or verifier")
	}

	key := fmt.Sprintf("/auth/otc/%s", req.Code)
	var data []byte
	err := s.cache.Get(ctx, key, &data)
	if err != nil || len(data) == 0 {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.PermissionDenied, "invalid otc")
	}
	err = s.cache.Delete(ctx, key)
	if err != nil {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.Internal, "unable to use otc").WithCause(err)
	}

	var protectedToken OTCState
	err = dataprotection.UnprotectObject(ctx, s.dataprotection, string(data), &protectedToken)
	if err != nil {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.PermissionDenied, "invalid otc")
	}
	challenge := req.Verifier
	if protectedToken.CodeChallengeMethod == "S256" {
		challenge = certutil.SHA256Base64([]byte(challenge))
	}
	if protectedToken.CodeChallenge != challenge {
		return nil, httperror.NewGrpcFromCtx(ctx, codes.PermissionDenied, "invalid code verifier")
	}

	res := &pb.Token{
		AccessToken: protectedToken.Token,
		ExpiresIn:   protectedToken.ExpiresIn,
	}

	return res, nil
}
