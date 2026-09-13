package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/porto/restserver"
	"github.com/effective-security/porto/xhttp/header"
	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/effective-security/porto/xhttp/marshal"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/trustyca/internal/db/model"
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

// AuthDoneHandler handles pb.PathForAuthDone
func (s *Service) AuthDoneHandler() restserver.Handle {
	return func(w http.ResponseWriter, r *http.Request, _ restserver.Params) {
		var (
			token string
			//expiresIn string
			errCode  string
			errDescr string
		)
		if r.Method == http.MethodPost {
			err := r.ParseForm()
			if err != nil {
				marshal.WriteJSON(w, r, httperror.InvalidRequest("unable to parse response body"))
				return
			}

			token = r.Form.Get("token")
			//expiresIn = r.Form.Get("expires_in")
			errCode = r.Form.Get("error")
			errDescr = r.Form.Get("error_description")
		} else {
			vals := r.URL.Query()
			token = urlutil.GetValue(vals, "token")
			//expiresIn = urlutil.GetValue(vals, "expires_in")
			errCode = urlutil.GetValue(vals, "error")
			errDescr = urlutil.GetValue(vals, "error_description")
		}
		if errCode != "" {
			marshal.WriteJSON(w, r, httperror.New(http.StatusInternalServerError, errCode, "%s", errDescr))
			return
		}

		if token == "" {
			marshal.WriteJSON(w, r, httperror.InvalidRequest("missing token parameter"))
			return
		}

		w.Header().Set(header.ContentType, header.TextPlain)
		fmt.Fprintf(w, "Authenticated!\n\nexport TRUSTYCA_AUTH_TOKEN=%s\n", token)
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
			errCode = r.Form.Get("error")
			errDescr = r.Form.Get("error_description")
		} else {
			vals := r.URL.Query()
			code = urlutil.GetValue(vals, "code")
			state = urlutil.GetValue(vals, "state")
			errCode = urlutil.GetValue(vals, "error")
			errDescr = urlutil.GetValue(vals, "error_description")
		}
		if errCode != "" {
			marshal.WriteJSON(w, r, httperror.FromOAuth(errCode, "OAuth provider error: "+errDescr))
			return
		}

		if state == "" {
			marshal.WriteJSON(w, r, httperror.InvalidRequest("missing state parameter"))
			return
		}

		var st State
		err := s.Unprotect(r.Context(), state, &st)
		if err != nil {
			marshal.WriteJSON(w, r, httperror.InvalidRequest("failed to decrypt state").WithCause(err))
			return
		}

		if time.Since(time.Unix(st.IssuedAt, 0)) > 5*time.Minute {
			marshal.WriteJSON(w, r, httperror.InvalidRequest("invalid state"))
			return
		}

		logger.ContextKV(ctx, xlog.DEBUG,
			"provider", st.Provider,
			"redirect", st.RedirectURL,
		)

		if st.ResponseType != pb.OAuthResponseTypeToken &&
			st.ResponseType != pb.OAuthResponseTypeCode &&
			st.ResponseType != pb.OAuthResponseTypeCookie {
			marshal.WriteJSON(w, r, httperror.InvalidRequest("unsupported response_type: '%s'", st.ResponseType))
			return
		}

		if code == "" {
			marshal.WriteJSON(w, r, httperror.InvalidRequest("missing code parameter"))
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
		marshal.WriteJSON(w, r, httperror.InvalidRequest("unsupported provider: %s", st.Provider))
		return
	}

	var (
		conf  *oauth2.Config
		token *oauth2.Token
		err   error
	)

	if st.Provider == pb.IDP_Local {
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

		token, err = conf.Exchange(ctx, code)
		if err != nil {
			err = errors.WithStack(err)
			logger.KV(xlog.DEBUG,
				"reason", "exchange",
				"redirect_url", conf.RedirectURL,
				"token_url", o.TokenURL,
				"err", err.Error())
			marshal.WriteJSON(w, r, httperror.Forbidden("authorization failed: unable to exchange token").WithContext(ctx))
			return
		}

		logger.KV(xlog.DEBUG,
			"redirect_url", conf.RedirectURL,
			"provider", st.Provider,
			//"token", *token,
		)

		if !token.Valid() {
			marshal.WriteJSON(w, r, httperror.Forbidden("retrieved invalid token"))
			return
		}
	}

	ui, idpClaims, err := s.GetUserInfo(ctx, st.Provider, prov.Config(), conf, token)
	if err != nil {
		marshal.WriteJSON(w, r, err)
		return
	}

	if st.Email != "" && !strings.EqualFold(ui.Email, st.Email) {
		marshal.WriteJSON(w, r, httperror.Forbidden("email mismatch: provider: %s", st.Provider))
		return
	}

	claims := jwt.MapClaims{
		"jti":      s.db.NextID().String(),
		"provider": st.Provider,
		"iss":      s.JwtSigner.Issuer(),
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
		marshal.WriteJSON(w, r, httperror.Unexpected("failed to login").WithCause(err).WithContext(ctx))
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

		// This operation makes sense only for new users,
		// as existing users shall be added to Members directly
		count, err := s.db.AcceptInvites(ctx, u)
		if err != nil {
			logger.KV(xlog.ERROR, "reason", "AcceptInvites", "err", err.Error())
		} else if count > 0 {
			logger.KV(xlog.INFO, "reason", "AcceptInvites", "count", count)
		}
	}

	// select the initial org for the session; the token carries the org and
	// the resolved role, permissions are resolved from grants at request time
	s.initialOrg(ctx, u).setOrgClaims(claims)

	tokenStr, err := s.JwtSigner.Sign(ctx, claims)
	if err != nil {
		marshal.WriteJSON(w, r, httperror.Unexpected("failed to protect Access Token").WithCause(err))
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
			marshal.WriteJSON(w, r, httperror.Unexpected("failed to protect Access Token").WithCause(err))
			return
		}
		err = s.cache.Set(ctx, fmt.Sprintf("/auth/otc/%s", otc), data, DefaultOTCSeconds*time.Second)
		if err != nil {
			marshal.WriteJSON(w, r, httperror.Unexpected("failed to set otc").WithCause(err))
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

	// TODO: teams or projects?
	// if !orgID.IsZero() {
	// 	name := values.StringsCoalesce(u.Name, u.Email)
	// 	s.db.TryCreateEvent(&model.Event{
	// 		OrgID:       orgID,
	// 		Type:        pb.EventType_UserLogin,
	// 		Email:       xdb.NULLString(ui.Email),
	// 		Source:      "OAuthCallback",
	// 		Title:       "login",
	// 		Description: xdb.NULLString(fmt.Sprintf("User %s logged in from %s", name, r.RemoteAddr)),
	// 	})
	// }

	writeOauthResponse(w, r, st, vals)
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

var localUser = &pb.UserInfo{
	ID:    "testuser",
	Email: "test@trustyca.io",
	Name:  "Trusty Test",
}

// githubNoReplyDomain is the domain GitHub issues to users who keep their
// address private. Mail to it is discarded, so it is not usable for an account.
const githubNoReplyDomain = "@users.noreply.github.com"

// githubAPITimeout bounds the emails call so a slow GitHub cannot hang a login.
const githubAPITimeout = 10 * time.Second

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

	client := &http.Client{Timeout: githubAPITimeout}
	resp, err := client.Do(req)
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

func (s *Service) GetUserInfo(ctx context.Context, idpType pb.IDP_Enum, cl *oauth2client.ClientConfig, _ *oauth2.Config, token *oauth2.Token) (*pb.UserInfo, jwt.MapClaims, error) {
	if idpType == pb.IDP_Local {
		return localUser, nil, nil
	}

	userInfoURL := cl.UserinfoURL
	if s.BaseURL != nil {
		u, _ := url.Parse(userInfoURL)
		u.Scheme = s.BaseURL.Scheme
		u.Host = s.BaseURL.Host
		userInfoURL = u.String()
	}
	req, _ := http.NewRequest(http.MethodGet, userInfoURL, nil)
	req.Header.Add(header.Authorization, "Bearer "+token.AccessToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "unable to get user info").WithCause(err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "unable to decode user info").WithCause(err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "unable to get user info from %s: %s: %s", userInfoURL, resp.Status, string(body))
	}

	var res jwt.MapClaims
	err = json.Unmarshal(body, &res)
	if err != nil {
		return nil, nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "unable to decode user info").WithCause(err)
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
			return nil, nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument,
				"no verified email address: verify an email address in your GitHub account settings, then sign in again")
		}
		return nil, nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "email is required")
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
		return nil, nil, httperror.NewGrpcFromCtx(ctx, codes.InvalidArgument, "name is required")
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
