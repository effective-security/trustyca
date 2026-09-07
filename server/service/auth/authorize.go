package auth

import (
	"net/http"
	"strings"
	"time"

	"github.com/effective-security/porto/restserver"
	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/effective-security/porto/xhttp/marshal"
	"github.com/effective-security/trustyca/api/pb"
	"github.com/effective-security/x/slices"
	"github.com/effective-security/x/urlutil"
	"github.com/effective-security/x/values"
	"github.com/effective-security/xpki/jwt/dpop"
	"github.com/effective-security/xpki/jwt/oauth2client"
	"golang.org/x/oauth2"
)

const (
	allowedClientID = "trustyca"
)

var errRestrictedUsers = httperror.Forbidden("login is restricted to invited users only. Please contact support@tbilicode.com")

// AuthorizeHandler handles pb.PathForAuthorize
func (s *Service) AuthorizeHandler() restserver.Handle {
	return func(w http.ResponseWriter, r *http.Request, _ restserver.Params) {
		ctx := r.Context()
		//logger.ContextKV(ctx, xlog.DEBUG, "method", r.Method, "url", r.URL, "remote", r.RemoteAddr /*, "header", r.Header*/)

		wh := w.Header()
		wh.Set("Cache-Control", "no-store")
		wh.Set("Pragma", "no-cache")
		ccfg := s.server.Configuration().IdentityMap.GetCookiesConfig()
		resetAuthCookie(w, ccfg)

		qs := r.URL.Query()
		clientID := values.StringsCoalesce(urlutil.GetValue(qs, "client_id"), allowedClientID)
		// TODO: config
		if clientID != allowedClientID {
			marshal.WriteJSON(w, r, httperror.InvalidRequest("unsupported client ID: %s", clientID))
			return
		}

		idpuserEmail := strings.ToLower(urlutil.GetValue(qs, "idpuser.email"))
		loginHint := values.StringsCoalesce(urlutil.GetValue(qs, "login_hint"), idpuserEmail)

		provFromParams := values.StringsCoalesce(urlutil.GetValue(qs, "provider"), urlutil.GetValue(qs, "idp"))
		req := &Request{
			ClientID:     clientID,
			DeviceID:     urlutil.GetValue(qs, "device_id"),
			ResponseMode: values.StringsCoalesce(urlutil.GetValue(qs, "response_mode"), "query"),
			ResponseType: values.StringsCoalesce(urlutil.GetValue(qs, "response_type"), pb.OAuthResponseTypeCode), // Default, otc
			Scope:        values.StringsCoalesce(urlutil.GetValue(qs, "scope"), "openid email profile"),
			RedirectURI:  urlutil.GetValue(qs, "redirect_uri"),
			Provider:     pb.IDPFromString(provFromParams),
			Nonce:        urlutil.GetValue(qs, "nonce"),
		}

		if req.Provider == pb.IDP_Undefined && idpuserEmail != "" {
			prov, err := s.AuthProviderForEmail(ctx, idpuserEmail)
			if err == nil && prov != nil {
				req.Provider = pb.IDPFromString(prov.Config().ProviderID)
			}
		}

		if req.Provider == pb.IDP_Undefined {
			marshal.WriteJSON(w, r, httperror.InvalidRequest("unsupported IDP"))
			return
		}

		if req.ResponseType == pb.OAuthResponseTypeCookie && ccfg.Auth == "" {
			marshal.WriteJSON(w, r, httperror.InvalidRequest("cookie response_type is not supported"))
			return
		}

		var (
			codecall       string
			codecallMethod string
		)

		if req.ResponseType == pb.OAuthResponseTypeCode {
			codecall = urlutil.GetValue(qs, "code_challenge")
			codecallMethod = values.StringsCoalesce(urlutil.GetValue(qs, "code_challenge_method"), "S256")
			if codecall != "" && codecallMethod != "S256" {
				marshal.WriteJSON(w, r, httperror.InvalidRequest("unsupported code_challenge_method: %s", codecallMethod))
				return
			}
		}

		err := req.Validate()
		if err != nil {
			marshal.WriteJSON(w, r, err)
			return
		}
		err = s.isAllowedRedirect(req.RedirectURI)
		if err != nil {
			marshal.WriteJSON(w, r, err)
			return
		}

		var (
			prov *oauth2client.Client
		)

		if req.Provider != pb.IDP_Undefined {
			prov, err = s.AuthProvider(ctx, req.Provider)
			if err != nil {
				marshal.WriteJSON(w, r, err)
				return
			}
		} else if idpuserEmail != "" {
			prov, err = s.AuthProviderForEmail(ctx, idpuserEmail)
			if prov == nil {
				marshal.WriteJSON(w, r, err)
				return
			}
		} else {
			marshal.WriteJSON(w, r, httperror.InvalidRequest("either provider or idpuser.email must be specified"))
			return
		}

		if prov == nil {
			marshal.WriteJSON(w, r, httperror.InvalidRequest("unsupported auth provider"))
			return
		}

		scopes := strings.Split(req.Scope, " ")
		dpopScope := slices.ContainsString(scopes, "dpop")

		var dpopThumbprint string
		if dpopScope {
			res, err := dpop.VerifyRequestClaims(dpop.VerifyConfig{EnableQuery: true}, r)
			if err != nil {
				marshal.WriteJSON(w, r, err.Error())
				return
			}
			dpopThumbprint = res.Thumbprint
			if dpopThumbprint == "" {
				marshal.WriteJSON(w, r, httperror.InvalidRequest("missing dpop for requested scope"))
				return
			}
		}

		provConfig := prov.Config()

		aud := values.StringsCoalesce(
			urlutil.GetValue(qs, "audience"),
			s.getAudience(dpopScope),
		)
		if aud != "" {
			req.Audience = []string{aud}
		}

		state, err := s.Protect(r.Context(), &State{
			DeviceID:            req.DeviceID,
			RedirectURL:         req.RedirectURI,
			Provider:            pb.IDPFromString(provConfig.ProviderID),
			Email:               idpuserEmail,
			IssuedAt:            time.Now().Unix(),
			ClientID:            req.ClientID,
			Scope:               req.Scope,
			Nonce:               req.Nonce,
			ResponseType:        req.ResponseType,
			ResponseMode:        req.ResponseMode,
			DPoPJwk:             dpopThumbprint,
			Audience:            req.Audience,
			CodeChallenge:       codecall,
			CodeChallengeMethod: codecallMethod,
			RememberMe:          urlutil.GetValue(qs, "remember_me") == "true",
		})
		if err != nil {
			marshal.WriteJSON(w, r, httperror.Unexpected("failed to encrypt state").WithCause(err))
			return
		}
		conf := &oauth2.Config{
			ClientID:     provConfig.ClientID,
			ClientSecret: provConfig.ClientSecret,
			RedirectURL:  urlutil.GetPublicEndpointURL(r, pb.PathForAuthCallback).String(),
			Scopes:       provConfig.Scopes, // TODO: map from request
			Endpoint: oauth2.Endpoint{
				AuthURL: provConfig.AuthURL,
			},
		}

		opts := []oauth2.AuthCodeOption{
			// if id_token is used, then Google will ignore `query`
			// and return as #frame which is not acceptable for the server,
			// so we have to use form_post
			oauth2.SetAuthURLParam("response_mode", "form_post"),
			oauth2.SetAuthURLParam("response_type", "code"),
			oauth2.SetAuthURLParam("nonce", req.Nonce),
		}

		if loginHint != "" {
			opts = append(opts, oauth2.SetAuthURLParam("login_hint", loginHint))
		}
		if provConfig.IDPParam != nil {
			val := provConfig.IDPParam.Value
			switch val {
			case "email":
				val = idpuserEmail
			case "domain":
				idpuserEmailParts := strings.Split(idpuserEmail, "@")
				val = idpuserEmailParts[len(idpuserEmailParts)-1]
			}
			opts = append(opts, oauth2.SetAuthURLParam(provConfig.IDPParam.Name, val))
		}

		// Redirect user to consent page to ask for permission
		// for the scopes specified above.
		authURL := conf.AuthCodeURL(state, opts...)
		// logger.KV(xlog.DEBUG,
		// 	"request_redirect_url", req.RedirectURI,
		// 	"provider", prov,
		// 	"audience", req.Audience,
		// 	"config_redirect_url", conf.RedirectURL,
		// 	"dpop_thumbprint", dpopThumbprint,
		// 	"auth_url", authURL)

		http.Redirect(w, r, authURL, http.StatusSeeOther)
	}
}

func (s *Service) getAudience(dpop bool) string {
	audience := ""
	idmapCfg := s.server.Configuration().IdentityMap
	if idmapCfg != nil {
		if dpop {
			audience = idmapCfg.DPoP.Audience
		} else {
			audience = idmapCfg.JWT.Audience
		}
	}
	return audience
}

// Request specifies Authorization request
type Request struct {
	ClientID     string
	DeviceID     string
	ResponseMode string
	ResponseType string
	Scope        string
	RedirectURI  string
	Provider     pb.IDP_Enum
	Nonce        string
	Audience     []string
}

// Validate interface to check the data before saving
func (c *Request) Validate() error {
	if c.ResponseType != pb.OAuthResponseTypeToken && c.ResponseType != pb.OAuthResponseTypeCode && c.ResponseType != pb.OAuthResponseTypeCookie {
		return httperror.InvalidRequest("unsupported response_type: '%s'", c.ResponseType)
	}
	if c.RedirectURI == "" {
		return httperror.InvalidRequest("missing parameter: redirect_uri")
	}
	if c.Scope == "" {
		return httperror.InvalidRequest("missing parameter: scope")
	}
	return nil
}

// State is OAuth state provided by an authenticating client
type State struct {
	RedirectURL string      `json:"rurl,omitempty"`
	Provider    pb.IDP_Enum `json:"idp,omitempty"`
	Email       string      `json:"email,omitempty"`
	IssuedAt    int64       `json:"isa,omitempty"`
	ClientID    string      `json:"cid,omitempty"`
	DeviceID    string      `json:"did,omitempty"`
	Scope       string      `json:"scope,omitempty"`
	Nonce       string      `json:"nonce,omitempty"`
	// ResponseType specifies response type: code|token
	ResponseType        string   `json:"rt,omitempty"`
	ResponseMode        string   `json:"rm,omitempty"`
	DPoPJwk             string   `json:"dpop,omitempty"`
	Audience            []string `json:"aud,omitempty"`
	CodeChallenge       string   `json:"cc,omitempty"`
	CodeChallengeMethod string   `json:"ccm,omitempty"`
	RememberMe          bool     `json:"remember_me,omitempty"`
}

type OTCState struct {
	Token               string `json:"token,omitempty"`
	ExpiresIn           uint32 `json:"expires_in,omitempty"`
	CodeChallenge       string `json:"code_challenge,omitempty"`
	CodeChallengeMethod string `json:"code_challenge_method,omitempty"`
}
