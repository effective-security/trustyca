package pb

// Status service API
const (
	// PathForStatus is base path for the Status service
	PathForStatus = "/v1/status"

	// PathForStatusVersion returns ServerVersion,
	// that proviodes the version of the installed package.
	//
	// Verbs: GET
	// Response: v1.ServerVersion
	PathForStatusVersion = "/v1/status/version"

	// PathForStatusServer returns ServerStatusResponse.
	//
	// Verbs: GET
	// Response: v1.ServerStatusResponse
	PathForStatusServer = "/v1/status/server"

	// PathForStatusNode returns `ALIVE` if the server is ready to server,
	// or 503 Service Unavailable otherwise.
	// This end-point can be used with Load Balancers
	//
	// Verbs: GET
	// Response: string
	// Content-Type: text/plain
	PathForStatusNode = "/v1/status/node"

	// PathForSwagger returns swagger file.
	//
	// Verbs: GET
	// Response: JSON
	PathForSwagger = "/v1/swagger/:service"
)

// Auth service API
const (
	// PathForAuth provides the base path for auth service
	PathForAuth = "/pb.Auth/:actions"

	// PathForAuthProviders provides list of supported providers
	PathForAuthProviders = "/v1/auth/providers"

	// PathForAuthCallback is auth callback for OAuth flow
	PathForAuthCallback = "/v1/auth/callback"

	// PathForAuthorize starts authorization flow
	//
	// Verbs: GET
	// Response: 303
	PathForAuthorize = "/v1/auth/authorize"

	// PathForAuthDone completes authorization flow
	//
	// Verbs: GET
	// Response: 200
	PathForAuthDone = "/v1/auth/done"

	// PathForAuthUserinfo returns UserInfo for the caller
	// Verbs: GET
	// Response: JWT token or JSON encoded claims
	PathForAuthUserinfo = "/v1/auth/userinfo"

	// PathForAuthUserToken returns Token and UserInfo
	// Verbs: GET
	// Response: UserTokenResponse
	PathForAuthUserToken = "/v1/auth/usertoken"

	// PathForStatusCaller returns CallerStatusResponse.
	//
	// Verbs: GET
	// Response: v1.CallerStatusResponse
	PathForStatusCaller = "/v1/auth/caller"

	// PathForRemoveCookie returns NoContent status.
	//
	// Verbs: DELETE
	// Response: 204
	PathForRemoveCookie = "/v1/auth/removecookie"
)

// CIS service API
// In addition to the JSON API below, CIS registers binary endpoints that
// are referenced from issued certificates (AIA and CDP extensions):
//
//	GET  /v1/cert/{ikid}          application/pkix-cert   issuer certificate
//	GET  /v1/crl/{ikid}           application/pkix-crl    current CRL (DER)
//	GET  /v1/ocsp/{ikid}/{req}    application/ocsp-response
//	POST /v1/ocsp/{ikid}          application/ocsp-response
//	POST /v1/ocsp                 application/ocsp-response (issuer by KID)
const (
	// PathForCert provides the issuer certificate by IKID
	//
	// Verbs: GET
	// Content-Type: application/pkix-cert
	// Response: CertificateResponse
	PathForCert = "/v1/cert/:ikid"
	// PathForCRL provides the current CRL by IKID
	//
	// Verbs: GET
	// Content-Type: application/pkix-crl
	// Response: CrlResponse
	PathForCRL = "/v1/crl/:ikid"
	// PathForGetOCSP provides the OCSP response by IKID and request
	//
	// Verbs: GET
	// Content-Type: application/ocsp-response
	// Response: OCSPResponse
	PathForGetOCSP = "/v1/ocsp/:ikid/:req"
	// PathForOCSPByIssuerID provides the OCSP response by IKID
	//
	// Verbs: POST
	// Content-Type: application/ocsp-response
	// Response: OCSPResponse
	PathForOCSPByIssuerID = "/v1/ocsp/:ikid"
	// PathForOCSP provides the OCSP response by issuer KID
	//
	// Verbs: POST
	// Content-Type: application/ocsp-response
	// Response: OCSPResponse
	PathForOCSP = "/v1/ocsp"
)

// Webhooks
const (
	// PathForWebhooks provides the base path for webhooks
	PathForWebhooks = "/v1/webhooks/:actions"

	// PathForWebhooksStripe provides the base path for stripe webhooks
	PathForWebhooksStripe = "/v1/webhooks/stripe"
)

// List of supported Types
const (
	OAuthResponseTypeIDToken = "id_token"
	OAuthResponseTypeCode    = "code"
	OAuthResponseTypeToken   = "token"
	OAuthResponseTypeCookie  = "cookie"
)

// Web pages served by the ui service.
// These are plain HTML test pages, not API end-points.
const (
	// PathForLoginPage renders the login page that lists the ID providers
	// and starts the OAuth flow via PathForAuthorize.
	//
	// Verbs: GET
	// Response: text/html
	PathForLoginPage = "/login"

	// PathForAuthenticatedPage is the default redirect target
	// after a successful login from PathForLoginPage.
	//
	// Verbs: GET
	// Response: text/html
	PathForAuthenticatedPage = "/authenticated"

	// PathForPaymentPage renders the Stripe checkout widget.
	// The PaymentIntent client secret is passed in the URL fragment,
	// see CheckoutClientSecretParam.
	//
	// Verbs: GET
	// Response: text/html
	PathForPaymentPage = "/payment"

	// CheckoutClientSecretParam is the URL fragment parameter of PathForPaymentPage
	// that carries PaymentOrderResponse.ClientSecret:
	// /payment#checkout_client_secret=<secret>
	CheckoutClientSecretParam = "checkout_client_secret"
)
