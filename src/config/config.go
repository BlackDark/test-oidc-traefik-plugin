package config

import (
	"text/template"

	"github.com/BlackDark/test-oidc-traefik-plugin/src/errorPages"
)

const DefaultSecret = "MLFs4TT99kOOq8h3UAVRtYoCTDYXiRcZ"

const (
	SessionStorageTypeCookie string = "Cookie"
)

type Config struct {
	LogLevel string `json:"log_level" yaml:"logLevel"`

	Secret string `json:"secret" yaml:"secret"`

	Provider *ProviderConfig `json:"provider" yaml:"provider"`
	Scopes   []string        `json:"scopes" yaml:"scopes"`

	// Can be a relative path or a full URL.
	// If a relative path is used, the scheme and domain will be taken from the incoming request.
	// In this case, the callback path will overlay all hostnames behind the middleware.
	// If a full URL is used, all callbacks are sent there.  It is the user's responsibility to ensure
	// that the callback URL is also routed to this middleware plugin.
	CallbackUri string `json:"callback_uri" yaml:"callbackUri"`

	// The URL used to start authorization when needed.
	// All other requests that are not already authorized will return a 401 Unauthorized.
	// When left empty, all requests can start authorization.
	LoginUri                    string   `json:"login_uri" yaml:"loginUri"`
	PostLoginRedirectUri        string   `json:"post_login_redirect_uri" yaml:"postLoginRedirectUri"`
	ValidPostLoginRedirectUris  []string `json:"valid_post_login_redirect_uris" yaml:"validPostLoginRedirectUris"`
	LogoutUri                   string   `json:"logout_uri" yaml:"logoutUri"`
	PostLogoutRedirectUri       string   `json:"post_logout_redirect_uri" yaml:"postLogoutRedirectUri"`
	ValidPostLogoutRedirectUris []string `json:"valid_post_logout_redirect_uris" yaml:"validPostLogoutRedirectUris"`
	FrontChannelLogoutUri       string   `json:"front_channel_logout_uri" yaml:"frontChannelLogoutUri"`

	SessionStorageType string `json:"session_storage_type" yaml:"sessionStorageType"`

	CookieNamePrefix        string                     `json:"cookie_name_prefix" yaml:"cookieNamePrefix"`
	SessionCookie           *SessionCookieConfig       `json:"session_cookie" yaml:"sessionCookie"`
	AuthorizationHeader     *AuthorizationHeaderConfig `json:"authorization_header" yaml:"authorizationHeader"`
	AuthorizationCookie     *AuthorizationCookieConfig `json:"authorization_cookie" yaml:"authorizationCookie"`
	UnauthenticatedBehavior string                     `json:"unauthenticated_behavior" yaml:"unauthenticatedBehavior"`
	UnauthorizedBehavior    string                     `json:"unauthorized_behavior" yaml:"unauthorizedBehavior"`

	Authorization *AuthorizationConfig `json:"authorization" yaml:"authorization"`

	Headers []HeaderConfig `json:"headers" yaml:"headers"`

	BypassAuthenticationRule string `json:"bypass_authentication_rule" yaml:"bypassAuthenticationRule"`

	ErrorPages *errorPages.ErrorPagesConfig `json:"error_pages" yaml:"errorPages"`

	RequestedResources []string `json:"requested_resources" yaml:"requestedResources"`

	// Additional query parameters to send to the IDP's authorization endpoint, eg. acr_values or prompt.
	// A `prompt` query parameter on the incoming /login request still takes precedence over this.
	AuthorizationParams map[string]string `json:"authorization_params" yaml:"authorizationParams"`
}

type ProviderConfig struct {
	Url string `json:"url" yaml:"url"`

	InsecureSkipVerify     string `json:"insecure_skip_verify" yaml:"insecureSkipVerify"`
	InsecureSkipVerifyBool bool   `json:"insecure_skip_verify_bool" yaml:"insecureSkipVerifyBool"`

	CABundle     string `json:"ca_bundle" yaml:"caBundle"`
	CABundleFile string `json:"ca_bundle_file" yaml:"caBundleFile"`

	ClientId              string `json:"client_id" yaml:"clientId"`
	ClientSecret          string `json:"client_secret" yaml:"clientSecret"`
	ClientJwtPrivateKey   string `json:"client_jwt_private_key" yaml:"clientJwtPrivateKey"`
	ClientJwtPrivateKeyId string `json:"client_jwt_private_key_id" yaml:"clientJwtPrivateKeyId"`

	UsePkce     string `json:"use_pkce" yaml:"usePkce"`
	UsePkceBool bool   `json:"use_pkce_bool" yaml:"usePkceBool"`

	ValidateAudience     string `json:"validate_audience" yaml:"validateAudience"`
	ValidateAudienceBool bool   `json:"validate_audience_bool" yaml:"validateAudienceBool"`
	ValidAudience        string `json:"valid_audience" yaml:"validAudience"`

	ValidateIssuer     string `json:"validate_issuer" yaml:"validateIssuer"`
	ValidateIssuerBool bool   `json:"validate_issuer_bool" yaml:"validateIssuerBool"`
	ValidIssuer        string `json:"valid_issuer" yaml:"validIssuer"`

	// AccessToken or IdToken or Introspection
	TokenValidation string `json:"verification_token" yaml:"tokenValidation"`

	TokenRenewalThreshold float64 `json:"token_renewal_threshold" yaml:"tokenRenewalThreshold"`

	UseClaimsFromUserInfo     string `json:"use_claims_from_user_info" yaml:"useClaimsFromUserInfo"`
	UseClaimsFromUserInfoBool bool   `json:"use_claims_from_user_info_bool" yaml:"useClaimsFromUserInfoBool"`

	// ValidateNonce requires the ID token nonce claim to match the sealed login state (OIDC Core).
	// Default true when unset via CreateConfig. Set false only if the IdP cannot return nonce.
	ValidateNonce     string `json:"validate_nonce" yaml:"validateNonce"`
	ValidateNonceBool bool   `json:"validate_nonce_bool" yaml:"validateNonceBool"`

	// TokenClockSkewSeconds is leeway for JWT nbf/exp validation (issue #236). Default 60.
	TokenClockSkewSeconds int `json:"token_clock_skew_seconds" yaml:"tokenClockSkewSeconds"`
}

type SessionCookieConfig struct {
	Path     string `json:"path" yaml:"path"`
	Domain   string `json:"domain" yaml:"domain"`
	Secure   bool   `json:"secure" yaml:"secure"`
	HttpOnly bool   `json:"http_only" yaml:"httpOnly"`
	SameSite string `json:"same_site" yaml:"sameSite"`
	MaxAge   int    `json:"max_age" yaml:"maxAge"`
}

type AuthorizationHeaderConfig struct {
	Name string `json:"name" yaml:"name"`
}
type AuthorizationCookieConfig struct {
	Name string `json:"name" yaml:"name"`
}

type AuthorizationConfig struct {
	AssertClaims        []ClaimAssertion `json:"assert_claims" yaml:"assertClaims"`
	CheckOnEveryRequest bool             `json:"check_on_every_request" yaml:"checkOnEveryRequest"`
}

type ClaimAssertion struct {
	Name  string   `json:"name" yaml:"name"`
	AnyOf []string `json:"anyOf" yaml:"anyOf"`
	AllOf []string `json:"allOf" yaml:"allOf"`
}

type HeaderConfig struct {
	Name        string `json:"name" yaml:"name"`
	Value       string `json:"value" yaml:"value"`
	Values      string `json:"values" yaml:"values"`
	IncludeWhen string `json:"include_when" yaml:"includeWhen"`

	// A reference to the parsed Value-template
	Template *template.Template `json:"-" yaml:"-"`
}
